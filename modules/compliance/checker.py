"""Compliance checking engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.logger import get_logger
from core.models import ScanResult, Severity, Target
from modules.compliance.standards import (
    CIS_CONTROLS,
    OWASP_TOP_10,
    ComplianceStatus,
    ControlCheck,
    SecurityStandard,
)


@dataclass
class ControlResult:
    """Result of a compliance control check."""
    control: ControlCheck
    status: ComplianceStatus
    message: str = ""
    evidence: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ComplianceReport:
    """Full compliance assessment report."""
    target: str
    standard: SecurityStandard
    results: list[ControlResult] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_controls(self) -> int:
        return len(self.results)

    @property
    def passed_controls(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.PASS)

    @property
    def failed_controls(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.FAIL)

    @property
    def compliance_score(self) -> float:
        applicable = [r for r in self.results if r.status != ComplianceStatus.NOT_APPLICABLE]
        if not applicable:
            return 100.0
        passed = sum(1 for r in applicable if r.status == ComplianceStatus.PASS)
        return (passed / len(applicable)) * 100

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "standard": {
                "id": self.standard.id,
                "name": self.standard.name,
                "version": self.standard.version,
            },
            "summary": {
                "total_controls": self.total_controls,
                "passed": self.passed_controls,
                "failed": self.failed_controls,
                "compliance_score": f"{self.compliance_score:.1f}%",
            },
            "results": [
                {
                    "control_id": r.control.id,
                    "control_name": r.control.name,
                    "status": r.status.value,
                    "severity": r.control.severity,
                    "message": r.message,
                    "remediation": r.control.remediation,
                }
                for r in self.results
            ],
            "generated_at": self.generated_at.isoformat(),
        }


class ComplianceChecker:
    """Check compliance against security standards."""

    STANDARDS = {
        "owasp-top-10": OWASP_TOP_10,
        "cis-controls": CIS_CONTROLS,
    }

    def __init__(self):
        self.logger = get_logger("compliance.checker")

    def list_standards(self) -> list[SecurityStandard]:
        """List available security standards."""
        return list(self.STANDARDS.values())

    def get_standard(self, standard_id: str) -> SecurityStandard | None:
        """Get a specific standard by ID."""
        return self.STANDARDS.get(standard_id)

    async def check_compliance(
        self,
        target: Target,
        standard_id: str,
        scan_results: list[ScanResult] | None = None,
    ) -> ComplianceReport:
        """Run compliance check against a standard.

        Args:
            target: Target being assessed
            standard_id: ID of the standard to check against
            scan_results: Optional scan results to use for assessment

        Returns:
            ComplianceReport with all control results
        """
        standard = self.get_standard(standard_id)
        if not standard:
            raise ValueError(f"Unknown standard: {standard_id}")

        self.logger.info(f"Running {standard.name} compliance check for {target.value}")

        report = ComplianceReport(
            target=target.value,
            standard=standard,
        )

        # Map scan findings to compliance controls
        findings = []
        if scan_results:
            for result in scan_results:
                findings.extend(result.findings)

        for control in standard.controls:
            result = self._check_control(control, findings)
            report.results.append(result)

        return report

    def _check_control(
        self,
        control: ControlCheck,
        findings: list,
    ) -> ControlResult:
        """Check a single compliance control based on scan findings."""

        # Map control categories to finding sources
        category_mapping = {
            "Injection": ["sqli", "xss"],
            "Input Validation": ["sqli", "xss", "ssrf"],
            "Cryptography": ["ssl", "headers"],
            "Configuration": ["headers", "dirbrute"],
            "Authentication": ["headers", "crawler"],
            "Access Control": ["dirbrute", "crawler"],
            "Logging": ["headers"],
        }

        relevant_modules = category_mapping.get(control.category, [])

        # Find relevant findings
        relevant_findings = [
            f for f in findings
            if any(mod in f.source.lower() for mod in relevant_modules)
        ]

        # Determine status based on findings
        critical_high = [
            f for f in relevant_findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        medium = [
            f for f in relevant_findings
            if f.severity == Severity.MEDIUM
        ]

        if critical_high:
            return ControlResult(
                control=control,
                status=ComplianceStatus.FAIL,
                message=f"Found {len(critical_high)} critical/high severity issue(s)",
                evidence={"findings": [f.title for f in critical_high]},
            )
        elif medium:
            return ControlResult(
                control=control,
                status=ComplianceStatus.WARNING,
                message=f"Found {len(medium)} medium severity issue(s)",
                evidence={"findings": [f.title for f in medium]},
            )
        elif relevant_findings:
            return ControlResult(
                control=control,
                status=ComplianceStatus.PASS,
                message="No significant issues found",
            )
        else:
            return ControlResult(
                control=control,
                status=ComplianceStatus.NOT_APPLICABLE,
                message="No relevant scan data available",
            )

    async def generate_scan_result(
        self,
        target: Target,
        standard_id: str,
        scan_results: list[ScanResult],
    ) -> ScanResult:
        """Generate a ScanResult from compliance check."""
        report = await self.check_compliance(target, standard_id, scan_results)

        result = ScanResult(
            target=target,
            module=f"compliance.{standard_id}",
        )

        # Add summary finding
        result.add_finding(
            title=f"{report.standard.name} Compliance Assessment",
            description=f"Compliance score: {report.compliance_score:.1f}% ({report.passed_controls}/{report.total_controls} controls passed)",
            severity=Severity.INFO if report.compliance_score >= 80 else Severity.MEDIUM,
            data=report.to_dict()["summary"],
        )

        # Add failed controls
        failed = [r for r in report.results if r.status == ComplianceStatus.FAIL]
        for cr in failed:
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            result.add_finding(
                title=f"[{cr.control.id}] {cr.control.name}",
                description=cr.message,
                severity=severity_map.get(cr.control.severity, Severity.MEDIUM),
                data=cr.evidence,
                references=cr.control.references,
            )

        result.raw_data["compliance_report"] = report.to_dict()
        result.complete()

        return result
