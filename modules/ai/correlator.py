"""Finding correlation engine."""

from collections import defaultdict
from dataclasses import dataclass, field

from core.logger import get_logger
from core.models import Finding, ScanResult, Severity


@dataclass
class CorrelatedFinding:
    """A finding with correlation data."""
    finding: Finding
    related_findings: list[Finding] = field(default_factory=list)
    attack_chain_position: int | None = None
    combined_risk_score: float = 0.0
    tags: list[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """Represents a potential attack chain."""
    name: str
    description: str
    findings: list[Finding]
    risk_score: float
    mitre_tactics: list[str] = field(default_factory=list)


@dataclass
class CorrelationReport:
    """Full correlation analysis report."""
    target: str
    total_findings: int
    unique_findings: int
    correlated_findings: list[CorrelatedFinding]
    attack_chains: list[AttackChain]
    risk_summary: dict
    recommendations: list[str]


class FindingCorrelator:
    """Correlate and deduplicate findings across scans."""

    # Severity weights for risk scoring
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 2.0,
        Severity.INFO: 0.5,
    }

    # Attack chain patterns
    ATTACK_PATTERNS = {
        "web_compromise": {
            "name": "Web Application Compromise",
            "description": "Path from reconnaissance to potential system compromise via web vulnerabilities",
            "stages": [
                ["osint", "tech_detect"],  # Recon
                ["webscanner.crawler", "webscanner.dirbrute"],  # Discovery
                ["webscanner.xss", "webscanner.sqli"],  # Exploitation
            ],
            "mitre": ["TA0043", "TA0001", "TA0002"],  # Recon, Initial Access, Execution
        },
        "exposed_services": {
            "name": "Exposed Service Attack",
            "description": "Exposed services leading to potential unauthorized access",
            "stages": [
                ["osint.port_scan", "osint.shodan"],  # Service discovery
                ["exploit.searchsploit", "exploit.metasploit"],  # Exploit research
            ],
            "mitre": ["TA0043", "TA0001"],
        },
        "credential_exposure": {
            "name": "Credential Exposure Risk",
            "description": "Paths that could lead to credential theft",
            "stages": [
                ["osint.email_harvest"],  # Target identification
                ["webscanner.xss", "phishing"],  # Credential capture
            ],
            "mitre": ["TA0043", "TA0006"],  # Recon, Credential Access
        },
    }

    def __init__(self):
        self.logger = get_logger("ai.correlator")

    def correlate(self, scan_results: list[ScanResult]) -> CorrelationReport:
        """Correlate findings across multiple scan results.

        Args:
            scan_results: List of scan results to correlate

        Returns:
            CorrelationReport with analysis
        """
        if not scan_results:
            return CorrelationReport(
                target="",
                total_findings=0,
                unique_findings=0,
                correlated_findings=[],
                attack_chains=[],
                risk_summary={},
                recommendations=[],
            )

        target = scan_results[0].target.value

        # Collect all findings
        all_findings = []
        findings_by_module = defaultdict(list)

        for result in scan_results:
            for finding in result.findings:
                all_findings.append(finding)
                findings_by_module[result.module].append(finding)

        self.logger.info(f"Correlating {len(all_findings)} findings from {len(scan_results)} scans")

        # Deduplicate findings
        unique_findings = self._deduplicate(all_findings)

        # Correlate findings
        correlated = self._correlate_findings(unique_findings, findings_by_module)

        # Identify attack chains
        attack_chains = self._identify_attack_chains(findings_by_module)

        # Calculate risk summary
        risk_summary = self._calculate_risk_summary(correlated, attack_chains)

        # Generate recommendations
        recommendations = self._generate_recommendations(correlated, attack_chains)

        return CorrelationReport(
            target=target,
            total_findings=len(all_findings),
            unique_findings=len(unique_findings),
            correlated_findings=correlated,
            attack_chains=attack_chains,
            risk_summary=risk_summary,
            recommendations=recommendations,
        )

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on title and severity."""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.title.lower(), finding.severity)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        self.logger.debug(f"Deduplicated {len(findings)} -> {len(unique)} findings")
        return unique

    def _correlate_findings(
        self,
        findings: list[Finding],
        by_module: dict[str, list[Finding]],
    ) -> list[CorrelatedFinding]:
        """Find relationships between findings."""
        correlated = []

        for finding in findings:
            related = []
            tags = []

            # Find related findings by data overlap
            for other in findings:
                if other == finding:
                    continue

                # Check for IP/domain overlap
                finding_ips = set(finding.data.get("addresses", []) + finding.data.get("ips", []))
                other_ips = set(other.data.get("addresses", []) + other.data.get("ips", []))

                if finding_ips & other_ips:
                    related.append(other)
                    continue

                # Check for port/service overlap
                finding_ports = set(finding.data.get("ports", []))
                other_ports = set(other.data.get("ports", []))

                if finding_ports & other_ports:
                    related.append(other)
                    continue

                # Check for technology overlap
                finding_tech = set(finding.data.get("technologies", []))
                other_tech = set(other.data.get("technologies", []))

                if finding_tech & other_tech:
                    related.append(other)

            # Add tags based on finding characteristics
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                tags.append("priority")

            if "sql" in finding.title.lower() or "injection" in finding.title.lower():
                tags.append("injection")

            if "xss" in finding.title.lower() or "script" in finding.title.lower():
                tags.append("xss")

            if "exposed" in finding.title.lower() or "disclosure" in finding.title.lower():
                tags.append("exposure")

            if "credential" in finding.title.lower() or "password" in finding.title.lower():
                tags.append("credentials")

            # Calculate combined risk score
            base_score = self.SEVERITY_WEIGHTS.get(finding.severity, 1.0)
            related_boost = len(related) * 0.5
            combined_score = min(10.0, base_score + related_boost)

            correlated.append(CorrelatedFinding(
                finding=finding,
                related_findings=related,
                combined_risk_score=combined_score,
                tags=tags,
            ))

        # Sort by risk score
        correlated.sort(key=lambda x: x.combined_risk_score, reverse=True)

        return correlated

    def _identify_attack_chains(
        self,
        by_module: dict[str, list[Finding]],
    ) -> list[AttackChain]:
        """Identify potential attack chains from findings."""
        chains = []

        for pattern in self.ATTACK_PATTERNS.values():
            chain_findings = []
            stages_matched = 0

            for stage_modules in pattern["stages"]:
                stage_findings = []
                for module in stage_modules:
                    # Check for module findings (partial match)
                    for mod_name, mod_findings in by_module.items():
                        if module in mod_name:
                            # Only include non-INFO findings
                            significant = [
                                f for f in mod_findings
                                if f.severity != Severity.INFO
                            ]
                            stage_findings.extend(significant)

                if stage_findings:
                    stages_matched += 1
                    chain_findings.extend(stage_findings)

            # Only report chains with multiple stages matched
            if stages_matched >= 2 and chain_findings:
                # Calculate chain risk
                risk_score = sum(
                    self.SEVERITY_WEIGHTS.get(f.severity, 1.0)
                    for f in chain_findings
                ) / len(chain_findings) * stages_matched

                chains.append(AttackChain(
                    name=pattern["name"],
                    description=pattern["description"],
                    findings=chain_findings,
                    risk_score=min(10.0, risk_score),
                    mitre_tactics=pattern["mitre"],
                ))

        # Sort by risk
        chains.sort(key=lambda x: x.risk_score, reverse=True)

        return chains

    def _calculate_risk_summary(
        self,
        correlated: list[CorrelatedFinding],
        chains: list[AttackChain],
    ) -> dict:
        """Calculate overall risk summary."""
        severity_counts = defaultdict(int)
        for cf in correlated:
            severity_counts[cf.finding.severity.value] += 1

        # Overall risk score (0-100)
        if not correlated:
            overall_score = 0
        else:
            weighted_sum = sum(
                self.SEVERITY_WEIGHTS.get(cf.finding.severity, 1.0)
                for cf in correlated
            )
            max_possible = len(correlated) * 10.0
            overall_score = min(100, (weighted_sum / max_possible) * 100 * (1 + len(chains) * 0.1))

        # Risk level
        if overall_score >= 70:
            risk_level = "CRITICAL"
        elif overall_score >= 50:
            risk_level = "HIGH"
        elif overall_score >= 30:
            risk_level = "MEDIUM"
        elif overall_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "overall_score": round(overall_score, 1),
            "risk_level": risk_level,
            "severity_breakdown": dict(severity_counts),
            "attack_chains_identified": len(chains),
            "high_priority_findings": sum(
                1 for cf in correlated
                if cf.finding.severity in (Severity.CRITICAL, Severity.HIGH)
            ),
        }

    def _generate_recommendations(
        self,
        correlated: list[CorrelatedFinding],
        chains: list[AttackChain],
    ) -> list[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Check for critical/high findings
        critical_high = [
            cf for cf in correlated
            if cf.finding.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if critical_high:
            recommendations.append(
                f"IMMEDIATE: Address {len(critical_high)} critical/high severity finding(s) first"
            )

        # Check for attack chains
        if chains:
            recommendations.append(
                f"ATTACK SURFACE: {len(chains)} potential attack chain(s) identified - "
                "review and break chain links"
            )

        # Check for specific vulnerability types
        tags = set()
        for cf in correlated:
            tags.update(cf.tags)

        if "injection" in tags:
            recommendations.append(
                "INPUT VALIDATION: Implement parameterized queries and input sanitization"
            )

        if "xss" in tags:
            recommendations.append(
                "OUTPUT ENCODING: Implement proper output encoding and CSP headers"
            )

        if "exposure" in tags:
            recommendations.append(
                "EXPOSURE: Review and restrict access to exposed resources and information"
            )

        if "credentials" in tags:
            recommendations.append(
                "CREDENTIALS: Review credential handling, implement MFA where possible"
            )

        # General recommendations based on finding count
        if len(correlated) > 20:
            recommendations.append(
                "SCOPE: High number of findings - consider prioritized remediation sprints"
            )

        if not recommendations:
            recommendations.append(
                "MAINTAIN: Continue regular security assessments to maintain posture"
            )

        return recommendations
