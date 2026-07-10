"""Nuclei vulnerability scanner integration."""

import asyncio
import json
import os
import shutil
import tempfile

from core.models import ScanResult, Severity, Target
from modules.webscanner.base import WebScannerModule


class NucleiScanner(WebScannerModule):
    """Run Nuclei vulnerability scanner."""

    name = "nuclei"
    description = "Run Nuclei templates for vulnerability detection"

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    def __init__(
        self,
        templates: list[str] | None = None,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
    ):
        super().__init__()
        self.templates = templates
        self.severity_filter = severity or ["critical", "high", "medium"]
        self.tags = tags
        self.nuclei_available = shutil.which("nuclei") is not None

    async def run(self, target: Target) -> ScanResult:
        """Run Nuclei scan on target."""
        result = self.create_result(target)

        if not self.nuclei_available:
            result.errors.append("Nuclei not found. Install from https://github.com/projectdiscovery/nuclei")
            result.success = False
            result.complete()
            return result

        url = self._build_url(target)
        self.logger.info(f"Starting Nuclei scan on {url}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            cmd = [
                "nuclei",
                "-u", url,
                "-json-export", output_file,
                "-silent",
            ]

            # Add severity filter
            if self.severity_filter:
                cmd.extend(["-severity", ",".join(self.severity_filter)])

            # Add specific templates
            if self.templates:
                for t in self.templates:
                    cmd.extend(["-t", t])

            # Add tags
            if self.tags:
                cmd.extend(["-tags", ",".join(self.tags)])

            self.logger.info(f"Running: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()

            # Parse results
            findings = []
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file) as f:
                    for line in f:
                        try:
                            finding = json.loads(line.strip())
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            result.raw_data["findings"] = findings
            result.raw_data["nuclei_output"] = stdout.decode() if stdout else ""

            # Convert to ScanResult findings
            for finding in findings:
                template_id = finding.get("template-id", "unknown")
                info = finding.get("info", {})
                severity = info.get("severity", "info").lower()
                matched_at = finding.get("matched-at", url)

                result.add_finding(
                    title=info.get("name", template_id),
                    description=info.get("description", f"Nuclei template {template_id} matched"),
                    severity=self.SEVERITY_MAP.get(severity, Severity.INFO),
                    data={
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "matcher_name": finding.get("matcher-name"),
                        "extracted_results": finding.get("extracted-results", []),
                    },
                    references=info.get("reference", []),
                )

            if not findings:
                result.add_finding(
                    title="No Vulnerabilities Found",
                    description="Nuclei scan completed with no findings",
                    severity=Severity.INFO,
                )

        except Exception as e:
            result.errors.append(f"Nuclei scan failed: {str(e)}")
            result.success = False

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

        result.complete()
        return result

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
