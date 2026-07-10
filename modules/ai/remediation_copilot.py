"""LLM-driven interactive remediation copilot with prerequisite checking."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field

from core.logger import get_logger
from core.models import Finding, ScanResult, Severity
from modules.ai.llm_client import BaseLLMClient, Message, get_llm_client

# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class PrereqCheck:
    name: str
    met: bool
    hint: str = ""          # what to do if not met


@dataclass
class PrereqResult:
    checks: list[PrereqCheck] = field(default_factory=list)
    can_autofix: bool = True    # False when target is remote and not localhost
    blocking: list[str] = field(default_factory=list)   # unmet checks that block execution

    @property
    def all_met(self) -> bool:
        return len(self.blocking) == 0


@dataclass
class RemediationStep:
    label: str      # [CHECK] / [FIX] / [VERIFY]
    command: str
    description: str = ""


@dataclass
class RemediationPlan:
    finding_title: str
    severity: str
    steps: list[RemediationStep] = field(default_factory=list)
    advisory_only: bool = False     # True when we can advise but not execute
    raw_response: str = ""


# ── Prerequisite checks ───────────────────────────────────────────────────────

class RemediationPrereqs:
    """Static factory methods for common prerequisite checks."""

    @staticmethod
    def sudo_available() -> PrereqCheck:
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"], capture_output=True, timeout=5
            )
            met = result.returncode == 0
        except Exception:
            met = False
        return PrereqCheck(
            name="sudo access",
            met=met,
            hint="Run: sudo -v  to cache credentials, or add your user to the sudo group",
        )

    @staticmethod
    def tool_installed(tool: str) -> PrereqCheck:
        met = shutil.which(tool) is not None
        return PrereqCheck(
            name=f"{tool} installed",
            met=met,
            hint=f"Install: sudo apt install {tool}",
        )

    @staticmethod
    def file_writable(path: str) -> PrereqCheck:
        met = os.access(path, os.W_OK) if os.path.exists(path) else False
        return PrereqCheck(
            name=f"{path} writable",
            met=met,
            hint=f"Run with sudo or fix permissions: sudo chmod u+w {path}",
        )

    @staticmethod
    def service_running(service: str) -> PrereqCheck:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", service],
                capture_output=True, timeout=5,
            )
            met = result.returncode == 0
        except Exception:
            met = False
        return PrereqCheck(
            name=f"{service} running",
            met=met,
            hint=f"Start service: sudo systemctl start {service}",
        )

    @staticmethod
    def is_local_target(target: str) -> PrereqCheck:
        local_names = {"localhost", "127.0.0.1", "::1", socket.gethostname()}
        try:
            local_names.add(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
        met = target.rstrip("/").split("://")[-1].split(":")[0].split("/")[0] in local_names
        return PrereqCheck(
            name="target is local host",
            met=met,
            hint="Commands can only be auto-applied on the local machine. For remote targets, review and apply manually.",
        )

    @classmethod
    def for_finding(cls, finding: Finding, target: str) -> PrereqResult:
        """Return the relevant prerequisite checks for a given finding."""
        result = PrereqResult()
        title = finding.title.lower()
        desc  = finding.description.lower()
        text  = f"{title} {desc}"

        local_check = cls.is_local_target(target)
        result.can_autofix = local_check.met

        if not local_check.met:
            result.checks.append(local_check)
            result.blocking.append(local_check.name)
            return result   # no point checking the rest for remote targets

        # Always need sudo for system-level changes
        needs_sudo = any(k in text for k in (
            "firewall", "ufw", "port", "redis", "ssh", "mysql", "postgres",
            "service", "sysctl", "chmod", "kernel", "cups", "apparmor", "systemctl",
        ))
        if needs_sudo:
            sudo_check = cls.sudo_available()
            result.checks.append(sudo_check)
            if not sudo_check.met:
                result.blocking.append(sudo_check.name)

        # Redis
        if "redis" in text:
            cfg = cls.file_writable("/etc/redis/redis.conf")
            result.checks.append(cfg)
            if not cfg.met:
                result.blocking.append(cfg.name)
            result.checks.append(cls.service_running("redis"))

        # SSH
        if "ssh" in text and "header" not in text:
            cfg = cls.file_writable("/etc/ssh/sshd_config")
            result.checks.append(cfg)
            if not cfg.met:
                result.blocking.append(cfg.name)

        # Firewall / UFW
        if any(k in text for k in ("firewall", "ufw", "port")):
            ufw = cls.tool_installed("ufw")
            result.checks.append(ufw)
            if not ufw.met:
                result.blocking.append(ufw.name)

        # SSL/TLS
        if any(k in text for k in ("ssl", "tls", "certificate")):
            result.checks.append(cls.tool_installed("certbot"))
            result.checks.append(cls.tool_installed("openssl"))

        # Web server headers
        if any(k in text for k in ("header", "csp", "hsts", "x-frame")):
            nginx_cfg = "/etc/nginx/sites-available/default"
            apache_cfg = "/etc/apache2/apache2.conf"
            if os.path.exists(nginx_cfg):
                result.checks.append(cls.file_writable(nginx_cfg))
            elif os.path.exists(apache_cfg):
                result.checks.append(cls.file_writable(apache_cfg))

        # CUPS
        if "cups" in text:
            result.checks.append(cls.service_running("cups"))

        # Docker
        if "docker" in text:
            result.checks.append(cls.tool_installed("docker"))

        # fail2ban
        if "fail2ban" in text:
            result.checks.append(cls.tool_installed("fail2ban"))

        return result


# ── Remediation Copilot ───────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior Linux security engineer specialising in Ubuntu 24.04 LTS hardening.
Your job is to produce exact, executable shell commands to fix security findings.

Strict rules:
- Output ONLY commands — no prose, no explanations, no markdown
- Use 'sudo' when root is needed
- NEVER suggest opening a text editor (nano, vim, vi, gedit) — use sed / tee / echo
- Each line must be a standalone shell command or a comment starting with #
- Prefix each command with one of:
    [CHECK]  — read-only check to verify the issue
    [FIX]    — the actual remediation command
    [VERIFY] — command to confirm the fix worked
- If multi-step, output one command per line in order
- If the finding cannot be auto-fixed (e.g. application source code change required), output exactly:
    # ADVISORY: <one-line explanation>"""


class RemediationCopilot:
    """LLM-driven interactive remediation for secsuite scan findings."""

    def __init__(
        self,
        provider: str = "ollama",
        model: str | None = None,
        base_url: str | None = None,
        target: str = "localhost",
    ):
        self.logger = get_logger("ai.remediation_copilot")
        self.provider = provider
        self.target = target
        self._client_kwargs: dict = {}
        if model:
            self._client_kwargs["model"] = model
        if base_url:
            self._client_kwargs["base_url"] = base_url
        self._client: BaseLLMClient | None = None

    def _get_client(self) -> BaseLLMClient:
        if self._client is None:
            self._client = get_llm_client(self.provider, **self._client_kwargs)
        return self._client

    # ── Prerequisite checking ──────────────────────────────────────────────────

    def check_prerequisites(self, finding: Finding) -> PrereqResult:
        return RemediationPrereqs.for_finding(finding, self.target)

    # ── LLM plan generation ────────────────────────────────────────────────────

    async def generate_plan(
        self, finding: Finding, prereq: PrereqResult
    ) -> RemediationPlan:
        """Ask the LLM to generate a step-by-step remediation plan."""
        prereq_summary = (
            "All prerequisites met."
            if prereq.all_met
            else "Missing prerequisites: " + ", ".join(prereq.blocking)
        )

        user_message = (
            f"Security finding on Ubuntu 24.04 LTS:\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Severity: {finding.severity.value}\n"
            f"Target: {self.target}\n"
            f"Prerequisites: {prereq_summary}\n\n"
            f"Generate the remediation commands."
        )

        messages = [
            Message(role="system", content=SYSTEM_PROMPT),
            Message(role="user",   content=user_message),
        ]

        try:
            response = await self._get_client().chat(
                messages, temperature=0.1, max_tokens=600
            )
            raw = response.content.strip()
        except Exception as exc:
            self.logger.error("LLM request failed: %s", exc)
            raw = f"# ADVISORY: LLM unavailable — {exc}"

        return self._parse_plan(finding.title, finding.severity.value, raw)

    def _parse_plan(self, title: str, severity: str, raw: str) -> RemediationPlan:
        """Parse LLM output into structured RemediationPlan."""
        # Strip markdown fences
        import re
        raw = re.sub(r"```(?:bash|sh)?\s*", "", raw)
        raw = re.sub(r"```", "", raw)

        steps: list[RemediationStep] = []
        advisory_only = False

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("# ADVISORY:"):
                advisory_only = True
                steps.append(RemediationStep(
                    label="ADVISORY",
                    command=line,
                    description="Manual review required",
                ))
            elif line.startswith("[CHECK]"):
                steps.append(RemediationStep(label="CHECK", command=line[7:].strip()))
            elif line.startswith("[FIX]"):
                steps.append(RemediationStep(label="FIX",   command=line[5:].strip()))
            elif line.startswith("[VERIFY]"):
                steps.append(RemediationStep(label="VERIFY", command=line[8:].strip()))
            elif line.startswith("#"):
                steps.append(RemediationStep(label="INFO", command=line))
            else:
                # Unlabelled line — treat as FIX
                steps.append(RemediationStep(label="FIX", command=line))

        if not steps:
            advisory_only = True
            steps.append(RemediationStep(
                label="ADVISORY",
                command="# ADVISORY: No actionable commands generated",
            ))

        return RemediationPlan(
            finding_title=title,
            severity=severity,
            steps=steps,
            advisory_only=advisory_only,
            raw_response=raw,
        )

    # ── Convenience: plan for all findings in a result set ────────────────────

    async def plans_for_results(
        self,
        results: list[ScanResult],
        min_severity: Severity = Severity.MEDIUM,
    ) -> list[tuple[Finding, PrereqResult, RemediationPlan]]:
        """Generate (finding, prereq, plan) triples for all qualifying findings."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH:     1,
            Severity.MEDIUM:   2,
            Severity.LOW:      3,
            Severity.INFO:     4,
        }
        threshold = severity_order[min_severity]

        findings: list[Finding] = []
        for result in results:
            for f in result.findings:
                if severity_order.get(f.severity, 99) <= threshold:
                    findings.append(f)

        # Sort CRITICAL first
        findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        output = []
        for finding in findings:
            prereq = self.check_prerequisites(finding)
            plan   = await self.generate_plan(finding, prereq)
            output.append((finding, prereq, plan))
        return output
