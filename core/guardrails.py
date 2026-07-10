"""
Guardrails Engine — the security and ethics layer that gates ALL exploit and remediation actions.

Design principles:
  1. DENY by default — nothing executes without a valid EngagementSession.
  2. ROE is law   — targets outside the authorized scope are permanently blocked.
  3. Check-only   — live exploitation requires a second explicit opt-in flag.
  4. AI distrust  — all AI-generated scripts pass a static safety analyzer before execution.
  5. Immutable log — every gate decision is appended to an in-process audit log.
  6. Rate limits  — per-target attempt caps prevent accidental DoS from runaway loops.
  7. No override  — guardrails cannot be disabled at runtime; only EngagementSession scope.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from core.logger import get_logger

logger = get_logger("core.guardrails")

# ── Constants ──────────────────────────────────────────────────────────────────

#: Maximum exploit attempts per target per 60-second window
RATE_LIMIT_MAX = int(os.getenv("GUARDRAIL_RATE_LIMIT", "10"))

#: Default session lifetime in hours
SESSION_TTL_HOURS = int(os.getenv("GUARDRAIL_SESSION_TTL_HOURS", "8"))

#: Module name fragments that are ALWAYS blocked regardless of session settings
FORBIDDEN_MODULE_PATTERNS = [
    "dos/",                # Denial of service
    "auxiliary/dos/",
    "ransomware",          # Ransomware
    "wiper",              # Data wiping
    "destructive",
    "format",             # Disk formatting
    "delete_files",       # File deletion
    "overwrite",          # Overwrite payloads
    "killmbr",            # Kill master boot record
    "encrypt_files",      # Encryption payloads
]

# ── Script safety ─────────────────────────────────────────────────────────────

#: Regex patterns in AI-generated scripts that trigger hard block
BANNED_SCRIPT_PATTERNS: list[tuple[str, str]] = [
    (r"rm\s+-[rRfF]+\s+/",              "rm -rf on root filesystem"),
    (r"rm\s+-[rRfF]+\s+\*",             "rm -rf wildcard"),
    (r"dd\s+if=",                        "dd command (can wipe disks)"),
    (r"mkfs\.",                          "filesystem format command"),
    (r":\(\)\s*\{.*\|.*&",              "fork bomb"),
    (r"curl[^;]*\|\s*(?:bash|sh)",      "curl pipe to shell"),
    (r"wget[^;]*\|\s*(?:bash|sh)",      "wget pipe to shell"),
    (r">\s*/dev/sd[a-z]",               "write to raw disk device"),
    (r">\s*/dev/nvme",                   "write to NVMe device"),
    (r">\s*/dev/null\s+2>&1\s*&&",     "redirect stderr to suppress errors"),
    (r"(?:chmod|chown)\s+777\s+/",      "world-writable root path"),
    (r"passwd\s+root",                   "change root password"),
    (r"echo\s+.*>>\s*/etc/passwd",      "modify /etc/passwd"),
    (r"echo\s+.*>>\s*/etc/shadow",      "modify /etc/shadow"),
    (r"(?:apt|apt-get|yum|dnf|pacman)\s+(?:remove|purge|erase|autoremove)", "package removal"),
    (r"pip\s+uninstall",                 "pip uninstall"),
    (r"systemctl\s+(?:stop|disable)\s+(?:ssh|sshd|networking|network-manager|firewall)", "stop critical service"),
    (r"ufw\s+disable",                   "disable UFW firewall"),
    (r"iptables\s+-F$",                  "flush all iptables rules without replacement"),
    (r"(?:reboot|shutdown|halt|poweroff)", "system power/restart command"),
    (r"crontab\s+-r",                    "remove all crontabs"),
    (r"base64\s+(?:--decode|-d)[^;]*\|\s*(?:bash|sh)", "base64 decode and execute"),
    (r"eval\s+\$\(",                     "eval execution"),
    (r"history\s+-[cCw]",               "clear command history"),
    (r"shred\s+",                        "secure file deletion (shred)"),
    (r"wipe\s+",                         "wipe command"),
    (r"(?:truncate|zero)\s+/etc/",      "truncate critical config"),
]


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class EngagementSession:
    """
    Authorization token required before any exploit or automated-remediation action.

    Create one via GuardrailsEngine.create_session().  All fields are immutable after
    creation — a new session must be created to change scope.
    """
    session_id: str
    operator: str
    engagement_id: str
    created_at: datetime
    expires_at: datetime
    roe_allowed: list[str]           # CIDRs / IPs in scope (empty = block all)
    roe_forbidden: list[str]         # CIDRs / IPs always blocked
    allow_live_exploitation: bool    # False = check-only; True = payload allowed
    authorized_modules: list[str]    # Empty = all non-forbidden; non-empty = strict allowlist

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "operator": self.operator,
            "engagement_id": self.engagement_id,
            "expires_at": self.expires_at.isoformat(),
            "roe_allowed": self.roe_allowed,
            "roe_forbidden": self.roe_forbidden,
            "allow_live_exploitation": self.allow_live_exploitation,
            "expired": self.is_expired(),
        }


@dataclass
class AuditEntry:
    timestamp: str
    operator: str
    session_id: str
    action: str
    target: str
    module: str
    decision: str   # ALLOWED | BLOCKED | ERROR
    reason: str


@dataclass
class ScriptValidationResult:
    safe: bool
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ── Guardrails Engine ─────────────────────────────────────────────────────────

class GuardrailsEngine:
    """
    Singleton guardrail layer.  Import the module-level `guardrails` instance.
    """

    def __init__(self) -> None:
        self._session: EngagementSession | None = None
        self._rate_tracker: dict[str, list[float]] = defaultdict(list)
        self._audit_log: list[AuditEntry] = []

    # ── Session management ─────────────────────────────────────────────────────

    def create_session(
        self,
        operator: str,
        engagement_id: str,
        roe_allowed: list[str],
        roe_forbidden: list[str] | None = None,
        allow_live_exploitation: bool = False,
        authorized_modules: list[str] | None = None,
        ttl_hours: int = SESSION_TTL_HOURS,
    ) -> EngagementSession:
        """
        Create and activate an engagement session.

        Args:
            operator:               Human operator name (recorded in audit log)
            engagement_id:          Ticket / engagement reference
            roe_allowed:            List of CIDR ranges in scope. REQUIRED — empty = all blocked.
            roe_forbidden:          CIDRs always blocked even if in roe_allowed
            allow_live_exploitation: If True, live payloads are permitted (default False)
            authorized_modules:     Explicit module allowlist (empty = all non-forbidden)
            ttl_hours:              Session lifetime in hours (default 8)
        """
        if not roe_allowed:
            raise ValueError(
                "roe_allowed must contain at least one CIDR/IP. "
                "An empty scope means nothing can be targeted — create a session with explicit scope."
            )
        if not operator.strip():
            raise ValueError("operator name is required for audit trail")
        if not engagement_id.strip():
            raise ValueError("engagement_id is required for audit trail")

        now = datetime.now(timezone.utc)
        session = EngagementSession(
            session_id=str(uuid.uuid4()),
            operator=operator.strip(),
            engagement_id=engagement_id.strip(),
            created_at=now,
            expires_at=now + timedelta(hours=ttl_hours),
            roe_allowed=roe_allowed,
            roe_forbidden=roe_forbidden or [],
            allow_live_exploitation=allow_live_exploitation,
            authorized_modules=authorized_modules or [],
        )
        self._session = session
        self._audit("SESSION_CREATED", "-", "-", "ALLOWED",
                    f"operator={operator} engagement={engagement_id} "
                    f"live_exploit={allow_live_exploitation} scope={roe_allowed}")
        logger.info(f"Engagement session created: {session.session_id} "
                    f"by {operator} (engagement: {engagement_id})")
        return session

    def end_session(self) -> None:
        """Explicitly close the active session."""
        if self._session:
            self._audit("SESSION_ENDED", "-", "-", "ALLOWED", "Operator closed session")
            logger.info(f"Engagement session ended: {self._session.session_id}")
            self._session = None

    def active_session(self) -> EngagementSession | None:
        return self._session

    # ── Gate methods ───────────────────────────────────────────────────────────

    def gate_exploit(
        self,
        target: str,
        module_name: str,
        live: bool = False,
    ) -> tuple[bool, str]:
        """
        Primary gate for ALL exploit/check operations.

        Returns (allowed: bool, reason: str).
        """
        # 1 — Require active non-expired session
        if not self._session:
            return self._deny(target, module_name, "No active engagement session. Call guardrails.create_session() first.")
        if self._session.is_expired():
            return self._deny(target, module_name, f"Engagement session {self._session.session_id} has expired.")

        # 2 — ROE: forbidden CIDRs always block
        forbidden_hit = self._cidr_match(target, self._session.roe_forbidden)
        if forbidden_hit:
            return self._deny(target, module_name, f"Target {target} is in forbidden scope ({forbidden_hit})")

        # 3 — ROE: target must be in allowed scope
        allowed_hit = self._cidr_match(target, self._session.roe_allowed)
        if not allowed_hit:
            return self._deny(target, module_name,
                f"Target {target} is NOT in authorized scope {self._session.roe_allowed}")

        # 4 — Forbidden module patterns (always blocked)
        for pattern in FORBIDDEN_MODULE_PATTERNS:
            if pattern in module_name.lower():
                return self._deny(target, module_name, f"Module matches forbidden pattern '{pattern}'")

        # 5 — Module allowlist (if session has one)
        if self._session.authorized_modules:
            if not any(module_name.startswith(m) for m in self._session.authorized_modules):
                return self._deny(target, module_name,
                    "Module not in session's authorized_modules list")

        # 6 — Live exploitation requires explicit session flag
        if live and not self._session.allow_live_exploitation:
            return self._deny(target, module_name,
                "Live exploitation blocked: session was created with allow_live_exploitation=False. "
                "Create a new session with allow_live_exploitation=True to enable payload execution.")

        # 7 — Rate limit
        ok, rate_reason = self._check_rate_limit(target)
        if not ok:
            return self._deny(target, module_name, rate_reason)

        # All gates passed
        self._audit("EXPLOIT_GATE", target, module_name, "ALLOWED",
                    f"live={live} session={self._session.session_id}")
        return True, "OK"

    def gate_remediation(self, target: str, script: str) -> tuple[bool, ScriptValidationResult]:
        """
        Gate for applying AI-generated remediation scripts.

        Returns (allowed: bool, validation_result).
        """
        if not self._session:
            result = ScriptValidationResult(safe=False, violations=["No active engagement session"])
            return False, result

        validation = self.validate_script(script)
        if not validation.safe:
            self._audit("REMEDIATION_GATE", target, "script", "BLOCKED",
                        f"violations={validation.violations}")
            return False, validation

        self._audit("REMEDIATION_GATE", target, "script", "ALLOWED", "Script passed safety checks")
        return True, validation

    # ── Script validator ───────────────────────────────────────────────────────

    def validate_script(self, script: str) -> ScriptValidationResult:
        """
        Static safety analysis of a shell script.

        Hard violations → safe=False (script is blocked).
        Warnings       → safe=True (script is allowed but user should review).
        """
        violations: list[str] = []
        warnings: list[str] = []

        for pattern, description in BANNED_SCRIPT_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE | re.MULTILINE):
                violations.append(f"Banned pattern detected: {description}")

        # Warnings (soft checks)
        if "sudo" in script and "NOPASSWD" in script:
            warnings.append("Script modifies sudoers configuration")
        if re.search(r">\s*/etc/", script):
            warnings.append("Script overwrites a file in /etc/ — review carefully")
        if "iptables" in script or "nftables" in script:
            warnings.append("Script modifies firewall rules — verify connectivity is maintained")
        if re.search(r"systemctl\s+restart", script):
            warnings.append("Script restarts a service — ensure this is non-critical or off-hours")
        if not re.search(r"(?:\.bak|\.orig|cp\s+.*\s+\S+)", script):
            warnings.append("No backup step detected — consider adding 'cp file file.bak' before modifications")

        return ScriptValidationResult(
            safe=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    # ── Audit log ──────────────────────────────────────────────────────────────

    def get_audit_log(self) -> list[dict]:
        return [
            {
                "timestamp": e.timestamp,
                "operator": e.operator,
                "session_id": e.session_id,
                "action": e.action,
                "target": e.target,
                "module": e.module,
                "decision": e.decision,
                "reason": e.reason,
            }
            for e in self._audit_log
        ]

    def export_audit_log(self, path: str) -> str:
        import json
        import os  # noqa: PLC0415
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.get_audit_log(), f, indent=2)
        return path

    # ── Private helpers ────────────────────────────────────────────────────────

    def _deny(self, target: str, module: str, reason: str) -> tuple[bool, str]:
        self._audit("EXPLOIT_GATE", target, module, "BLOCKED", reason)
        logger.warning(f"[GUARDRAIL BLOCK] target={target} module={module} reason={reason}")
        return False, reason

    def _audit(self, action: str, target: str, module: str, decision: str, reason: str) -> None:
        operator = self._session.operator if self._session else "system"
        session_id = self._session.session_id if self._session else "none"
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            operator=operator,
            session_id=session_id,
            action=action,
            target=target,
            module=module,
            decision=decision,
            reason=reason,
        )
        self._audit_log.append(entry)

    def _check_rate_limit(self, target: str) -> tuple[bool, str]:
        now = time.monotonic()
        window = 60.0
        timestamps = [t for t in self._rate_tracker[target] if now - t < window]
        self._rate_tracker[target] = timestamps
        if len(timestamps) >= RATE_LIMIT_MAX:
            return False, (
                f"Rate limit: {RATE_LIMIT_MAX} attempts per {int(window)}s reached for {target}. "
                "Wait before retrying."
            )
        self._rate_tracker[target].append(now)
        return True, "OK"

    @staticmethod
    def _cidr_match(target: str, cidr_list: list[str]) -> str:
        """Return the matching CIDR string if target falls within any list entry, else ''."""
        try:
            target_ip = ipaddress.ip_address(target.split(":")[0])
            for cidr in cidr_list:
                try:
                    if target_ip in ipaddress.ip_network(cidr, strict=False):
                        return cidr
                except ValueError:
                    if target.split(":")[0] == cidr:
                        return cidr
        except ValueError:
            # Hostname — do literal match
            for cidr in cidr_list:
                if target == cidr or target.endswith(f".{cidr}"):
                    return cidr
        return ""


# ── Module-level singleton ─────────────────────────────────────────────────────
guardrails = GuardrailsEngine()
