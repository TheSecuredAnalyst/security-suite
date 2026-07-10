"""
Password strength auditor — ported from Security_Python/password_security_suite_v2.

Supports: single audit, batch file audit, policy modes (home/enterprise).
Privacy-first: exports metrics only, never stores plaintext passwords.
"""

from __future__ import annotations

import csv
import json
import math
import os
import re
import string
from dataclasses import asdict, dataclass, field
from enum import Enum

from core.logger import get_logger
from core.models import ScanResult, Severity, Target

logger = get_logger("password.auditor")

# ── Common patterns ────────────────────────────────────────────────────────────

_COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "qwerty", "abc123",
    "letmein", "monkey", "1234567890", "iloveyou", "admin", "welcome",
    "login", "pass", "master", "dragon", "shadow", "654321", "superman",
    "sunshine", "princess", "starwars", "football", "baseball", "soccer",
    "batman", "trustno1", "hello", "charlie", "donald", "access",
}

_KEYBOARD_RUNS = [
    "qwerty", "asdf", "zxcv", "qwert", "asdfg", "zxcvb",
    "12345", "23456", "34567", "45678", "56789", "67890",
]

_SEQUENCES = "abcdefghijklmnopqrstuvwxyz0123456789"


class PolicyMode(str, Enum):
    HOME = "home"
    ENTERPRISE = "enterprise"


_POLICY = {
    PolicyMode.HOME: {
        "min_length": 12,
        "preferred_length": 16,
        "description": "Home — resistant to normal offline attacks",
    },
    PolicyMode.ENTERPRISE: {
        "min_length": 14,
        "preferred_length": 20,
        "description": "Enterprise — resistant to strong offline attacks",
    },
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class AuditResult:
    length: int
    entropy: float
    score: int          # 0–100
    risk_label: str     # CRITICAL / HIGH / MEDIUM / LOW / STRONG
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    is_common: bool
    patterns_found: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Entropy calculation ────────────────────────────────────────────────────────

def _charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += 32
    return max(size, 1)


def _entropy(password: str) -> float:
    cs = _charset_size(password)
    return len(password) * math.log2(cs)


# ── Pattern detection ─────────────────────────────────────────────────────────

def _find_patterns(password: str) -> list[str]:
    found: list[str] = []
    pw_lower = password.lower()

    # Repeated characters (aaa, 111)
    if re.search(r"(.)\1{2,}", password):
        found.append("repeated characters (e.g. 'aaa')")

    # Sequential letters/numbers
    for i in range(len(pw_lower) - 2):
        chunk = pw_lower[i : i + 3]
        if chunk in _SEQUENCES or chunk[::-1] in _SEQUENCES:
            found.append("sequential characters")
            break

    # Keyboard runs
    for run in _KEYBOARD_RUNS:
        if run in pw_lower:
            found.append(f"keyboard pattern ('{run}')")
            break

    # All digits
    if password.isdigit():
        found.append("all numeric")

    return found


# ── Scorer ─────────────────────────────────────────────────────────────────────

def _score(password: str, policy: PolicyMode) -> tuple[int, list[str]]:
    """Compute 0–100 score and list of deduction reasons."""
    pol = _POLICY[policy]
    score = 50
    deductions: list[str] = []

    # Length
    min_len = pol["min_length"]
    pref_len = pol["preferred_length"]
    if len(password) >= pref_len:
        score += 25
    elif len(password) >= min_len:
        score += 10
    else:
        deficit = min_len - len(password)
        score -= deficit * 5
        deductions.append(f"too short (minimum {min_len} chars)")

    # Character variety
    varieties = sum([
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password),
    ])
    score += (varieties - 1) * 5

    # Common password
    if password.lower() in _COMMON_PASSWORDS:
        score -= 40
        deductions.append("matches a known common password")

    # Patterns
    patterns = _find_patterns(password)
    score -= len(patterns) * 8
    deductions.extend(patterns)

    return max(0, min(100, score)), deductions


def _risk_label(score: int) -> str:
    if score >= 80:
        return "STRONG"
    if score >= 60:
        return "LOW"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "HIGH"
    return "CRITICAL"


def _recommendations(result: AuditResult, policy: PolicyMode) -> list[str]:
    recs: list[str] = []
    pol = _POLICY[policy]
    if result.length < pol["preferred_length"]:
        recs.append(f"Increase length to at least {pol['preferred_length']} characters")
    if not result.has_upper:
        recs.append("Add uppercase letters")
    if not result.has_lower:
        recs.append("Add lowercase letters")
    if not result.has_digit:
        recs.append("Add numbers")
    if not result.has_special:
        recs.append("Add special characters (!@#$...)")
    if result.is_common:
        recs.append("Do not use common passwords — use a password manager")
    if result.patterns_found:
        recs.append("Avoid predictable patterns (sequences, keyboard rows, repeats)")
    if not recs:
        recs.append("Password meets policy requirements")
    return recs


# ── PasswordAuditor ────────────────────────────────────────────────────────────

class PasswordAuditor:
    """
    Password strength auditor.

    Usage:
        auditor = PasswordAuditor(policy=PolicyMode.ENTERPRISE)
        result = auditor.audit("MyP@ssw0rd!")
        print(result.score, result.risk_label, result.recommendations)
    """

    def __init__(self, policy: PolicyMode = PolicyMode.ENTERPRISE):
        self.policy = policy

    def audit(self, password: str) -> AuditResult:
        """Audit a single password. Does not store the password — only metrics."""
        if not password:
            return AuditResult(
                length=0, entropy=0.0, score=0, risk_label="CRITICAL",
                has_upper=False, has_lower=False, has_digit=False, has_special=False,
                is_common=True, patterns_found=[], recommendations=["Password cannot be empty"],
            )

        score, pattern_deductions = _score(password, self.policy)
        ent = _entropy(password)

        result = AuditResult(
            length=len(password),
            entropy=round(ent, 2),
            score=score,
            risk_label=_risk_label(score),
            has_upper=any(c.isupper() for c in password),
            has_lower=any(c.islower() for c in password),
            has_digit=any(c.isdigit() for c in password),
            has_special=any(c in string.punctuation for c in password),
            is_common=password.lower() in _COMMON_PASSWORDS,
            patterns_found=_find_patterns(password),
        )
        result.recommendations = _recommendations(result, self.policy)
        return result

    def audit_file(self, path: str) -> list[AuditResult]:
        """Audit passwords from a file (one per line). Skips blank lines and comments."""
        results: list[AuditResult] = []
        try:
            with open(path) as f:
                for line in f:
                    pw = line.rstrip("\n")
                    if pw and not pw.startswith("#"):
                        results.append(self.audit(pw))
        except FileNotFoundError:
            logger.error(f"Password file not found: {path}")
        return results

    def export_json(self, results: list[AuditResult], path: str) -> str:
        """Export audit results as JSON (no plaintext passwords)."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        return path

    def export_csv(self, results: list[AuditResult], path: str) -> str:
        """Export audit results as CSV (no plaintext passwords)."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not results:
            return path
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].to_dict().keys()))
            writer.writeheader()
            writer.writerows(r.to_dict() for r in results)
        return path

    async def run(self, target: Target) -> ScanResult:
        """Security-suite compatible run() — target.value is treated as password label."""
        result = ScanResult(target=target, module="password.auditor")
        result.add_finding(
            title="Password Audit Complete",
            description=(
                "Use PasswordAuditor.audit(password) directly for single audits, "
                "or audit_file(path) for batch processing."
            ),
            severity=Severity.INFO,
        )
        result.complete()
        return result
