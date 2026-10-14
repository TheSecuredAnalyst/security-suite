"""Find credentials committed to source.

Matched values are never stored or printed in full: a finding carries the
first four characters and the length, enough to locate and rotate it.
"""

from __future__ import annotations

import bisect
import math
import re
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path

from .common import CodeFinding, downgrade
from .walker import is_test_path, iter_files


@dataclass(frozen=True)
class SecretRule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: str = "high"
    group: int = 0           # which regex group is the secret itself
    min_entropy: float = 0.0


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


RULES: list[SecretRule] = [
    SecretRule("aws-access-key", "AWS access key ID", _r(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high", 1),
    SecretRule("github-token", "GitHub token",
               _r(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), "critical", 1),
    SecretRule("slack-token", "Slack token", _r(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), "high", 1),
    SecretRule("slack-webhook", "Slack webhook URL",
               _r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})"),
               "medium", 1),
    SecretRule("stripe-live-key", "Stripe live secret key",
               _r(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b"), "critical", 1),
    SecretRule("google-api-key", "Google API key", _r(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), "medium", 1),
    SecretRule("anthropic-key", "Anthropic API key", _r(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), "critical", 1),
    SecretRule("openai-key", "OpenAI API key",
               _r(r"\b(sk-(?:proj-)?[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-proj-[A-Za-z0-9_\-]{40,})"),
               "critical", 1),
    SecretRule("sendgrid-key", "SendGrid API key",
               _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "high", 1),
    SecretRule("twilio-key", "Twilio API key", _r(r"\b(SK[0-9a-f]{32})\b"), "medium", 1, 3.0),
    SecretRule("private-key", "Private key",
               _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
               "critical", 1),
    SecretRule("jwt", "JSON Web Token",
               _r(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), "medium", 1),
    SecretRule("db-url-password", "Database URL with password",
               _r(r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://[^:\s/'\"]+:([^@\s'\"]{4,})@)"),
               "high", 2, 2.5),
    SecretRule("generic-secret", "Hard-coded secret",
               _r(r"""(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth[_-]?key|access[_-]?key)[\w.-]{0,20}["']?[ \t]*[:=][ \t]*["']([^"'\s]{12,})["']"""),
               "medium", 1, 3.5),
]

# Values that are obviously not real credentials.
_PLACEHOLDER = re.compile(
    r"(?i)example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|<[^>]*>|\$\{|\{\{|"
    r"process\.env|import\.meta|env\(|getenv|os\.environ|^ENV:|redacted|\*\*\*|test|fake|lorem|"
    r"^\$(?:2[abxy]|argon2\w*|scrypt|pbkdf2[\w-]*)\$|"  # password hashes, not credentials
    r"^(.)\1+$|abcdef|123456"
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def redact(value: str) -> str:
    return f"{value[:4]}…({len(value)} chars)"


def scan_text(text: str, rel: str, rules: list[SecretRule] = RULES) -> list[CodeFinding]:
    out: list[CodeFinding] = []
    seen_lines: set[int] = set()
    test = is_test_path(rel)
    starts: list[int] | None = None
    lines: list[str] | None = None
    for rule in rules:
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if rule.id != "private-key" and _PLACEHOLDER.search(value):
                continue
            if rule.min_entropy and entropy(value) < rule.min_entropy:
                continue
            if rule.id == "generic-secret" and not any(c.isdigit() for c in value):
                continue  # identifiers and words ("passwordConfirmation") are not secrets
            if starts is None:
                starts = [0] + [n.end() for n in re.finditer("\n", text)]
                lines = text.split("\n")
            lineno = bisect.bisect_right(starts, m.start())
            line = lines[lineno - 1] if lines else ""
            # One finding per line: the specific rules run first, so a key that is
            # also a "generic secret" is reported once, under its real name.
            if len(line) > 2000 or lineno in seen_lines:
                continue
            seen_lines.add(lineno)
            shown = line.replace(value, redact(value)).strip()[:200]
            out.append(CodeFinding(
                check="secrets", rule_id=f"secret.{rule.id}", title=rule.title,
                severity=downgrade(rule.severity, 2) if test else rule.severity,
                file=rel, line=lineno, snippet=shown, cwe="CWE-798",
                confidence="high" if rule.id not in ("generic-secret", "jwt") else "medium",
                message=(f"{rule.title} committed to source ({redact(value)}). "
                         "Rotate it, then remove it from the code and the git history."
                         + (" Found in test code." if test else "")),
                data={"redacted": redact(value), "in_tests": test},
            ))
    return out


def git_ignored(base: Path, rels: list[str]) -> set[str]:
    """Which of ``rels`` git ignores. Empty when ``base`` is not a repository."""
    git = shutil.which("git")
    if not git or not rels:
        return set()
    try:
        proc = subprocess.run(  # nosec B603
            [git, "-C", str(base), "check-ignore", "--stdin", "-z"],
            input="\0".join(rels), capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return set()
    return {p for p in proc.stdout.split("\0") if p}


def scan(root: Path, include_tests: bool = True) -> list[CodeFinding]:
    root = root.resolve()
    base = root if root.is_dir() else root.parent
    findings: list[CodeFinding] = []
    for path, text in iter_files(root, skip_tests=not include_tests):
        findings += scan_text(text, str(path.relative_to(base)))
    # A secret in a git-ignored file (.env, storage/) is local configuration, not a
    # leak. It is still reported, at info, so it can be checked for weak values.
    ignored = git_ignored(base, sorted({f.file for f in findings}))
    for f in findings:
        if f.file in ignored:
            f.severity = "info"
            f.data["git_ignored"] = True
            f.message = (f"{f.title} in a git-ignored file ({f.data['redacted']}): local "
                         "configuration, not committed.")
    return findings
