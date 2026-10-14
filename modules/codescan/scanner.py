"""Run the code checks over a source tree and report in SecSuite's shapes."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

from core.logger import get_logger
from core.models import ScanResult, Severity, Target

from . import deps, sast, secrets
from .common import SEVERITIES, CodeFinding

CHECKS = ("secrets", "deps", "sast")
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


class CodeScanner:
    """Passive: reads files under ``root``. The only network call is the OSV
    lookup of dependency names and versions, skipped with ``offline=True``."""

    def __init__(self, root: Path, checks: tuple[str, ...] = CHECKS, include_tests: bool = False,
                 offline: bool = False, client: httpx.Client | None = None):
        self.root = Path(root).resolve()
        self.checks = checks
        self.include_tests = include_tests
        self.offline = offline
        self.client = client
        self.logger = get_logger("codescan")
        self.stats: dict[str, Any] = {}
        self.errors: list[str] = []

    def run(self) -> list[CodeFinding]:
        if not self.root.exists():
            raise FileNotFoundError(self.root)
        found: list[CodeFinding] = []
        if "secrets" in self.checks:
            found += secrets.scan(self.root, self.include_tests)
        if "sast" in self.checks:
            found += sast.scan(self.root, self.include_tests)
        if "deps" in self.checks:
            if self.offline:
                self.stats["deps"] = {"skipped": "offline"}
            else:
                try:
                    d, self.stats["deps"] = deps.scan(self.root, self.client)
                    found += d
                except httpx.HTTPError as e:
                    self.errors.append(f"OSV lookup failed: {e}")
        if not self.include_tests:
            found = [f for f in found if not f.data.get("in_tests")]
        found.sort(key=lambda f: (SEVERITIES.index(f.severity), f.check, f.file, f.line))
        self.stats["by_check"] = dict(Counter(f.check for f in found))
        self.stats["by_severity"] = dict(Counter(f.severity for f in found))
        return found

    # ── output shapes ──────────────────────────────────────────────────────
    def to_scan_result(self, findings: list[CodeFinding]) -> ScanResult:
        result = ScanResult(target=Target(value=str(self.root), target_type="path"),
                            module="codescan")
        for f in findings:
            result.add_finding(
                f.title, f.message, severity=Severity(f.severity),
                data={"check": f.check, "rule_id": f.rule_id, "location": f.location,
                      "snippet": f.snippet, "cwe": f.cwe, "confidence": f.confidence,
                      **{k: v for k, v in f.data.items() if k != "in_tests"}},
                references=f.references,
            )
        result.raw_data["stats"] = self.stats
        result.errors = self.errors
        result.complete()
        return result

    def to_sarif(self, findings: list[CodeFinding]) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        results = []
        for f in findings:
            rid = f.rule_id
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "shortDescription": {"text": f.title if f.check != "deps" else f.title.split(": ", 1)[-1]},
                    "properties": {"security-severity": SECURITY_SEVERITY[f.severity],
                                   "tags": ["security", f.check] + ([f.cwe] if f.cwe else [])},
                    **({"helpUri": f.references[0]} if f.references else {}),
                }
            loc: dict[str, Any] = {"artifactLocation": {"uri": f.file}}
            if f.line:
                loc["region"] = {"startLine": f.line}
            results.append({
                "ruleId": rid, "level": SARIF_LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [{"physicalLocation": loc}],
                "properties": {"confidence": f.confidence, "severity": f.severity},
            })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "secsuite-codescan",
                                          "informationUri": "https://github.com/TheSecuredAnalyst/security-suite",
                                          "rules": list(rules.values())}},
                      "originalUriBaseIds": {"SRCROOT": {"uri": self.root.as_uri() + "/"}},
                      "results": results}],
        }

    def to_json(self, findings: list[CodeFinding]) -> str:
        return json.dumps({"root": str(self.root), "stats": self.stats, "errors": self.errors,
                           "findings": [{**f.__dict__, "location": f.location} for f in findings]},
                          indent=2)


def group_key(f: CodeFinding, depth: int) -> str:
    """The first ``depth`` path parts: with depth 1 in a monorepo, the app name."""
    parts = Path(f.file).parts
    return "/".join(parts[:depth]) if len(parts) > depth else "(root)"
