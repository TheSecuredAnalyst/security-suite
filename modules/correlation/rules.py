"""Declarative correlation rules.

A correlation rule says *when a set of findings, seen together, means more than
the sum of its parts* — and it says so in YAML, not in Python, so the community
can contribute rules the way they contribute Nuclei templates. Each rule is a
small list of predicates over findings (and, optionally, the entity a finding is
about); when all of them match, the engine emits a :class:`Correlation` that
carries the evidence and — when the rule is host-scoped — the provenance chain
that led there.

The predicate vocabulary is deliberately small. A rule is meant to be readable
by someone who is not a programmer; a general query language would defeat that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from core.entities import EntityType
from core.logger import get_logger
from core.models import Finding, Severity

logger = get_logger("correlation.rules")

# info < low < medium < high < critical — used for `min_severity` comparisons.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_at_least(actual: Severity, floor: Severity) -> bool:
    """True when ``actual`` is as severe as ``floor`` or worse."""
    return _SEVERITY_RANK[actual] >= _SEVERITY_RANK[floor]


class FindingPredicate(BaseModel):
    """One condition a finding must satisfy to count towards a rule.

    Every field given must hold (logical AND). An omitted field is not checked.
    """

    sources: list[str] = Field(
        default_factory=list,
        description="fnmatch globs against finding.source; matches if ANY glob matches "
        '(e.g. "webscanner.*", "osint.port_scan").',
    )
    title_matches: str | None = Field(
        default=None, description="Regex searched (case-insensitive) against the finding title."
    )
    min_severity: Severity | None = Field(
        default=None, description="Finding severity must be at least this."
    )
    entity_type: EntityType | None = Field(
        default=None,
        description="The entity the finding is about (via finding.entity_id) must be of this type.",
    )

    @field_validator("title_matches")
    @classmethod
    def _valid_regex(cls, v: str | None) -> str | None:
        if v is not None:
            re.compile(v)  # raises on an invalid pattern, surfaced at load time
        return v


class MatchSpec(BaseModel):
    """How a rule's predicates combine."""

    all_of: list[FindingPredicate] = Field(
        ..., min_length=1, description="Every predicate must be satisfied for the rule to fire."
    )
    same_host: bool = Field(
        default=False,
        description="When true, all predicates must be satisfied by findings that trace back to "
        "the SAME anchor entity in the entity graph (requires a graph).",
    )
    anchor: EntityType | list[EntityType] = Field(
        default=EntityType.IP_ADDRESS,
        description="Entity type(s) findings are grouped under when same_host is true. A list "
        "lets one rule anchor on whichever host type a run produced (e.g. [ip_address, domain]).",
    )
    anchor_in_scope: bool = Field(
        default=True,
        description="When same_host is true, only anchors marked in_scope are considered.",
    )

    def anchor_types(self) -> list[EntityType]:
        """The anchor spec normalised to a list, preserving order (first wins)."""
        return self.anchor if isinstance(self.anchor, list) else [self.anchor]


class CorrelationRule(BaseModel):
    """A named pattern that turns co-occurring findings into one correlation."""

    id: str
    name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    match: MatchSpec
    mitre: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    enabled: bool = True


@dataclass
class Correlation:
    """The result of a rule firing: what it means, and the evidence for it."""

    rule_id: str
    name: str
    severity: Severity
    description: str
    evidence: list[Finding]
    anchor: str | None = None
    attack_path: str | None = None
    mitre: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_finding(self) -> Finding:
        """Fold the correlation back into the finding stream (for reports/SARIF)."""
        detail = self.description.strip()
        if self.attack_path:
            detail = f"{detail}\n\nPath: {self.attack_path}".strip()
        elif self.anchor:
            detail = f"{detail}\n\nHost: {self.anchor}".strip()
        return Finding(
            title=self.name,
            description=detail or self.name,
            severity=self.severity,
            source="correlation",
            references=list(self.references),
            data={
                "rule_id": self.rule_id,
                "mitre": self.mitre,
                "anchor": self.anchor,
                "attack_path": self.attack_path,
                "evidence": [f.title for f in self.evidence],
            },
        )


def _coerce_rule_documents(raw: Any) -> list[dict[str, Any]]:
    """A rule file may hold one rule, a list of rules, or {"rules": [...]}."""
    if raw is None:
        return []
    if isinstance(raw, dict):
        if "rules" in raw and isinstance(raw["rules"], list):
            return list(raw["rules"])
        return [raw]
    if isinstance(raw, list):
        return list(raw)
    raise ValueError(f"unexpected top-level YAML type: {type(raw).__name__}")


def load_rule_file(path: Path) -> list[CorrelationRule]:
    """Parse and validate every rule in one YAML file.

    Raises ValueError with the file name on any parse/validation error so the
    caller can report exactly which file is broken.
    """
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"{path.name}: invalid YAML: {exc}") from exc

    rules: list[CorrelationRule] = []
    for doc in _coerce_rule_documents(raw):
        try:
            rules.append(CorrelationRule.model_validate(doc))
        except Exception as exc:  # pydantic ValidationError et al.
            rid = doc.get("id", "<no id>") if isinstance(doc, dict) else "<not a mapping>"
            raise ValueError(f"{path.name}: rule '{rid}' is invalid: {exc}") from exc
    return rules


def bundled_rules_dir() -> Path:
    """The rule pack shipped with the project (repo-root/rules/correlation)."""
    return Path(__file__).resolve().parents[2] / "rules" / "correlation"


def load_rules(*dirs: Path, include_bundled: bool = True) -> list[CorrelationRule]:
    """Load rules from the bundled pack plus any extra directories.

    Later directories win on duplicate rule ids, so a user rule can override a
    bundled one. Invalid files are logged and skipped rather than aborting the
    whole load — one bad user rule should not disable the engine.
    """
    search: list[Path] = []
    if include_bundled:
        search.append(bundled_rules_dir())
    search.extend(dirs)

    by_id: dict[str, CorrelationRule] = {}
    for directory in search:
        if not directory or not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.y*ml")):
            try:
                for rule in load_rule_file(path):
                    by_id[rule.id] = rule
            except ValueError as exc:
                logger.warning("skipping correlation rule file: %s", exc)
    return list(by_id.values())
