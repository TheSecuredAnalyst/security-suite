"""Evaluate correlation rules over findings and the entity graph.

Two evaluation modes, chosen per rule:

* **flat** (``same_host: false``) — a rule fires once if, across all findings,
  every predicate is matched by at least one finding.
* **host-scoped** (``same_host: true``) — findings are grouped by the anchor
  entity they trace back to in the :class:`~core.entities.EntityGraph`, and the
  rule fires once per anchor whose findings satisfy every predicate. The
  resulting correlation carries that anchor's provenance chain.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from core.entities import Entity, EntityGraph, EntityType
from core.logger import get_logger
from core.models import Finding

from .rules import Correlation, CorrelationRule, FindingPredicate, load_rules, severity_at_least

logger = get_logger("correlation.engine")


def _predicate_matches(pred: FindingPredicate, finding: Finding, graph: EntityGraph | None) -> bool:
    """True when a single finding satisfies every set field of a predicate."""
    if pred.sources and not any(fnmatch.fnmatch(finding.source, g) for g in pred.sources):
        return False
    if pred.title_matches and not re.search(pred.title_matches, finding.title, re.IGNORECASE):
        return False
    if pred.min_severity and not severity_at_least(finding.severity, pred.min_severity):
        return False
    if pred.entity_type is not None:
        entity = graph.get(finding.entity_id) if (graph and finding.entity_id) else None
        if entity is None or entity.entity_type != pred.entity_type:
            return False
    return True


class CorrelationEngine:
    """Runs a set of correlation rules; the rule library is the moat, not this."""

    def __init__(self, rules: list[CorrelationRule]):
        self.rules = [r for r in rules if r.enabled]

    @classmethod
    def from_dirs(cls, *dirs: Path, include_bundled: bool = True) -> CorrelationEngine:
        return cls(load_rules(*dirs, include_bundled=include_bundled))

    @staticmethod
    def _dedup(findings: list[Finding]) -> list[Finding]:
        """Preserve order, drop repeats (findings are unhashable, key on id)."""
        seen: set[int] = set()
        unique: list[Finding] = []
        for finding in findings:
            if id(finding) not in seen:
                seen.add(id(finding))
                unique.append(finding)
        return unique

    # ── Evaluation ──────────────────────────────────────────────────────────────

    def evaluate(
        self, findings: list[Finding], graph: EntityGraph | None = None
    ) -> list[Correlation]:
        """Return every correlation that fires over the given findings."""
        correlations: list[Correlation] = []
        for rule in self.rules:
            if rule.match.same_host:
                correlations.extend(self._eval_host_scoped(rule, findings, graph))
            else:
                correlations.extend(self._eval_flat(rule, findings, graph))
        return correlations

    def _eval_flat(
        self, rule: CorrelationRule, findings: list[Finding], graph: EntityGraph | None
    ) -> list[Correlation]:
        evidence: list[Finding] = []
        for pred in rule.match.all_of:
            matched = [f for f in findings if _predicate_matches(pred, f, graph)]
            if not matched:
                return []  # a predicate went unmatched — the rule cannot fire
            evidence.extend(matched)

        return [self._build(rule, self._dedup(evidence))]

    def _eval_host_scoped(
        self, rule: CorrelationRule, findings: list[Finding], graph: EntityGraph | None
    ) -> list[Correlation]:
        if graph is None:
            return []  # host-scoped rules are meaningless without provenance

        anchor_type = rule.match.anchor
        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            anchor = self._anchor_of(finding, graph, anchor_type)
            if anchor is None:
                continue
            if rule.match.anchor_in_scope and not anchor.in_scope:
                continue
            grouped.setdefault(anchor.id, []).append(finding)

        out: list[Correlation] = []
        for anchor_id, host_findings in grouped.items():
            evidence: list[Finding] = []
            satisfied = True
            for pred in rule.match.all_of:
                matched = [f for f in host_findings if _predicate_matches(pred, f, graph)]
                if not matched:
                    satisfied = False
                    break
                evidence.extend(matched)
            if not satisfied:
                continue
            anchor = graph.get(anchor_id)
            unique = self._dedup(evidence)
            # Render the chain down to the deepest piece of evidence, not just the
            # anchor, so the path reads host -> service -> CVE rather than "host".
            path_entity = self._deepest_evidence_entity(unique, graph) or anchor
            out.append(
                self._build(
                    rule,
                    unique,
                    anchor=anchor.value if anchor else None,
                    attack_path=graph.attack_path(path_entity) if path_entity else None,
                )
            )
        return out

    @staticmethod
    def _deepest_evidence_entity(
        evidence: list[Finding], graph: EntityGraph
    ) -> Entity | None:
        """The evidence entity furthest from its root — the tip of the chain."""
        deepest = None
        deepest_len = -1
        for finding in evidence:
            entity = graph.get(finding.entity_id) if finding.entity_id else None
            if entity is None:
                continue
            depth = len(graph.ancestry(entity))
            if depth > deepest_len:
                deepest_len = depth
                deepest = entity
        return deepest

    @staticmethod
    def _anchor_of(
        finding: Finding, graph: EntityGraph, anchor_type: EntityType
    ) -> Entity | None:
        """The anchor-typed ancestor of the entity a finding is about, if any."""
        if not finding.entity_id:
            return None
        entity = graph.get(finding.entity_id)
        if entity is None:
            return None
        for ancestor in graph.ancestry(entity):
            if ancestor.entity_type == anchor_type:
                return ancestor
        return None

    @staticmethod
    def _build(
        rule: CorrelationRule,
        evidence: list[Finding],
        *,
        anchor: str | None = None,
        attack_path: str | None = None,
    ) -> Correlation:
        return Correlation(
            rule_id=rule.id,
            name=rule.name,
            severity=rule.severity,
            description=rule.description,
            evidence=evidence,
            anchor=anchor,
            attack_path=attack_path,
            mitre=list(rule.mitre),
            references=list(rule.references),
        )
