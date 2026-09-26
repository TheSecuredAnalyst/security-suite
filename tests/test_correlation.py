"""Tests for the correlation rule engine and the bundled rule pack."""

from __future__ import annotations

import pytest

from core.entities import Entity, EntityGraph, EntityType
from core.models import Finding, Severity
from modules.correlation import (
    CorrelationEngine,
    CorrelationRule,
    bundled_rules_dir,
    load_rule_file,
    load_rules,
)
from modules.correlation.rules import severity_at_least

# ── Rule loading ──────────────────────────────────────────────────────────────


def test_bundled_rules_load_and_validate():
    rules = load_rules()
    ids = {r.id for r in rules}
    assert {"web-app-compromise", "critical-vuln-on-exposed-host"} <= ids
    assert len(rules) >= 5


def test_invalid_rule_file_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: broken\nname: missing match\n")  # no `match` -> invalid
    with pytest.raises(ValueError) as exc:
        load_rule_file(bad)
    assert "broken" in str(exc.value)


def test_bad_user_dir_is_skipped_not_fatal(tmp_path):
    (tmp_path / "bad.yaml").write_text("::: not yaml :::\n- [")
    # Bundled rules still load; the broken user file is skipped with a warning.
    rules = load_rules(tmp_path)
    assert len(rules) >= 5


def test_user_rule_overrides_bundled_by_id(tmp_path):
    override = tmp_path / "override.yaml"
    override.write_text(
        "id: web-app-compromise\n"
        "name: Overridden\n"
        "severity: low\n"
        "match:\n"
        "  all_of:\n"
        "    - sources: ['osint.*']\n"
    )
    rules = {r.id: r for r in load_rules(tmp_path)}
    assert rules["web-app-compromise"].name == "Overridden"


# ── Flat evaluation ───────────────────────────────────────────────────────────


def _f(title: str, source: str, severity: Severity = Severity.INFO, entity_id: str | None = None):
    return Finding(
        title=title, description=title, severity=severity, source=source, entity_id=entity_id
    )


def test_flat_rule_fires_when_all_predicates_present():
    engine = CorrelationEngine([_web_rule()])
    findings = [
        _f("DNS records", "osint.dns"),
        _f("Directories", "webscanner.dirbrute"),
        _f("Reflected XSS", "webscanner.xss", Severity.HIGH),
    ]
    result = engine.evaluate(findings)
    assert len(result) == 1
    assert result[0].rule_id == "web-app-compromise"
    assert len(result[0].evidence) == 3


def test_flat_rule_does_not_fire_with_a_missing_stage():
    engine = CorrelationEngine([_web_rule()])
    findings = [_f("DNS records", "osint.dns"), _f("Directories", "webscanner.dirbrute")]
    assert engine.evaluate(findings) == []


# ── Host-scoped evaluation (provenance) ───────────────────────────────────────


def _graph_with_host():
    graph = EntityGraph()
    host = graph.add(Entity.root("10.0.0.5", EntityType.IP_ADDRESS, "scanner"))
    svc = graph.add(host.child(EntityType.SERVICE, "445/tcp smb", "scanner"))
    vuln = graph.add(svc.child(EntityType.VULNERABILITY, "CVE-2017-0144", "cve_lookup"))
    return graph, host, svc, vuln


def test_host_scoped_rule_fires_with_provenance():
    graph, host, svc, vuln = _graph_with_host()
    findings = [
        _f("SMB service", "osint.port_scan", entity_id=svc.id),
        _f("EternalBlue", "vulnscan.cve", Severity.CRITICAL, entity_id=vuln.id),
    ]
    engine = CorrelationEngine(load_rules())
    results = [c for c in engine.evaluate(findings, graph) if c.rule_id == "critical-vuln-on-exposed-host"]
    assert len(results) == 1
    assert results[0].anchor == "10.0.0.5"
    assert "CVE-2017-0144" in results[0].attack_path


def test_host_scoped_rule_needs_graph():
    _, _, svc, vuln = _graph_with_host()
    findings = [
        _f("SMB service", "osint.port_scan", entity_id=svc.id),
        _f("EternalBlue", "vulnscan.cve", Severity.CRITICAL, entity_id=vuln.id),
    ]
    engine = CorrelationEngine(load_rules())
    # No graph -> host-scoped rules cannot resolve anchors and stay silent.
    assert [c for c in engine.evaluate(findings) if c.rule_id == "critical-vuln-on-exposed-host"] == []


def test_out_of_scope_anchor_is_excluded():
    graph = EntityGraph()
    host = graph.add(Entity.root("8.8.8.8", EntityType.IP_ADDRESS, "scanner", in_scope=False))
    svc = graph.add(host.child(EntityType.SERVICE, "53/udp dns", "scanner"))
    vuln = graph.add(svc.child(EntityType.VULNERABILITY, "CVE-9999-0001", "cve_lookup"))
    findings = [
        _f("DNS service", "osint.port_scan", entity_id=svc.id),
        _f("Some CVE", "vulnscan.cve", Severity.CRITICAL, entity_id=vuln.id),
    ]
    engine = CorrelationEngine(load_rules())
    assert [c for c in engine.evaluate(findings, graph) if c.rule_id == "critical-vuln-on-exposed-host"] == []


# ── Helpers / misc ────────────────────────────────────────────────────────────


def test_severity_ordering():
    assert severity_at_least(Severity.CRITICAL, Severity.HIGH)
    assert severity_at_least(Severity.HIGH, Severity.HIGH)
    assert not severity_at_least(Severity.LOW, Severity.HIGH)


def test_correlation_to_finding_carries_evidence_and_path():
    graph, host, svc, vuln = _graph_with_host()
    findings = [
        _f("SMB service", "osint.port_scan", entity_id=svc.id),
        _f("EternalBlue", "vulnscan.cve", Severity.CRITICAL, entity_id=vuln.id),
    ]
    engine = CorrelationEngine(load_rules())
    corr = [c for c in engine.evaluate(findings, graph) if c.rule_id == "critical-vuln-on-exposed-host"][0]
    finding = corr.to_finding()
    assert finding.source == "correlation"
    assert finding.severity == Severity.CRITICAL
    assert finding.data["rule_id"] == "critical-vuln-on-exposed-host"
    assert "10.0.0.5" in finding.description


def _web_rule() -> CorrelationRule:
    return CorrelationRule.model_validate(
        {
            "id": "web-app-compromise",
            "name": "Web application compromise path",
            "severity": "high",
            "match": {
                "all_of": [
                    {"sources": ["osint.*"]},
                    {"sources": ["webscanner.dirbrute", "webscanner.crawler"]},
                    {"sources": ["webscanner.xss", "webscanner.sqli"]},
                ]
            },
        }
    )


def test_bundled_dir_exists():
    assert bundled_rules_dir().is_dir()
