"""Tests for CVE enrichment and the vulnerability-based rule firing end-to-end."""

from __future__ import annotations

import asyncio

from core.models import ScanResult, Severity, Target
from modules.correlation import CorrelationEngine, build_graph, load_rules
from modules.correlation.enrich import cvss_to_severity, enrich_with_cves, extract_services


class _FakeLookup:
    """Stand-in for CVELookup so tests never touch the network."""

    def __init__(self, cves: list[dict]):
        self.cves = cves
        self.calls: list[tuple[str, str, str]] = []

    async def lookup(self, product: str, version: str = "", service_name: str = "") -> list[dict]:
        self.calls.append((product, version, service_name))
        return self.cves


def _port_scan_result(services: list[dict]) -> ScanResult:
    r = ScanResult(target=Target.from_string("example.com"), module="osint.port_scan")
    r.raw_data["services"] = services
    r.add_finding("Open Ports Discovered", "n open", data={"services": services})
    return r


def test_cvss_to_severity():
    assert cvss_to_severity(9.8) == Severity.CRITICAL
    assert cvss_to_severity(7.5) == Severity.HIGH
    assert cvss_to_severity(5.0) == Severity.MEDIUM
    assert cvss_to_severity(1.0) == Severity.LOW
    assert cvss_to_severity(0) == Severity.INFO


def test_extract_services_only_keeps_products():
    r = _port_scan_result(
        [
            {"port": 445, "product": "Samba", "version": "3.0.0", "service": "smb"},
            {"port": 22, "product": "", "version": "", "service": "ssh"},  # no product -> skipped
        ]
    )
    services = extract_services([r])
    assert len(services) == 1
    assert services[0]["product"] == "Samba"
    assert services[0]["port"] == 445


def test_enrich_returns_none_without_identifiable_services():
    r = _port_scan_result([{"port": 22, "product": "", "service": "ssh"}])
    assert asyncio.run(enrich_with_cves("example.com", [r], lookup=_FakeLookup([]))) is None


def test_enrich_builds_cve_findings_with_port_and_severity():
    r = _port_scan_result([{"port": 445, "product": "Samba", "version": "3.0.0", "service": "smb"}])
    fake = _FakeLookup([{"id": "CVE-2017-0144", "cvss_score": 9.3, "description": "EternalBlue"}])
    cve_result = asyncio.run(enrich_with_cves("example.com", [r], lookup=fake))
    assert cve_result is not None and len(cve_result.findings) == 1
    f = cve_result.findings[0]
    assert f.source == "vulnscan.cve_lookup"
    assert f.severity == Severity.CRITICAL
    assert f.data["port"] == 445 and f.data["cve_id"] == "CVE-2017-0144"
    assert fake.calls == [("Samba", "3.0.0", "smb")]


def test_critical_vuln_rule_fires_end_to_end_with_cve_nested_under_service():
    ports = _port_scan_result(
        [{"port": 445, "protocol": "tcp", "product": "Samba", "version": "3.0.0", "service": "smb"}]
    )
    fake = _FakeLookup([{"id": "CVE-2017-0144", "cvss_score": 9.3, "description": "EternalBlue"}])

    results = [ports]
    cve_result = asyncio.run(enrich_with_cves("example.com", results, lookup=fake))
    assert cve_result is not None
    results.append(cve_result)

    graph = build_graph("example.com", results)
    findings = [f for r in results for f in r.findings]

    engine = CorrelationEngine(load_rules())
    fired = [c for c in engine.evaluate(findings, graph) if c.rule_id == "critical-vuln-on-exposed-host"]

    assert len(fired) == 1
    assert fired[0].anchor == "example.com"
    # CVE nested under the service -> the chain names both the port and the CVE.
    assert "445/tcp" in fired[0].attack_path
    assert "CVE-2017-0144" in fired[0].attack_path


def test_low_severity_cve_does_not_fire_critical_rule():
    ports = _port_scan_result(
        [{"port": 8080, "protocol": "tcp", "product": "Jetty", "version": "9.0", "service": "http"}]
    )
    fake = _FakeLookup([{"id": "CVE-0000-0001", "cvss_score": 3.1, "description": "minor"}])
    results = [ports]
    results.append(asyncio.run(enrich_with_cves("example.com", results, lookup=fake)))

    graph = build_graph("example.com", results)
    findings = [f for r in results for f in r.findings]
    engine = CorrelationEngine(load_rules())
    assert [c for c in engine.evaluate(findings, graph) if c.rule_id == "critical-vuln-on-exposed-host"] == []
