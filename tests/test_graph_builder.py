"""Tests for the scan-results -> entity graph builder and end-to-end firing."""

from __future__ import annotations

from core.entities import EntityType
from core.models import ScanResult, Severity, Target
from modules.correlation import CorrelationEngine, build_graph, load_rules


def _result(module: str) -> ScanResult:
    return ScanResult(target=Target.from_string("example.com"), module=module)


def test_build_graph_sets_entity_ids_and_anchors_under_one_host():
    ports = _result("osint.port_scan")
    ports.add_finding("Open 445", "smb", data={"port": 445, "protocol": "tcp", "name": "smb"})
    other = _result("osint.dns")
    other.add_finding("A record", "1.2.3.4")

    graph = build_graph("example.com", [ports, other])

    # Every finding got an entity id.
    assert all(f.entity_id for r in [ports, other] for f in r.findings)
    # One domain host anchor for the target.
    hosts = graph.by_type(EntityType.DOMAIN)
    assert [h.value for h in hosts] == ["example.com"]
    # The port finding produced a service under that host.
    services = graph.by_type(EntityType.SERVICE)
    assert len(services) == 1
    assert "445/tcp" in services[0].value


def test_host_type_follows_target():
    assert build_graph("10.0.0.5", []).by_type(EntityType.IP_ADDRESS)[0].value == "10.0.0.5"
    assert build_graph("https://x.example.com/p", []).by_type(EntityType.HOSTNAME)[0].value == "x.example.com"
    assert build_graph("example.com", []).by_type(EntityType.DOMAIN)[0].value == "example.com"


def test_services_list_expands_to_multiple_nodes():
    ports = _result("osint.port_scan")
    ports.add_finding(
        "Open ports",
        "summary",
        data={"services": [
            {"port": 80, "protocol": "tcp", "name": "http"},
            {"port": 443, "protocol": "tcp", "name": "https"},
        ]},
    )
    graph = build_graph("example.com", [ports])
    labels = sorted(s.value for s in graph.by_type(EntityType.SERVICE))
    assert any("80/tcp" in v for v in labels)
    assert any("443/tcp" in v for v in labels)


def test_injection_rule_fires_end_to_end_from_scan_results():
    ports = _result("osint.port_scan")
    ports.add_finding("Open 80", "http", data={"port": 80, "protocol": "tcp", "name": "http"})
    sqli = _result("webscanner.sqli")
    sqli.add_finding(
        "SQL injection", "sqli in id param", severity=Severity.HIGH,
        data={"url": "http://example.com/item?id=1"},
    )

    results = [ports, sqli]
    graph = build_graph("example.com", results)
    findings = [f for r in results for f in r.findings]

    engine = CorrelationEngine(load_rules())
    fired = [c for c in engine.evaluate(findings, graph) if c.rule_id == "injection-on-live-host"]

    assert len(fired) == 1
    assert fired[0].anchor == "example.com"
    assert "example.com" in fired[0].attack_path


def test_low_severity_injection_does_not_fire():
    ports = _result("osint.port_scan")
    ports.add_finding("Open 80", "http", data={"port": 80, "protocol": "tcp", "name": "http"})
    sqli = _result("webscanner.sqli")
    sqli.add_finding("Possible SQLi", "weak signal", severity=Severity.LOW, data={"url": "http://example.com/"})

    results = [ports, sqli]
    graph = build_graph("example.com", results)
    findings = [f for r in results for f in r.findings]

    engine = CorrelationEngine(load_rules())
    # min_severity: high on the injection predicate -> a LOW finding must not fire it.
    assert [c for c in engine.evaluate(findings, graph) if c.rule_id == "injection-on-live-host"] == []
