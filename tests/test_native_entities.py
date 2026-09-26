"""Native entity emission: PortScanner emits entities, build_graph honors them."""

from __future__ import annotations

from core.entities import EntityType
from core.models import ScanResult, Severity, Target
from modules.correlation import CorrelationEngine, build_graph, load_rules
from modules.osint import PortScanner

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba smbd" version="3.0.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _parsed_result(tmp_path) -> ScanResult:
    xml = tmp_path / "scan.xml"
    xml.write_text(_NMAP_XML)
    result = ScanResult(target=Target.from_string("example.com"), module="osint.port_scan")
    PortScanner()._parse_nmap_xml(str(xml), result)
    return result


def test_port_scanner_emits_host_and_service_entities(tmp_path):
    result = _parsed_result(tmp_path)

    hosts = [e for e in result.entities if e.entity_type == EntityType.HOSTNAME]
    services = [e for e in result.entities if e.entity_type == EntityType.SERVICE]
    assert len(hosts) == 1 and hosts[0].value == "example.com"
    assert len(services) == 2
    assert any("445/tcp" in s.value for s in services)

    # The summary finding is linked to a service the scanner emitted.
    open_ports = next(f for f in result.findings if f.title == "Open Ports Discovered")
    assert open_ports.entity_id in {s.id for s in services}


def test_build_graph_honors_emitted_entities_without_reclassifying(tmp_path):
    result = _parsed_result(tmp_path)
    open_ports = next(f for f in result.findings if f.title == "Open Ports Discovered")
    linked_before = open_ports.entity_id

    graph = build_graph("example.com", [result])

    # The scanner's link is respected, and the entity is the emitted service.
    assert open_ports.entity_id == linked_before
    entity = graph.get(open_ports.entity_id)
    assert entity is not None and entity.entity_type == EntityType.SERVICE
    # The emitted host is the single root anchor.
    roots = graph.roots()
    assert len(roots) == 1 and roots[0].value == "example.com"


def test_native_emission_feeds_host_scoped_rule_end_to_end(tmp_path):
    ports = _parsed_result(tmp_path)  # emits host + services natively
    sqli = ScanResult(target=Target.from_string("example.com"), module="webscanner.sqli")
    sqli.add_finding(
        "SQL injection", "confirmed", severity=Severity.HIGH,
        data={"url": "http://example.com/x?id=1"},
    )  # no native entities -> attributed heuristically under the emitted host

    results = [ports, sqli]
    graph = build_graph("example.com", results)
    findings = [f for r in results for f in r.findings]

    engine = CorrelationEngine(load_rules())
    fired = [c for c in engine.evaluate(findings, graph) if c.rule_id == "injection-on-live-host"]
    assert len(fired) == 1
    assert fired[0].anchor == "example.com"
    assert "445/tcp" in fired[0].attack_path


def test_results_without_entities_still_work(tmp_path):
    # Backward compatibility: a result with no native entities is handled by the
    # heuristic path exactly as before.
    r = ScanResult(target=Target.from_string("example.com"), module="osint.port_scan")
    r.raw_data["services"] = [{"port": 22, "product": "OpenSSH", "version": "8.0"}]
    r.add_finding("Open Ports Discovered", "1 open", data={"services": r.raw_data["services"]})
    assert r.entities == []

    graph = build_graph("example.com", [r])
    finding = r.findings[0]
    assert finding.entity_id and graph.get(finding.entity_id).entity_type == EntityType.SERVICE
