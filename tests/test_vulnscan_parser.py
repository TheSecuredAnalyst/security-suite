"""nmap XML parsing: a service name nmap only guessed from the port number
(method="table") must be marked, so it never drives CVE lookups."""

from modules.vulnscan.scanner import _parse_nmap_xml

XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/>
  <service name="http" product="nginx" version="1.24.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="5000"><state state="open"/>
  <service name="upnp" method="table" conf="3"/></port>
<port protocol="tcp" portid="9999"><state state="open"/></port>
<port protocol="tcp" portid="22"><state state="closed"/>
  <service name="ssh" method="probed" conf="10"/></port>
</ports></host></nmaprun>"""


def _parse(tmp_path):
    f = tmp_path / "scan.xml"
    f.write_text(XML)
    return {s["port"]: s for s in _parse_nmap_xml(str(f), "10.0.0.1")}


def test_probed_service_is_not_guessed(tmp_path):
    s = _parse(tmp_path)[443]
    assert s["product"] == "nginx" and s["name_guessed"] is False


def test_port_table_service_is_guessed(tmp_path):
    s = _parse(tmp_path)[5000]
    assert s["name"] == "upnp" and s["product"] == "" and s["name_guessed"] is True


def test_port_without_service_element_is_guessed(tmp_path):
    assert _parse(tmp_path)[9999]["name_guessed"] is True


def test_closed_ports_are_skipped(tmp_path):
    assert 22 not in _parse(tmp_path)
