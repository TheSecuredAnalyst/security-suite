"""Tests for the SIEM event model, CEF/LEEF formatters, and batch export."""

from datetime import datetime, timezone

from core.models import Finding, ScanResult, Severity, Target
from modules.siem.base import EventType, SIEMEvent, SIEMExporter


def _event(**kw) -> SIEMEvent:
    base = {
        "event_type": EventType.FINDING_DETECTED,
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "severity": "high",
        "message": "SQL injection",
        "target": "10.0.0.5",
        "module": "webscanner.sqli",
    }
    base.update(kw)
    return SIEMEvent(**base)


def test_to_dict_serializes_enum_and_timestamp():
    d = _event().to_dict()
    assert d["event_type"] == "finding_detected"
    assert d["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert d["severity"] == "high"


def test_cef_format_structure_and_severity():
    cef = _event().to_cef()
    assert cef.startswith("CEF:0|SecuritySuite|SecSuite|1.0|")
    # high maps to CEF severity 8
    assert "|8|" in cef
    assert "src=10.0.0.5" in cef


def test_cef_unknown_severity_defaults_to_one():
    cef = _event(severity="bogus").to_cef()
    assert "|1|" in cef


def test_leef_format_structure():
    leef = _event().to_leef()
    assert leef.startswith("LEEF:1.0|SecuritySuite|SecSuite|1.0|")
    assert "src=10.0.0.5" in leef
    assert "severity=high" in leef


def test_from_finding_maps_fields():
    finding = Finding(
        title="Weak TLS",
        description="TLS 1.0 enabled",
        severity=Severity.MEDIUM,
        source="webscanner.ssl",
        references=["https://example.com/a", "https://example.com/b"],
    )
    ev = SIEMEvent.from_finding(finding, target="host.example.com")
    assert ev.event_type == EventType.FINDING_DETECTED
    assert ev.severity == "medium"
    assert ev.message == "Weak TLS"
    assert ev.target == "host.example.com"
    assert ev.tags == ["https://example.com/a", "https://example.com/b"]


def test_from_scan_result_emits_completed_plus_findings():
    result = ScanResult(target=Target.from_string("example.com"), module="webscanner")
    result.add_finding(title="A", description="d", severity=Severity.HIGH)
    result.add_finding(title="B", description="d", severity=Severity.LOW)
    events = SIEMEvent.from_scan_result(result)
    # one SCAN_COMPLETED + two findings
    assert len(events) == 3
    assert events[0].event_type == EventType.SCAN_COMPLETED
    assert sum(e.event_type == EventType.FINDING_DETECTED for e in events) == 2


class _FakeExporter(SIEMExporter):
    """Exporter that succeeds unless the message says 'fail', and can raise."""

    async def export(self, event: SIEMEvent) -> bool:
        if event.message == "raise":
            raise RuntimeError("boom")
        return event.message != "fail"

    async def test_connection(self) -> bool:
        return True

    def get_config_info(self) -> dict:
        return {}


async def test_export_batch_counts_success_and_failure():
    exporter = _FakeExporter()
    events = [_event(message="ok"), _event(message="fail"), _event(message="raise")]
    success, failed = await exporter.export_batch(events)
    assert success == 1
    assert failed == 2


async def test_export_scan_result_delegates_to_batch():
    result = ScanResult(target=Target.from_string("example.com"), module="webscanner")
    result.add_finding(title="ok", description="d", severity=Severity.HIGH)
    success, failed = await _FakeExporter().export_scan_result(result)
    # SCAN_COMPLETED message is "Scan completed: ..." so it is not "fail" -> success.
    assert success == 2
    assert failed == 0
