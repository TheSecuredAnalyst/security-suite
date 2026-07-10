"""Tests for the compliance engine (OWASP Top 10 / CIS Controls mapping and scoring)."""

import pytest

from core.models import ScanResult, Severity, Target
from modules.compliance.checker import ComplianceChecker
from modules.compliance.standards import ComplianceStatus


def _scan_with(source: str, severity: Severity) -> ScanResult:
    # A finding's source is inherited from the ScanResult's module name.
    result = ScanResult(target=Target.from_string("example.com"), module=source)
    result.add_finding(title="issue", description="d", severity=severity)
    return result


@pytest.fixture
def checker():
    return ComplianceChecker()


def test_list_and_get_standards(checker):
    ids = {s.id for s in checker.list_standards()}
    assert checker.get_standard("owasp-top-10") is not None
    assert checker.get_standard("nonexistent") is None
    assert ids  # at least one standard registered


async def test_unknown_standard_raises(checker):
    with pytest.raises(ValueError, match="Unknown standard"):
        await checker.check_compliance(Target.from_string("example.com"), "bogus")


async def test_high_severity_injection_fails_control(checker):
    scan = _scan_with("webscanner.sqli", Severity.HIGH)
    report = await checker.check_compliance(
        Target.from_string("example.com"), "owasp-top-10", [scan]
    )
    statuses = {r.status for r in report.results}
    assert ComplianceStatus.FAIL in statuses
    assert report.failed_controls >= 1


async def test_medium_severity_warns(checker):
    scan = _scan_with("webscanner.sqli", Severity.MEDIUM)
    report = await checker.check_compliance(
        Target.from_string("example.com"), "owasp-top-10", [scan]
    )
    assert any(r.status == ComplianceStatus.WARNING for r in report.results)


async def test_no_scan_data_is_not_applicable(checker):
    report = await checker.check_compliance(
        Target.from_string("example.com"), "owasp-top-10", None
    )
    assert all(r.status == ComplianceStatus.NOT_APPLICABLE for r in report.results)
    # Score defaults to 100 when nothing is applicable.
    assert report.compliance_score == 100.0


async def test_compliance_score_reflects_failures(checker):
    scan = _scan_with("webscanner.sqli", Severity.CRITICAL)
    report = await checker.check_compliance(
        Target.from_string("example.com"), "owasp-top-10", [scan]
    )
    # With at least one applicable-and-failing control, score is below 100.
    assert report.compliance_score < 100.0
    assert 0.0 <= report.compliance_score <= 100.0


async def test_generate_scan_result_summarizes(checker):
    scan = _scan_with("webscanner.sqli", Severity.HIGH)
    result = await checker.generate_scan_result(
        Target.from_string("example.com"), "owasp-top-10", [scan]
    )
    assert result.module == "compliance.owasp-top-10"
    assert result.findings  # summary finding + failed controls
    assert "compliance_report" in result.raw_data


def test_report_to_dict_shape(checker):
    from modules.compliance.checker import ComplianceReport

    report = ComplianceReport(target="example.com", standard=checker.get_standard("owasp-top-10"))
    d = report.to_dict()
    assert set(d) >= {"target", "standard", "summary", "results", "generated_at"}
    assert d["summary"]["compliance_score"].endswith("%")
