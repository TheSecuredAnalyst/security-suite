"""Tests for core functionality."""

from core.models import ScanResult, Severity, Target


class TestTarget:
    """Tests for Target model."""

    def test_domain_detection(self):
        t = Target.from_string("example.com")
        assert t.target_type == "domain"
        assert t.value == "example.com"

    def test_url_detection(self):
        t = Target.from_string("https://example.com/path")
        assert t.target_type == "url"
        assert t.value == "https://example.com/path"

    def test_ip_detection(self):
        t = Target.from_string("192.168.1.1")
        assert t.target_type == "ip"
        assert t.value == "192.168.1.1"

    def test_email_detection(self):
        t = Target.from_string("user@example.com")
        assert t.target_type == "email"
        assert t.value == "user@example.com"


class TestScanResult:
    """Tests for ScanResult model."""

    def test_create_result(self):
        target = Target.from_string("example.com")
        result = ScanResult(target=target, module="test")

        assert result.target == target
        assert result.module == "test"
        assert result.success is True
        assert len(result.findings) == 0

    def test_add_finding(self):
        target = Target.from_string("example.com")
        result = ScanResult(target=target, module="test")

        finding = result.add_finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
        )

        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert len(result.findings) == 1
        assert result.findings[0].title == "Test Finding"
        assert result.findings[0].severity == Severity.HIGH

    def test_complete(self):
        target = Target.from_string("example.com")
        result = ScanResult(target=target, module="test")

        assert result.completed_at is None
        result.complete()
        assert result.completed_at is not None

    def test_duration(self):
        target = Target.from_string("example.com")
        result = ScanResult(target=target, module="test")
        result.complete()

        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
