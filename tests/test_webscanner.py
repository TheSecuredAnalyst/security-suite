"""Tests for the web scanner modules (SSL/TLS, XSS, SQLi).

Network I/O is faked: SSLAnalyzer's cert/TLS probes are mocked, and the XSS/SQLi
scanners run against a stub HTTPClient. The detection and finding-generation
logic is what's under test — no real HTTP or TLS handshake occurs.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from core.models import Severity, Target
from modules.webscanner.sqli_scanner import SQLiScanner
from modules.webscanner.ssl_analyzer import SSLAnalyzer
from modules.webscanner.xss_scanner import XSSScanner


def _titles(result):
    return [f.title for f in result.findings]


def _severity_of(result, title):
    return next(f.severity for f in result.findings if f.title == title)


# ── Fake HTTP layer for XSS/SQLi ────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, url, text):
        self.url = url
        self.text = text


class _FakeClient:
    """Async-context-manager stand-in for HTTPClient.

    `handler(url)` returns the response body for that URL.
    """

    def __init__(self, handler):
        self._handler = handler
        self.requested = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        self.requested.append(url)
        return _FakeResponse(url, self._handler(url))


def _patch_client(module_path, handler):
    return patch(module_path, lambda *a, **k: _FakeClient(handler))


# ── SSL analyzer ────────────────────────────────────────────────────────────────

class TestSSLExtractHost:
    def test_plain_host(self):
        assert SSLAnalyzer()._extract_host("example.com") == "example.com"

    def test_https_url(self):
        assert SSLAnalyzer()._extract_host("https://example.com/path") == "example.com"

    def test_http_url_with_port(self):
        assert SSLAnalyzer()._extract_host("http://example.com:8443/x") == "example.com:8443"


class TestSSLRun:
    def _cert(self, **overrides):
        base = {
            "subject": "example.com",
            "issuer": "DigiCert",
            "not_after": (datetime.now() + timedelta(days=365)).isoformat(),
        }
        base.update(overrides)
        return base

    async def _run(self, cert, tls):
        analyzer = SSLAnalyzer()
        with patch.object(analyzer, "_get_certificate", AsyncMock(return_value=cert)), \
             patch.object(analyzer, "_check_tls_versions", AsyncMock(return_value=tls)):
            return await analyzer.run(Target(value="example.com", target_type="domain"))

    async def test_valid_cert_and_modern_tls(self):
        result = await self._run(self._cert(), {"TLSv1.2": True, "TLSv1.3": True})
        assert "Certificate Information" in _titles(result)
        assert "TLS Versions Supported" in _titles(result)
        assert result.success is True

    async def test_expired_certificate_is_critical(self):
        cert = self._cert(not_after=(datetime.now() - timedelta(days=5)).isoformat())
        result = await self._run(cert, {"TLSv1.2": True})
        assert "Certificate Expired" in _titles(result)
        assert _severity_of(result, "Certificate Expired") == Severity.CRITICAL

    async def test_certificate_expiring_soon_is_medium(self):
        cert = self._cert(not_after=(datetime.now() + timedelta(days=10)).isoformat())
        result = await self._run(cert, {"TLSv1.2": True})
        assert "Certificate Expiring Soon" in _titles(result)
        assert _severity_of(result, "Certificate Expiring Soon") == Severity.MEDIUM

    async def test_self_signed_certificate_flagged(self):
        cert = self._cert(subject="acme.local", issuer="acme.local")
        result = await self._run(cert, {"TLSv1.2": True})
        assert "Self-Signed Certificate" in _titles(result)

    async def test_deprecated_tls_versions_flagged(self):
        result = await self._run(self._cert(), {"TLSv1.0": True, "TLSv1.2": True})
        assert "Deprecated TLS Versions Enabled" in _titles(result)

    async def test_sslv3_is_high_severity(self):
        result = await self._run(self._cert(), {"SSLv3": True})
        assert "SSLv3 Enabled" in _titles(result)
        assert _severity_of(result, "SSLv3 Enabled") == Severity.HIGH

    async def test_no_tls_listener_flagged(self):
        result = await self._run(self._cert(), {"TLSv1.2": False, "TLSv1.3": False})
        assert "No TLS/SSL Configured" in _titles(result)

    async def test_no_certificate_still_checks_tls(self):
        result = await self._run(None, {"TLSv1.2": True})
        assert "Certificate Information" not in _titles(result)
        assert "TLS Versions Supported" in _titles(result)


# ── XSS scanner ─────────────────────────────────────────────────────────────────

class TestXSSHelpers:
    def test_inject_payload_sets_parameter(self):
        scanner = XSSScanner(custom_payloads=["X"])
        out = scanner._inject_payload("https://x.com/?q=hi", "q", "<script>")
        assert "q=%3Cscript%3E" in out

    def test_check_reflection_direct(self):
        scanner = XSSScanner(custom_payloads=["X"])
        assert scanner._check_reflection("<b><script>alert(1)</script></b>",
                                         "<script>alert(1)</script>") is True

    def test_check_reflection_pattern(self):
        scanner = XSSScanner(custom_payloads=["X"])
        # Payload not present verbatim, but an onerror=alert pattern is.
        assert scanner._check_reflection("<img onerror=alert(1)>", "different") is True

    def test_check_reflection_negative(self):
        scanner = XSSScanner(custom_payloads=["X"])
        assert scanner._check_reflection("clean page", "<script>") is False

    def test_extract_evidence_returns_context(self):
        scanner = XSSScanner(custom_payloads=["X"])
        html = "prefix " + ("A" * 10) + "<script>" + ("B" * 10) + " suffix"
        assert "<script>" in scanner._extract_evidence(html, "<script>")

    def test_extract_evidence_absent_payload(self):
        assert XSSScanner(custom_payloads=["X"])._extract_evidence("nope", "<script>") == ""

    def test_build_url_from_domain(self):
        scanner = XSSScanner(custom_payloads=["X"])
        assert scanner._build_url(Target(value="x.com", target_type="domain")) == "https://x.com"

    def test_build_url_from_url_target(self):
        scanner = XSSScanner(custom_payloads=["X"])
        t = Target(value="https://x.com/a?b=1", target_type="url")
        assert scanner._build_url(t) == "https://x.com/a?b=1"


class TestXSSRun:
    async def test_reflected_payload_yields_high_finding(self):
        payload = "<script>alert(1)</script>"
        # Any request whose URL carries the (encoded) payload reflects it back.
        def handler(url):
            return payload if "script" in url else "baseline"

        scanner = XSSScanner(custom_payloads=[payload])
        with _patch_client("modules.webscanner.xss_scanner.HTTPClient", handler):
            result = await scanner.run(
                Target(value="https://x.com/?q=test", target_type="url")
            )
        assert "XSS Vulnerabilities Detected" in _titles(result)
        assert _severity_of(result, "XSS Vulnerabilities Detected") == Severity.HIGH

    async def test_clean_response_yields_info_finding(self):
        scanner = XSSScanner(custom_payloads=["<script>alert(1)</script>"])
        with _patch_client("modules.webscanner.xss_scanner.HTTPClient", lambda u: "clean"):
            result = await scanner.run(
                Target(value="https://x.com/?q=test", target_type="url")
            )
        assert "No XSS Vulnerabilities Found" in _titles(result)

    async def test_no_query_params_uses_common_names(self):
        scanner = XSSScanner(custom_payloads=["<script>alert(1)</script>"])
        with _patch_client("modules.webscanner.xss_scanner.HTTPClient", lambda u: "clean"):
            result = await scanner.run(Target(value="https://x.com/", target_type="url"))
        tested = result.raw_data["tested_parameters"]
        assert {"q", "search", "id", "page"} == set(tested)


# ── SQLi scanner ────────────────────────────────────────────────────────────────

class TestSQLiHelpers:
    def test_check_sql_errors_mysql(self):
        scanner = SQLiScanner(custom_payloads=["'"])
        assert scanner._check_sql_errors("You have an SQL syntax error near MySQL server")

    def test_check_sql_errors_postgres(self):
        scanner = SQLiScanner(custom_payloads=["'"])
        assert scanner._check_sql_errors("PostgreSQL query failed: ERROR: bad")

    def test_check_sql_errors_oracle(self):
        scanner = SQLiScanner(custom_payloads=["'"])
        assert scanner._check_sql_errors("ORA-01756 quoted string")

    def test_check_sql_errors_none(self):
        assert SQLiScanner(custom_payloads=["'"])._check_sql_errors("all good") is None

    def test_inject_payload(self):
        scanner = SQLiScanner(custom_payloads=["'"])
        out = scanner._inject_payload("https://x.com/?id=1", "id", "' OR 1=1")
        assert "id=" in out


class TestSQLiRun:
    async def test_error_based_detection_is_critical(self):
        def handler(url):
            # Any injected request triggers a MySQL error page.
            return "baseline" if url.endswith("id=1") else "SQL syntax error near MySQL"

        scanner = SQLiScanner(custom_payloads=["'"])
        with _patch_client("modules.webscanner.sqli_scanner.HTTPClient", handler):
            result = await scanner.run(
                Target(value="https://x.com/?id=1", target_type="url")
            )
        assert "SQL Injection Vulnerabilities Detected" in _titles(result)
        assert _severity_of(
            result, "SQL Injection Vulnerabilities Detected"
        ) == Severity.CRITICAL

    async def test_clean_response_reports_no_sqli(self):
        scanner = SQLiScanner(custom_payloads=["'"])
        with _patch_client("modules.webscanner.sqli_scanner.HTTPClient",
                           lambda u: "same length page"):
            result = await scanner.run(
                Target(value="https://x.com/?id=1", target_type="url")
            )
        assert "No SQL Injection Found" in _titles(result)

    async def test_boolean_based_detection(self):
        baseline = "x" * 100

        def handler(url):
            # true condition (1=1) → long page; false (1=2) → short page.
            if "1%3D1" in url or "1=1" in url:
                return "y" * 400
            if "1%3D2" in url or "1=2" in url:
                return "z" * 100
            return baseline

        scanner = SQLiScanner(custom_payloads=["1 AND 1=1"])
        with _patch_client("modules.webscanner.sqli_scanner.HTTPClient", handler):
            result = await scanner.run(
                Target(value="https://x.com/?id=1", target_type="url")
            )
        vulns = result.raw_data["vulnerabilities"]
        assert any(v["type"] == "Boolean-based SQLi" for v in vulns)
