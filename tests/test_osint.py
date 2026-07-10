"""Tests for OSINT modules."""

from unittest.mock import MagicMock, patch

import pytest

from core.models import Target


class TestDNSEnumerator:
    """Tests for DNS enumeration."""

    @pytest.mark.asyncio
    async def test_dns_enum_valid_domain(self):
        from modules.osint import DNSEnumerator

        # Mock the DNS resolver
        with patch("modules.osint.dns_enum.dns.asyncresolver.Resolver") as mock_resolver:
            mock_instance = MagicMock()
            mock_resolver.return_value = mock_instance

            # Mock resolve to return some records
            async def mock_resolve(domain, record_type):
                if record_type == "A":
                    mock_result = MagicMock()
                    mock_result.__iter__ = lambda s: iter(["93.184.216.34"])
                    return mock_result
                raise Exception("No records")

            mock_instance.resolve = mock_resolve

            scanner = DNSEnumerator()
            target = Target.from_string("example.com")
            result = await scanner.run(target)

            assert result.success is True
            assert result.module == "osint.dns_enum"

    def test_extract_domain_from_url(self):
        from modules.osint import DNSEnumerator

        scanner = DNSEnumerator()
        assert scanner._extract_domain("https://example.com/path") == "example.com"
        assert scanner._extract_domain("example.com") == "example.com"


class TestSubdomainScanner:
    """Tests for subdomain discovery."""

    def test_common_subdomains_exist(self):
        from modules.osint import SubdomainScanner

        scanner = SubdomainScanner()
        assert len(scanner.COMMON_SUBDOMAINS) > 0
        assert "www" in scanner.COMMON_SUBDOMAINS
        assert "api" in scanner.COMMON_SUBDOMAINS
        assert "admin" in scanner.COMMON_SUBDOMAINS


class TestHeaderAnalyzer:
    """Tests for header analysis."""

    def test_security_headers_defined(self):
        from modules.osint import HeaderAnalyzer

        scanner = HeaderAnalyzer()
        assert "strict-transport-security" in scanner.SECURITY_HEADERS
        assert "content-security-policy" in scanner.SECURITY_HEADERS
        assert "x-frame-options" in scanner.SECURITY_HEADERS


class TestPortScanner:
    """Tests for port scanner."""

    def test_common_ports_defined(self):
        from modules.osint import PortScanner

        scanner = PortScanner()
        assert 22 in scanner.COMMON_PORTS  # SSH
        assert 80 in scanner.COMMON_PORTS  # HTTP
        assert 443 in scanner.COMMON_PORTS  # HTTPS
        assert 3306 in scanner.COMMON_PORTS  # MySQL
