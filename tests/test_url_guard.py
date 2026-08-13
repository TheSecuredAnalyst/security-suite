"""Tests for the outbound URL (SSRF) guard."""

import socket

import pytest

from core.url_guard import BlockedTargetError, safe_join, validate_outbound_url


def _fake_resolver(address: str):
    """Return a getaddrinfo stub that always resolves to `address`."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET

    def resolver(host, port, *args, **kwargs):
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))]

    return resolver


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("93.184.216.34"))


class TestAllowedTargets:
    def test_public_https_url_passes_through(self, public_dns):
        url = "https://api.example.com/openapi.json"
        assert validate_outbound_url(url) == url

    def test_query_string_and_port_are_preserved(self, public_dns):
        url = "https://api.example.com:8443/spec?format=yaml"
        assert validate_outbound_url(url) == url

    def test_fragment_is_dropped(self, public_dns):
        assert (
            validate_outbound_url("https://api.example.com/spec#section")
            == "https://api.example.com/spec"
        )

    def test_private_address_allowed_when_opted_in(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("127.0.0.1"))
        url = "http://localhost:8000/openapi.json"
        assert validate_outbound_url(url, allow_private=True) == url


class TestBlockedTargets:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",        # loopback
            "10.0.0.5",         # RFC1918
            "192.168.1.10",     # RFC1918
            "172.16.4.4",       # RFC1918
            "169.254.169.254",  # cloud metadata
            "0.0.0.0",          # unspecified
            "::1",              # IPv6 loopback
            "fd00::1",          # IPv6 unique-local
            "::ffff:127.0.0.1",  # IPv4-mapped loopback
        ],
    )
    def test_non_public_addresses_are_blocked(self, monkeypatch, address):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver(address))
        with pytest.raises(BlockedTargetError):
            validate_outbound_url("http://spec.attacker.test/openapi.json")

    def test_any_resolved_address_being_private_blocks_the_url(self, monkeypatch):
        def resolver(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        with pytest.raises(BlockedTargetError, match="127.0.0.1"):
            validate_outbound_url("http://spec.attacker.test/openapi.json")

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://example.com:6379/_FLUSHALL",
            "ftp://example.com/spec.json",
            "//example.com/spec.json",
        ],
    )
    def test_non_http_schemes_are_blocked(self, url):
        with pytest.raises(BlockedTargetError, match="scheme"):
            validate_outbound_url(url)

    def test_credentials_in_url_are_rejected(self, public_dns):
        with pytest.raises(BlockedTargetError, match="credentials"):
            validate_outbound_url("https://user:pass@api.example.com/spec")

    def test_missing_host_is_rejected(self):
        with pytest.raises(BlockedTargetError, match="no host"):
            validate_outbound_url("http:///openapi.json")

    def test_malformed_port_is_rejected(self):
        with pytest.raises(BlockedTargetError, match="malformed"):
            validate_outbound_url("https://api.example.com:notaport/spec")

    def test_unresolvable_host_is_rejected(self, monkeypatch):
        def resolver(*args, **kwargs):
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        with pytest.raises(BlockedTargetError, match="DNS resolution failed"):
            validate_outbound_url("https://nope.invalid/spec")


class TestSafeJoin:
    def test_relative_path_joins_normally(self):
        assert (
            safe_join("https://api.example.com/", "/users/{id}")
            == "https://api.example.com/users/{id}"
        )

    def test_query_is_preserved(self):
        assert (
            safe_join("https://api.example.com/", "/users?page=2")
            == "https://api.example.com/users?page=2"
        )

    @pytest.mark.parametrize(
        "path",
        [
            "http://169.254.169.254/latest/meta-data/",
            "https://evil.example/steal",
            "//evil.example/steal",
        ],
    )
    def test_absolute_paths_cannot_change_origin(self, path):
        joined = safe_join("https://api.example.com/v1/", path)
        assert joined.startswith("https://api.example.com/")


class TestModuleIntegration:
    """Every apisec entry point that sends requests must run the guard."""

    @pytest.fixture
    def private_api(self):
        from modules.apisec.openapi_parser import APIEndpoint, ParsedAPI

        return ParsedAPI(
            title="Internal",
            version="1.0.0",
            base_url="http://169.254.169.254/latest/",
            endpoints=[
                APIEndpoint(
                    path="/login",
                    method="POST",
                    security=[{"bearerAuth": []}],
                    tags=["admin"],
                )
            ],
            security_schemes={},
            servers=["http://169.254.169.254/latest/"],
        )

    @pytest.fixture(autouse=True)
    def _metadata_dns(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver("169.254.169.254"))

    @pytest.mark.asyncio
    async def test_parse_url_refuses_metadata_endpoint(self):
        from modules.apisec.openapi_parser import OpenAPIParser

        with pytest.raises(BlockedTargetError):
            await OpenAPIParser().parse_url("http://169.254.169.254/latest/meta-data/")

    @pytest.mark.asyncio
    async def test_endpoint_tester_refuses_private_base_url(self, private_api):
        from modules.apisec.endpoint_tester import APIEndpointTester

        with pytest.raises(BlockedTargetError):
            await APIEndpointTester().test_api(private_api)

    @pytest.mark.asyncio
    async def test_fuzzer_refuses_private_base_url(self, private_api):
        from modules.apisec.fuzzer import APIFuzzer

        with pytest.raises(BlockedTargetError):
            await APIFuzzer().fuzz_api(private_api)

    @pytest.mark.asyncio
    async def test_auth_tester_refuses_private_base_url(self, private_api):
        from modules.apisec.auth_tester import APIAuthTester

        with pytest.raises(BlockedTargetError):
            await APIAuthTester().test_api_auth(private_api)
