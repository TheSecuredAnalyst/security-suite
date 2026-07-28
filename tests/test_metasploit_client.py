"""Tests for the Metasploit RPC client.

The RPC transport (_call) is mocked throughout — no test contacts a real
msfrpcd. The focus is response decoding and the higher-level method logic.
"""

from unittest.mock import AsyncMock

import pytest

from core.models import Target
from modules.exploit.metasploit import MetasploitClient, MSFSession


@pytest.fixture
def client():
    return MetasploitClient(host="127.0.0.1", port=55553, username="msf", password="pw")


class TestBaseURL:
    def test_https_when_ssl(self):
        c = MetasploitClient(host="h", port=1, ssl=True)
        assert c.base_url == "https://h:1/api"

    def test_http_when_not_ssl(self):
        c = MetasploitClient(host="h", port=1, ssl=False)
        assert c.base_url == "http://h:1/api"


class TestDecodeResult:
    def test_byte_keys_and_values_become_strings(self):
        raw = {b"result": b"success", b"token": b"abc"}
        out = MetasploitClient._decode_result(raw)
        assert out == {"result": "success", "token": "abc"}

    def test_string_keys_are_preserved(self):
        assert MetasploitClient._decode_result({"a": 1}) == {"a": 1}

    def test_nested_dicts_are_decoded(self):
        raw = {b"outer": {b"inner": b"val"}}
        assert MetasploitClient._decode_result(raw) == {"outer": {"inner": "val"}}

    def test_lists_of_bytes_are_decoded(self):
        raw = {b"items": [b"a", b"b"]}
        assert MetasploitClient._decode_result(raw) == {"items": ["a", "b"]}

    def test_lists_of_dicts_are_decoded(self):
        raw = {b"items": [{b"k": b"v"}]}
        assert MetasploitClient._decode_result(raw) == {"items": [{"k": "v"}]}

    def test_non_byte_scalars_pass_through(self):
        assert MetasploitClient._decode_result({b"n": 42, b"f": 1.5}) == {"n": 42, "f": 1.5}

    def test_invalid_utf8_is_replaced_not_raised(self):
        out = MetasploitClient._decode_result({b"x": b"\xff\xfe"})
        assert "x" in out  # decoded with errors="replace", no exception


class TestConnect:
    async def test_success_with_string_keys(self, client):
        client._call = AsyncMock(return_value={"result": "success", "token": "tok123"})
        assert await client.connect() is True
        assert client.token == "tok123"

    async def test_success_with_byte_token_is_decoded(self, client):
        client._call = AsyncMock(return_value={"result": "success", "token": b"tok123"})
        assert await client.connect() is True
        assert client.token == "tok123"

    async def test_failed_auth_returns_false(self, client):
        client._call = AsyncMock(return_value={"result": "failure"})
        assert await client.connect() is False
        assert client.token is None

    async def test_missing_token_returns_false(self, client):
        client._call = AsyncMock(return_value={"result": "success"})
        assert await client.connect() is False

    async def test_transport_exception_returns_false(self, client):
        client._call = AsyncMock(side_effect=ConnectionError("refused"))
        assert await client.connect() is False


class TestListSessions:
    async def test_parses_session_dicts(self, client):
        client._call = AsyncMock(return_value={
            "1": {"type": "meterpreter", "target_host": "10.0.0.5", "via_exploit": "x"},
        })
        sessions = await client.list_sessions()
        assert len(sessions) == 1
        assert isinstance(sessions[0], MSFSession)
        assert sessions[0].id == 1
        assert sessions[0].target_host == "10.0.0.5"

    async def test_empty_session_list(self, client):
        client._call = AsyncMock(return_value={})
        assert await client.list_sessions() == []

    async def test_non_dict_entries_are_ignored(self, client):
        client._call = AsyncMock(return_value={"1": "not-a-dict"})
        assert await client.list_sessions() == []

    async def test_missing_fields_default_to_unknown(self, client):
        client._call = AsyncMock(return_value={"2": {}})
        sessions = await client.list_sessions()
        assert sessions[0].session_type == "unknown"
        assert sessions[0].target_host == "unknown"


class TestRunExploit:
    async def test_payload_is_injected_into_options(self, client):
        client._call = AsyncMock(return_value={"job_id": 1})
        options = {"RHOSTS": "10.0.0.5"}
        await client.run_exploit("exploit/x", "linux/x86/meterpreter", options)
        assert options["PAYLOAD"] == "linux/x86/meterpreter"
        _, call_args = client._call.await_args.args
        assert call_args[0] == "exploit"


class TestSearchModules:
    async def test_returns_module_list(self, client):
        client._call = AsyncMock(return_value={"modules": [{"type": "exploit", "fullname": "a"}]})
        assert len(await client.search_modules("smb")) == 1

    async def test_filters_by_module_type(self, client):
        client._call = AsyncMock(return_value={"modules": [
            {"type": "exploit", "fullname": "a"},
            {"type": "auxiliary", "fullname": "b"},
        ]})
        result = await client.search_modules("smb", module_type="exploit")
        assert [m["fullname"] for m in result] == ["a"]

    async def test_missing_modules_key_returns_empty(self, client):
        client._call = AsyncMock(return_value={})
        assert await client.search_modules("smb") == []


class TestExtractHost:
    def test_plain_host_is_unchanged(self, client):
        assert client._extract_host("10.0.0.5") == "10.0.0.5"

    def test_http_url_reduced_to_netloc(self, client):
        assert client._extract_host("http://example.com:8080/path") == "example.com:8080"

    def test_https_url_reduced_to_netloc(self, client):
        assert client._extract_host("https://example.com/x") == "example.com"


class TestRunScan:
    async def test_connects_when_no_token(self, client):
        client.connect = AsyncMock(return_value=True)
        client.run_auxiliary = AsyncMock(return_value={"open_ports": [22]})
        result = await client.run_scan(Target(value="10.0.0.5", target_type="ip"))
        client.connect.assert_awaited_once()
        assert result.success is True

    async def test_connection_failure_is_reported(self, client):
        client.connect = AsyncMock(return_value=False)
        result = await client.run_scan(Target(value="10.0.0.5", target_type="ip"))
        assert result.success is False
        assert any("Failed to connect" in e for e in result.errors)

    async def test_vuln_scan_reports_modules(self, client):
        client.token = "tok"
        client.search_modules = AsyncMock(return_value=[{"fullname": "exploit/x"}])
        result = await client.run_scan(
            Target(value="10.0.0.5", target_type="ip"), scan_type="vuln",
        )
        assert result.success is True

    async def test_scan_exception_is_captured(self, client):
        client.token = "tok"
        client.run_auxiliary = AsyncMock(side_effect=RuntimeError("boom"))
        result = await client.run_scan(Target(value="10.0.0.5", target_type="ip"))
        assert result.success is False
        assert any("boom" in e for e in result.errors)


class TestClose:
    async def test_close_logs_out_and_clears_token(self, client):
        client.token = "tok"
        client._call = AsyncMock(return_value={})
        await client.close()
        assert client.token is None

    async def test_close_without_token_is_a_noop(self, client):
        client._call = AsyncMock()
        await client.close()
        client._call.assert_not_called()

    async def test_close_swallows_logout_errors(self, client):
        client.token = "tok"
        client._call = AsyncMock(side_effect=RuntimeError("network"))
        await client.close()
        assert client.token is None
