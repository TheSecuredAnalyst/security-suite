"""Tests for the AI remediation-script generator.

RemediationAI.__init__ imports `ollama` lazily. To keep these tests
dependency-free (they must run in the [dev]-only CI job), a stub ollama module
is injected into sys.modules and the client is replaced with a fake.
"""

import json
import sys
import types
from unittest.mock import MagicMock

import pytest

from core.guardrails import GuardrailsEngine
from modules.exploit_engine.runner import ExploitResult
from modules.remediation.ai_engine import (
    MAX_RETRIES,
    RemediationAI,
    RemediationScript,
)


@pytest.fixture(autouse=True)
def fake_ollama(monkeypatch):
    """Inject a stub `ollama` module so RemediationAI() can be constructed."""
    stub = types.ModuleType("ollama")
    stub.Client = MagicMock(return_value=MagicMock())
    monkeypatch.setitem(sys.modules, "ollama", stub)
    return stub


@pytest.fixture
def clean_guardrails(monkeypatch):
    engine = GuardrailsEngine()
    monkeypatch.setattr("modules.remediation.ai_engine.guardrails", engine)
    return engine


def _ai(chat_returns):
    """Build a RemediationAI whose model client returns the given payload(s)."""
    ai = RemediationAI(model="test-model")
    ai._client = MagicMock()
    if isinstance(chat_returns, list):
        ai._client.chat.side_effect = [
            {"message": {"content": c}} for c in chat_returns
        ]
    else:
        ai._client.chat.return_value = {"message": {"content": chat_returns}}
    return ai


def _safe_json(**overrides):
    payload = {
        "immediate_mitigation": "echo mitigate",
        "permanent_fix": "systemctl restart sshd",
        "rollback_script": "echo rollback",
        "verification_command": "sshd -t",
        "explanation": "Patch the service.",
    }
    payload.update(overrides)
    return json.dumps(payload)


def _confirmed_result():
    return ExploitResult(
        cve_id="CVE-2024-6387", target="10.0.0.5", port=22,
        module_path="exploit/linux/ssh/regresshion", status="CONFIRMED",
    )


class TestExtractJSON:
    def test_direct_json(self):
        assert RemediationAI._extract_json('{"a": 1}') == {"a": 1}

    def test_json_in_markdown_fence(self):
        text = 'Here you go:\n```json\n{"a": 1}\n```\ndone'
        assert RemediationAI._extract_json(text) == {"a": 1}

    def test_json_in_plain_fence(self):
        assert RemediationAI._extract_json('```\n{"a": 1}\n```') == {"a": 1}

    def test_embedded_braces(self):
        assert RemediationAI._extract_json('noise {"a": 1} trailing') == {"a": 1}

    def test_invalid_returns_none(self):
        assert RemediationAI._extract_json("no json here") is None

    def test_empty_string_returns_none(self):
        assert RemediationAI._extract_json("") is None

    def test_multiline_json_object(self):
        assert RemediationAI._extract_json('{\n  "a": 1,\n  "b": 2\n}') == {"a": 1, "b": 2}


class TestGenerateFromExploit:
    async def test_non_confirmed_result_is_skipped(self, clean_guardrails):
        ai = _ai(_safe_json())
        unconfirmed = ExploitResult(
            cve_id="CVE-X", target="10.0.0.5", port=22, module_path="m",
            status="NOT_EXPLOITABLE",
        )
        script = await ai.generate_from_exploit(unconfirmed)
        assert script.safe is False
        assert "not confirmed" in script.explanation.lower()
        ai._client.chat.assert_not_called()

    async def test_confirmed_result_produces_a_safe_script(self, clean_guardrails):
        ai = _ai(_safe_json())
        script = await ai.generate_from_exploit(_confirmed_result())
        assert script.safe is True
        assert script.permanent_fix == "systemctl restart sshd"
        assert script.cve_id == "CVE-2024-6387"

    async def test_safe_script_surfaces_guardrail_warnings(self, clean_guardrails):
        # "systemctl restart" triggers a soft warning, not a block.
        ai = _ai(_safe_json())
        script = await ai.generate_from_exploit(_confirmed_result())
        assert any("restarts a service" in w for w in script.warnings)


class TestGenerateSafety:
    async def test_banned_script_is_rejected_after_retries(self, clean_guardrails):
        # Every attempt returns a dangerous fix — must exhaust retries and fail closed.
        dangerous = _safe_json(permanent_fix="rm -rf /")
        ai = _ai([dangerous] * (MAX_RETRIES + 1))
        script = await ai.generate_from_exploit(_confirmed_result())
        assert script.safe is False
        assert ai._client.chat.call_count == MAX_RETRIES + 1
        assert "failed safety validation" in script.explanation.lower()

    async def test_recovers_when_a_later_attempt_is_clean(self, clean_guardrails):
        ai = _ai([_safe_json(permanent_fix="dd if=/dev/zero of=/dev/sda"), _safe_json()])
        script = await ai.generate_from_exploit(_confirmed_result())
        assert script.safe is True
        assert ai._client.chat.call_count == 2

    async def test_dangerous_content_never_marked_safe(self, clean_guardrails):
        ai = _ai([_safe_json(rollback_script=":(){ :|:& };:")] * (MAX_RETRIES + 1))
        script = await ai.generate_from_exploit(_confirmed_result())
        assert script.safe is False

    async def test_invalid_json_triggers_retry(self, clean_guardrails):
        ai = _ai(["not json at all", _safe_json()])
        script = await ai.generate_from_exploit(_confirmed_result())
        assert script.safe is True
        assert ai._client.chat.call_count == 2

    async def test_persistent_invalid_json_fails_closed(self, clean_guardrails):
        ai = _ai(["nope"] * (MAX_RETRIES + 1))
        script = await ai.generate_from_exploit(_confirmed_result())
        assert script.safe is False

    async def test_client_exception_is_caught_and_fails_closed(self, clean_guardrails):
        ai = RemediationAI(model="test-model")
        ai._client = MagicMock()
        ai._client.chat.side_effect = RuntimeError("ollama down")
        script = await ai.generate_from_exploit(_confirmed_result())
        assert script.safe is False


class TestGenerateFromService:
    async def test_service_misconfig_produces_a_script(self, clean_guardrails):
        ai = _ai(_safe_json())
        script = await ai.generate_from_service(
            service="redis", version="6.0", target="10.0.0.5", port=6379,
            issue="unauthenticated access",
        )
        assert script.safe is True
        assert script.cve_id == "redis-6379"
        assert script.service == "redis"

    async def test_service_banned_script_fails_closed(self, clean_guardrails):
        ai = _ai([_safe_json(permanent_fix="mkfs.ext4 /dev/sda1")] * (MAX_RETRIES + 1))
        script = await ai.generate_from_service(
            service="redis", version="6.0", target="10.0.0.5", port=6379, issue="x",
        )
        assert script.safe is False


class TestRemediationScriptModel:
    def test_defaults(self):
        s = RemediationScript(
            cve_id="c", target="t", service="s", version="v", model_used="m",
        )
        assert s.safe is False
        assert s.warnings == []
        assert s.validation is None
        assert s.immediate_mitigation == ""
