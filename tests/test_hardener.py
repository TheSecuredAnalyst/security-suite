"""Tests for AutoHardener — the component that executes remediation on hosts.

Safety-critical invariants under test:
  * apply() consults the guardrail gate and refuses when it denies.
  * dry_run defaults to True — the default call path never executes anything.
  * a script containing a banned pattern can never reach subprocess execution.
  * rollback is also gated.

Real subprocess execution is only exercised with harmless shell (echo/exit),
in the tests explicitly marked as such.
"""

from unittest.mock import AsyncMock, patch

import pytest

from core.guardrails import GuardrailsEngine
from modules.remediation.ai_engine import RemediationScript
from modules.remediation.hardener import AutoHardener, HardenResult, SnapshotEntry


@pytest.fixture
def clean_guardrails(monkeypatch):
    engine = GuardrailsEngine()
    monkeypatch.setattr("modules.remediation.hardener.guardrails", engine)
    return engine


@pytest.fixture
def authorized_guardrails(clean_guardrails):
    clean_guardrails.create_session(
        operator="tester", engagement_id="ENG-1", roe_allowed=["10.0.0.0/8"],
    )
    return clean_guardrails


@pytest.fixture
def hardener(tmp_path):
    return AutoHardener(snapshot_dir=str(tmp_path / "snaps"))


def _script(**overrides):
    data = {
        "cve_id": "CVE-2024-6387",
        "target": "10.0.0.5",
        "service": "ssh",
        "version": "8.2",
        "model_used": "test",
        "immediate_mitigation": "echo mitigate",
        "permanent_fix": "echo fix",
        "rollback_script": "echo rollback",
        "verification_command": "true",
    }
    data.update(overrides)
    return RemediationScript(**data)


class TestGating:
    async def test_no_session_blocks_and_does_not_execute(self, hardener, clean_guardrails):
        with patch.object(AutoHardener, "_execute") as ex:
            result = await hardener.apply(_script(), dry_run=False)
        assert result.success is False
        assert any("blocked" in s.lower() for s in result.steps_skipped)
        ex.assert_not_called()

    async def test_banned_script_is_blocked_before_execution(
        self, hardener, authorized_guardrails
    ):
        malicious = _script(permanent_fix="rm -rf /")
        with patch.object(AutoHardener, "_execute") as ex:
            result = await hardener.apply(malicious, dry_run=False)
        assert result.success is False
        assert any("Guardrail blocked" in e for e in result.errors)
        ex.assert_not_called()

    async def test_empty_phase_script_is_a_no_op_error(self, hardener, authorized_guardrails):
        with patch.object(AutoHardener, "_execute") as ex:
            result = await hardener.apply(_script(permanent_fix=""), dry_run=False)
        assert result.success is False
        assert any("No script available" in e for e in result.errors)
        ex.assert_not_called()

    async def test_fork_bomb_is_blocked(self, hardener, authorized_guardrails):
        bomb = _script(permanent_fix=":(){ :|:& };:")
        with patch.object(AutoHardener, "_execute") as ex:
            result = await hardener.apply(bomb, dry_run=False)
        assert result.success is False
        ex.assert_not_called()


class TestDryRun:
    async def test_dry_run_is_the_default(self, hardener, authorized_guardrails):
        with patch.object(AutoHardener, "_execute") as ex:
            result = await hardener.apply(_script())  # no dry_run arg
        assert result.dry_run is True
        ex.assert_not_called()

    async def test_dry_run_reports_success_without_executing(
        self, hardener, authorized_guardrails
    ):
        with patch.object(AutoHardener, "_execute") as ex:
            result = await hardener.apply(_script(), dry_run=True)
        assert result.success is True
        assert any("DRY-RUN" in s for s in result.steps_executed)
        assert "WOULD RUN" in result.stdout
        ex.assert_not_called()

    async def test_dry_run_reports_rollback_availability(self, hardener, authorized_guardrails):
        result = await hardener.apply(_script(rollback_script="echo undo"), dry_run=True)
        assert result.rollback_available is True

    async def test_dry_run_without_rollback_flags_unavailable(
        self, hardener, authorized_guardrails
    ):
        result = await hardener.apply(_script(rollback_script=""), dry_run=True)
        assert result.rollback_available is False

    async def test_immediate_mitigation_phase_is_selectable(
        self, hardener, authorized_guardrails
    ):
        result = await hardener.apply(
            _script(immediate_mitigation="echo quick"), dry_run=True,
            phase="immediate_mitigation",
        )
        assert "echo quick" in result.stdout


class TestExecution:
    async def test_successful_apply_runs_and_verifies(self, hardener, authorized_guardrails):
        execute = AsyncMock(side_effect=[("done", "", 0), ("ok", "", 0)])
        with patch.object(AutoHardener, "_execute", execute), \
             patch.object(AutoHardener, "_snapshot", AsyncMock(return_value=[])):
            result = await hardener.apply(_script(), dry_run=False)
        assert result.success is True
        assert any("executed successfully" in s for s in result.steps_executed)
        assert any("Verification passed" in s for s in result.steps_executed)

    async def test_failed_script_triggers_auto_rollback_of_snapshots(
        self, hardener, authorized_guardrails
    ):
        snap = SnapshotEntry(path="/etc/x", original_hash="h", backup_path="/b", timestamp="t")
        with patch.object(AutoHardener, "_execute", AsyncMock(return_value=("", "err", 1))), \
             patch.object(AutoHardener, "_snapshot", AsyncMock(return_value=[snap])), \
             patch.object(AutoHardener, "_restore_snapshots", AsyncMock()) as restore:
            result = await hardener.apply(_script(), dry_run=False)
        assert result.success is False
        assert any("exit 1" in s for s in result.steps_executed)
        restore.assert_awaited_once()

    async def test_successful_apply_registers_rollback(self, hardener, authorized_guardrails):
        with patch.object(AutoHardener, "_execute", AsyncMock(return_value=("", "", 0))), \
             patch.object(AutoHardener, "_snapshot", AsyncMock(return_value=[])):
            await hardener.apply(_script(), dry_run=False)
        assert len(hardener.list_rollbacks()) == 1

    async def test_verification_failure_is_recorded_but_not_fatal(
        self, hardener, authorized_guardrails
    ):
        execute = AsyncMock(side_effect=[("done", "", 0), ("", "bad", 3)])
        with patch.object(AutoHardener, "_execute", execute), \
             patch.object(AutoHardener, "_snapshot", AsyncMock(return_value=[])):
            result = await hardener.apply(_script(), dry_run=False)
        assert result.success is True
        assert any("Verification returned non-zero" in s for s in result.steps_skipped)


class TestRollback:
    async def test_rollback_without_registration_fails(self, hardener, authorized_guardrails):
        result = await hardener.rollback("CVE-2024-6387", "10.0.0.5")
        assert result.success is False
        assert any("No rollback registered" in e for e in result.errors)

    async def test_registered_rollback_executes_and_deregisters(
        self, hardener, authorized_guardrails
    ):
        with patch.object(AutoHardener, "_execute", AsyncMock(return_value=("", "", 0))), \
             patch.object(AutoHardener, "_snapshot", AsyncMock(return_value=[])):
            await hardener.apply(_script(), dry_run=False)
        assert hardener.list_rollbacks()

        with patch.object(AutoHardener, "_execute", AsyncMock(return_value=("undone", "", 0))):
            result = await hardener.rollback("CVE-2024-6387", "10.0.0.5")
        assert result.success is True
        assert hardener.list_rollbacks() == []

    async def test_rollback_is_guardrail_gated(self, hardener, clean_guardrails):
        # Register a rollback under an authorized session...
        clean_guardrails.create_session(
            operator="t", engagement_id="E", roe_allowed=["10.0.0.0/8"],
        )
        with patch.object(AutoHardener, "_execute", AsyncMock(return_value=("", "", 0))), \
             patch.object(AutoHardener, "_snapshot", AsyncMock(return_value=[])):
            await hardener.apply(_script(rollback_script="rm -rf /"), dry_run=False)

        # ...then attempt rollback of a dangerous script — the gate must catch it.
        with patch.object(AutoHardener, "_execute") as ex:
            result = await hardener.rollback("CVE-2024-6387", "10.0.0.5")
        assert result.success is False
        assert any("Guardrail blocked rollback" in e for e in result.errors)
        ex.assert_not_called()

    async def test_rollback_failure_is_reported(self, hardener, authorized_guardrails):
        with patch.object(AutoHardener, "_execute", AsyncMock(return_value=("", "", 0))), \
             patch.object(AutoHardener, "_snapshot", AsyncMock(return_value=[])):
            await hardener.apply(_script(), dry_run=False)
        with patch.object(AutoHardener, "_execute", AsyncMock(return_value=("", "fail", 1))):
            result = await hardener.rollback("CVE-2024-6387", "10.0.0.5")
        assert result.success is False
        assert any("Rollback failed" in e for e in result.errors)


class TestExecuteSubprocess:
    """Exercises the real subprocess path with harmless shell only."""

    async def test_echo_runs_and_captures_stdout(self, hardener):
        stdout, stderr, code = await hardener._execute("echo hello", timeout=10)
        assert code == 0
        assert "hello" in stdout

    async def test_nonzero_exit_is_reported(self, hardener):
        _, _, code = await hardener._execute("exit 7", timeout=10)
        assert code == 7

    async def test_stderr_is_captured(self, hardener):
        _, stderr, _ = await hardener._execute("echo oops 1>&2", timeout=10)
        assert "oops" in stderr

    async def test_set_e_aborts_on_first_failure(self, hardener):
        # The wrapper injects `set -euo pipefail`, so a failing command stops the script.
        _, _, code = await hardener._execute("false\necho should_not_print", timeout=10)
        assert code != 0

    async def test_timeout_returns_124(self, hardener):
        _, stderr, code = await hardener._execute("sleep 5", timeout=1)
        assert code == 124
        assert "timed out" in stderr


class TestSnapshot:
    # _snapshot does a function-local `import re`, so the patch targets the real
    # re.findall rather than a name on the hardener module.
    async def test_snapshots_only_existing_files(self, hardener, tmp_path):
        real = tmp_path / "etc_target"
        real.write_text("original")
        with patch("re.findall", return_value=[str(real)]):
            snaps = await hardener._snapshot(f"sed -i s/a/b/ {real}")
        assert len(snaps) == 1
        assert snaps[0].path == str(real)
        assert snaps[0].original_hash  # sha256 recorded

    async def test_missing_files_are_skipped(self, hardener):
        with patch("re.findall", return_value=["/etc/nonexistent-xyz"]):
            assert await hardener._snapshot("sed -i s/a/b/ /etc/nonexistent-xyz") == []

    async def test_snapshot_restore_round_trip(self, hardener, tmp_path):
        original = tmp_path / "conf"
        original.write_text("v1")
        with patch("re.findall", return_value=[str(original)]):
            snaps = await hardener._snapshot(f"sed -i x {original}")
        original.write_text("v2-modified")
        await hardener._restore_snapshots(snaps)
        assert original.read_text() == "v1"


class TestExplainAndModel:
    def test_explain_prefixes_lines_with_would_run(self, hardener):
        out = hardener._explain_script("echo a\necho b")
        assert out.count("WOULD RUN") == 2

    def test_explain_skips_comments_and_blanks(self, hardener):
        out = hardener._explain_script("# comment\n\necho real")
        assert out.count("WOULD RUN") == 1

    def test_explain_caps_at_30_lines(self, hardener):
        script = "\n".join(f"echo {i}" for i in range(50))
        out = hardener._explain_script(script)
        assert "and 20 more lines" in out

    def test_harden_result_to_dict_excludes_snapshot_internals(self):
        result = HardenResult(cve_id="c", target="t", dry_run=True, success=True)
        result.snapshots.append(
            SnapshotEntry(path="/etc/x", original_hash="h", backup_path="/b", timestamp="t")
        )
        d = result.to_dict()
        assert "snapshots" not in d
        assert d["cve_id"] == "c"

    def test_snapshot_dir_is_created(self, tmp_path):
        target = tmp_path / "made" / "here"
        AutoHardener(snapshot_dir=str(target))
        assert target.is_dir()
