"""Tests for the RedBlueOrchestrator autonomous loop.

The orchestrator wires together the scanner, exploit runner, AI engine and
hardener. Every external component is mocked here — no network, no Metasploit,
no Ollama, no real subprocess, and no writes to the real SQLite database (the
db functions are patched in the loop's namespace).

Focus:
  * run() session gating and mode dispatch (which phases run per mode).
  * each phase's own logic driven directly with mocked components.
  * confirmed-only + (ip,port) dedup before blue-team phases.
"""

import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.guardrails import GuardrailsEngine
from core.models import Finding, ScanResult, Severity, Target
from modules.exploit_engine.runner import ExploitResult
from modules.orchestrator.loop import (
    LoopFinding,
    LoopReport,
    RedBlueOrchestrator,
)
from modules.remediation.ai_engine import RemediationScript
from modules.remediation.hardener import HardenResult


@pytest.fixture(autouse=True)
def fake_ollama(monkeypatch):
    stub = types.ModuleType("ollama")
    stub.Client = MagicMock(return_value=MagicMock())
    monkeypatch.setitem(sys.modules, "ollama", stub)
    return stub


@pytest.fixture(autouse=True)
def no_db_writes(monkeypatch):
    """Neuter the SQLite writes the report writer performs."""
    for name in ("upsert_run", "upsert_finding", "insert_remediation", "save_entities"):
        monkeypatch.setattr(f"modules.orchestrator.loop.{name}", MagicMock())


@pytest.fixture
def clean_guardrails(monkeypatch):
    engine = GuardrailsEngine()
    monkeypatch.setattr("modules.orchestrator.loop.guardrails", engine)
    return engine


@pytest.fixture
def authorized(clean_guardrails):
    clean_guardrails.create_session(
        operator="tester", engagement_id="ENG-1", roe_allowed=["10.0.0.0/8"],
    )
    return clean_guardrails


@pytest.fixture
def orch(tmp_path):
    o = RedBlueOrchestrator(output_dir=str(tmp_path / "loop"))
    o._exploit_runner = AsyncMock()
    o._remediation_ai = AsyncMock()
    o._hardener = AsyncMock()
    return o


def _confirmed_finding(ip="10.0.0.5", port=445, cvss=9.8, cve="CVE-2017-0144"):
    return LoopFinding(
        ip=ip, port=port, service="smb", version="1", cve_id=cve,
        cvss_score=cvss, exploit_status="CONFIRMED",
    )


def _safe_rem(cve="CVE-2017-0144", ip="10.0.0.5"):
    return RemediationScript(
        cve_id=cve, target=ip, service="smb", version="1", model_used="m",
        permanent_fix="echo fix", immediate_mitigation="echo mit",
        rollback_script="echo rb", verification_command="true", safe=True,
    )


class TestRunGating:
    async def test_invalid_mode_raises(self, orch, authorized):
        with pytest.raises(ValueError, match="Invalid mode"):
            await orch.run("10.0.0.5", mode="nonsense")

    async def test_no_session_raises(self, orch, clean_guardrails):
        with pytest.raises(PermissionError, match="No active engagement session"):
            await orch.run("10.0.0.5", mode="recon_only")

    async def test_expired_session_raises(self, orch, clean_guardrails):
        clean_guardrails.create_session(
            operator="t", engagement_id="E", roe_allowed=["10.0.0.0/8"], ttl_hours=0,
        )
        with pytest.raises(PermissionError, match="expired"):
            await orch.run("10.0.0.5", mode="recon_only")

    async def test_report_carries_session_identity(self, orch, authorized):
        with patch.object(RedBlueOrchestrator, "_phase_scan", AsyncMock(return_value=[])):
            report = await orch.run("10.0.0.5", mode="recon_only")
        assert report.operator == "tester"
        assert report.engagement_id == "ENG-1"
        assert report.session_id


class TestModeDispatch:
    """Each mode must stop at the right phase boundary."""

    def _patch_phases(self, add_confirmed=True):
        """Patch every phase; exploit-check optionally seeds a confirmed finding."""
        async def exploit_check(cve_findings, report, mc):
            if add_confirmed:
                report.findings.append(_confirmed_finding())
                report.confirmed_exploitable = 1

        return {
            "_phase_scan": AsyncMock(return_value=[{"ip": "10.0.0.5"}]),
            "_phase_exploit_check": AsyncMock(side_effect=exploit_check),
            "_phase_threat_hunt": AsyncMock(),
            "_phase_generate_remediations": AsyncMock(),
            "_phase_apply_hardening": AsyncMock(),
            "_phase_verify_closure": AsyncMock(),
        }

    async def _run_mode(self, orch, mode, add_confirmed=True):
        patches = self._patch_phases(add_confirmed)
        with patch.multiple(RedBlueOrchestrator, **patches), \
             patch.object(RedBlueOrchestrator, "_write_report", MagicMock()):
            await orch.run("10.0.0.5", mode=mode)
        return patches

    async def test_recon_only_stops_after_scan(self, orch, authorized):
        p = await self._run_mode(orch, "recon_only")
        p["_phase_exploit_check"].assert_not_called()
        p["_phase_generate_remediations"].assert_not_called()

    async def test_confirm_only_runs_scan_and_exploit_check_only(self, orch, authorized):
        p = await self._run_mode(orch, "confirm_only")
        p["_phase_exploit_check"].assert_awaited_once()
        p["_phase_threat_hunt"].assert_not_called()
        p["_phase_generate_remediations"].assert_not_called()

    async def test_confirm_and_plan_generates_but_does_not_apply(self, orch, authorized):
        p = await self._run_mode(orch, "confirm_and_plan")
        p["_phase_threat_hunt"].assert_awaited_once()
        p["_phase_generate_remediations"].assert_awaited_once()
        p["_phase_apply_hardening"].assert_not_called()
        p["_phase_verify_closure"].assert_not_called()

    async def test_full_auto_runs_every_phase(self, orch, authorized):
        p = await self._run_mode(orch, "full_auto")
        p["_phase_apply_hardening"].assert_awaited_once()
        p["_phase_verify_closure"].assert_awaited_once()

    async def test_empty_scan_short_circuits_before_exploit_check(self, orch, authorized):
        patches = self._patch_phases()
        patches["_phase_scan"] = AsyncMock(return_value=[])  # nothing found
        with patch.multiple(RedBlueOrchestrator, **patches), \
             patch.object(RedBlueOrchestrator, "_write_report", MagicMock()):
            report = await orch.run("10.0.0.5", mode="full_auto")
        patches["_phase_exploit_check"].assert_not_called()
        assert report.completed_at

    async def test_full_auto_with_no_confirmed_skips_blue_team(self, orch, authorized):
        p = await self._run_mode(orch, "full_auto", add_confirmed=False)
        p["_phase_generate_remediations"].assert_not_called()
        p["_phase_apply_hardening"].assert_not_called()


class TestPhaseScan:
    def _scan_result(self, services):
        finding = Finding(
            title="services", description="", severity=Severity.INFO,
            source="vulnscan", data={"services": services},
        )
        return ScanResult(
            target=Target(value="10.0.0.5", target_type="ip"),
            module="vulnscan", findings=[finding],
        )

    async def test_populates_findings_and_counts(self, orch, authorized):
        services = [
            {"target_ip": "10.0.0.5", "port": 445, "product": "Samba",
             "name": "microsoft-ds", "version": "4.1"},
        ]
        with patch("modules.orchestrator.loop.NetworkScanner") as NS, \
             patch("modules.orchestrator.loop.CVELookup") as CL:
            NS.return_value.run = AsyncMock(return_value=self._scan_result(services))
            CL.return_value.lookup = AsyncMock(return_value=[
                {"id": "CVE-2017-0144", "cvss_score": 9.8, "description": "eternalblue"},
            ])
            report = LoopReport(
                target="10.0.0.5", mode="recon_only", operator="t",
                engagement_id="E", session_id="s", started_at="now",
            )
            out = await orch._phase_scan("10.0.0.5", "normal", report)

        assert out  # non-empty -> loop proceeds
        assert report.total_hosts == 1
        assert report.total_services == 1
        assert report.total_cves == 1
        assert report.findings[0].cve_id == "CVE-2017-0144"
        assert report.risk_score > 0

    async def test_service_without_product_is_skipped(self, orch, authorized):
        services = [{"target_ip": "10.0.0.5", "port": 9, "name": "", "version": ""}]
        with patch("modules.orchestrator.loop.NetworkScanner") as NS, \
             patch("modules.orchestrator.loop.CVELookup") as CL:
            NS.return_value.run = AsyncMock(return_value=self._scan_result(services))
            CL.return_value.lookup = AsyncMock(return_value=[])
            report = LoopReport(
                target="10.0.0.5", mode="recon_only", operator="t",
                engagement_id="E", session_id="s", started_at="now",
            )
            await orch._phase_scan("10.0.0.5", "normal", report)
        assert report.findings == []

    async def test_non_numeric_cvss_is_coerced_to_zero(self, orch, authorized):
        services = [{"target_ip": "10.0.0.5", "port": 80, "product": "nginx", "version": "1"}]
        with patch("modules.orchestrator.loop.NetworkScanner") as NS, \
             patch("modules.orchestrator.loop.CVELookup") as CL:
            NS.return_value.run = AsyncMock(return_value=self._scan_result(services))
            CL.return_value.lookup = AsyncMock(return_value=[
                {"id": "CVE-X", "cvss_score": "not-a-number", "description": ""},
            ])
            report = LoopReport(
                target="10.0.0.5", mode="recon_only", operator="t",
                engagement_id="E", session_id="s", started_at="now",
            )
            await orch._phase_scan("10.0.0.5", "normal", report)
        assert report.findings[0].cvss_score == 0.0

    async def test_scanner_exception_is_captured_as_error(self, orch, authorized):
        with patch("modules.orchestrator.loop.NetworkScanner") as NS:
            NS.return_value.run = AsyncMock(side_effect=RuntimeError("nmap missing"))
            report = LoopReport(
                target="10.0.0.5", mode="recon_only", operator="t",
                engagement_id="E", session_id="s", started_at="now",
            )
            out = await orch._phase_scan("10.0.0.5", "normal", report)
        assert out == []
        assert any("RED-1 scan failed" in e for e in report.errors)


class TestPhaseExploitCheck:
    def _report_with(self, findings):
        r = LoopReport(
            target="10.0.0.5", mode="confirm_only", operator="t",
            engagement_id="E", session_id="s", started_at="now",
        )
        r.findings = findings
        return r

    async def test_confirmed_result_increments_counter(self, orch, authorized):
        finding = LoopFinding(ip="10.0.0.5", port=445, service="smb", version="1",
                              cve_id="CVE-2017-0144")
        report = self._report_with([finding])
        orch._exploit_runner.check_cve = AsyncMock(return_value=ExploitResult(
            cve_id="CVE-2017-0144", target="10.0.0.5", port=445, module_path="m",
            status="CONFIRMED",
        ))
        await orch._phase_exploit_check([{}], report, max_concurrent=5)
        assert finding.exploit_status == "CONFIRMED"
        assert report.confirmed_exploitable == 1

    async def test_two_cves_same_port_count_once(self, orch, authorized):
        findings = [
            LoopFinding(ip="10.0.0.5", port=445, service="smb", version="1", cve_id="CVE-A"),
            LoopFinding(ip="10.0.0.5", port=445, service="smb", version="1", cve_id="CVE-B"),
        ]
        report = self._report_with(findings)
        orch._exploit_runner.check_cve = AsyncMock(side_effect=lambda cve, ip, port: ExploitResult(
            cve_id=cve, target=ip, port=port, module_path="m", status="CONFIRMED",
        ))
        await orch._phase_exploit_check([{}], report, max_concurrent=5)
        assert report.confirmed_exploitable == 1

    async def test_findings_without_cve_are_ignored(self, orch, authorized):
        finding = LoopFinding(ip="10.0.0.5", port=445, service="smb", version="1", cve_id="")
        report = self._report_with([finding])
        orch._exploit_runner.check_cve = AsyncMock()
        await orch._phase_exploit_check([{}], report, max_concurrent=5)
        orch._exploit_runner.check_cve.assert_not_called()

    async def test_no_module_triggers_service_fallback(self, orch, authorized):
        finding = LoopFinding(ip="10.0.0.5", port=22, service="ssh", version="8",
                              cve_id="CVE-Z", exploit_status="NO_MODULE")
        report = self._report_with([finding])
        # check_cve leaves it NO_MODULE; the fallback confirms via check_service.
        orch._exploit_runner.check_cve = AsyncMock(return_value=ExploitResult(
            cve_id="CVE-Z", target="10.0.0.5", port=22, module_path="m", status="NO_MODULE",
        ))
        orch._exploit_runner.check_service = AsyncMock(return_value=[ExploitResult(
            cve_id="EXPOSED-SSH", target="10.0.0.5", port=22,
            module_path="auxiliary/scanner/ssh", status="CONFIRMED",
        )])
        await orch._phase_exploit_check([{}], report, max_concurrent=5)
        orch._exploit_runner.check_service.assert_awaited_once()
        assert finding.exploit_status == "CONFIRMED"
        assert report.confirmed_exploitable == 1


class TestPhaseThreatHunt:
    async def test_no_ioc_patterns_for_cve_is_a_noop(self, orch, authorized):
        finding = _confirmed_finding(cve="CVE-9999-0000")
        report = LoopReport(target="t", mode="full_auto", operator="o",
                            engagement_id="e", session_id="s", started_at="n")
        await orch._phase_threat_hunt([finding], report)
        assert finding.already_exploited is False
        assert report.already_exploited == 0

    async def test_ioc_match_flags_prior_exploitation(self, orch, authorized):
        from unittest.mock import mock_open
        finding = _confirmed_finding(cve="CVE-2017-0144")
        report = LoopReport(target="t", mode="full_auto", operator="o",
                            engagement_id="e", session_id="s", started_at="n")
        # Only /var/log/auth.log "exists"; it contains an EternalBlue IOC.
        opener = mock_open(read_data="Jan 1 attacker used DOUBLEPULSAR implant\n")
        with patch("modules.orchestrator.loop.os.path.isfile",
                   side_effect=lambda p: p == "/var/log/auth.log"), \
             patch("builtins.open", opener):
            await orch._phase_threat_hunt([finding], report)
        assert finding.already_exploited is True
        assert report.already_exploited == 1
        assert finding.hunt_evidence


class TestPhaseGenerateRemediations:
    def _report(self):
        return LoopReport(target="t", mode="confirm_and_plan", operator="o",
                          engagement_id="e", session_id="s", started_at="n")

    async def test_safe_remediation_increments_counter(self, orch, authorized):
        finding = _confirmed_finding()
        report = self._report()
        orch._remediation_ai.generate_from_exploit = AsyncMock(return_value=_safe_rem())
        await orch._phase_generate_remediations([finding], report, "Linux")
        assert finding.remediation.safe is True
        assert report.remediations_generated == 1

    async def test_exposed_service_uses_service_prompt(self, orch, authorized):
        finding = LoopFinding(ip="10.0.0.5", port=6379, service="redis", version="6",
                              cve_id="EXPOSED-REDIS", exploit_status="CONFIRMED")
        report = self._report()
        orch._remediation_ai.generate_from_service = AsyncMock(return_value=_safe_rem())
        orch._remediation_ai.generate_from_exploit = AsyncMock()
        await orch._phase_generate_remediations([finding], report, "Linux")
        orch._remediation_ai.generate_from_service.assert_awaited_once()
        orch._remediation_ai.generate_from_exploit.assert_not_called()

    async def test_generation_is_capped(self, orch, authorized):
        findings = [_confirmed_finding(port=p, cvss=float(p)) for p in range(1, 11)]
        report = self._report()
        orch._remediation_ai.generate_from_exploit = AsyncMock(return_value=_safe_rem())
        await orch._phase_generate_remediations(findings, report, "Linux")
        assert orch._remediation_ai.generate_from_exploit.await_count == \
            RedBlueOrchestrator._MAX_REMEDIATION_TARGETS

    async def test_unsafe_remediation_not_counted(self, orch, authorized):
        finding = _confirmed_finding()
        report = self._report()
        unsafe = _safe_rem()
        unsafe.safe = False
        orch._remediation_ai.generate_from_exploit = AsyncMock(return_value=unsafe)
        await orch._phase_generate_remediations([finding], report, "Linux")
        assert report.remediations_generated == 0

    async def test_generation_exception_is_swallowed(self, orch, authorized):
        finding = _confirmed_finding()
        report = self._report()
        orch._remediation_ai.generate_from_exploit = AsyncMock(side_effect=RuntimeError("x"))
        await orch._phase_generate_remediations([finding], report, "Linux")
        assert report.remediations_generated == 0


class TestPhaseApplyHardening:
    def _report(self):
        return LoopReport(target="t", mode="full_auto", operator="o",
                          engagement_id="e", session_id="s", started_at="n")

    async def test_applies_only_safe_remediations(self, orch, authorized):
        with_rem = _confirmed_finding()
        with_rem.remediation = _safe_rem()
        without = _confirmed_finding(port=139)  # no remediation
        report = self._report()
        orch._hardener.apply = AsyncMock(return_value=HardenResult(
            cve_id="CVE-2017-0144", target="10.0.0.5", dry_run=False, success=True,
        ))
        await orch._phase_apply_hardening([with_rem, without], report)
        # two apply() calls for the one finding (immediate + permanent)
        assert orch._hardener.apply.await_count == 2
        assert report.remediations_applied == 1

    async def test_failed_hardening_not_counted(self, orch, authorized):
        finding = _confirmed_finding()
        finding.remediation = _safe_rem()
        report = self._report()
        orch._hardener.apply = AsyncMock(return_value=HardenResult(
            cve_id="c", target="t", dry_run=False, success=False,
        ))
        await orch._phase_apply_hardening([finding], report)
        assert report.remediations_applied == 0

    async def test_apply_exception_is_swallowed(self, orch, authorized):
        finding = _confirmed_finding()
        finding.remediation = _safe_rem()
        report = self._report()
        orch._hardener.apply = AsyncMock(side_effect=RuntimeError("boom"))
        await orch._phase_apply_hardening([finding], report)
        assert report.remediations_applied == 0


class TestPhaseVerifyClosure:
    def _report(self):
        return LoopReport(target="t", mode="full_auto", operator="o",
                          engagement_id="e", session_id="s", started_at="n")

    async def test_recheck_not_exploitable_marks_closed(self, orch, authorized):
        finding = _confirmed_finding()
        finding.harden_result = HardenResult(cve_id="c", target="t", dry_run=False, success=True)
        report = self._report()
        orch._exploit_runner.check_cve = AsyncMock(return_value=ExploitResult(
            cve_id="CVE-2017-0144", target="10.0.0.5", port=445, module_path="m",
            status="NOT_EXPLOITABLE",
        ))
        await orch._phase_verify_closure([finding], report)
        assert finding.verified_closed is True
        assert report.verified_closed == 1

    async def test_still_exploitable_is_not_closed(self, orch, authorized):
        finding = _confirmed_finding()
        finding.harden_result = HardenResult(cve_id="c", target="t", dry_run=False, success=True)
        report = self._report()
        orch._exploit_runner.check_cve = AsyncMock(return_value=ExploitResult(
            cve_id="CVE-2017-0144", target="10.0.0.5", port=445, module_path="m",
            status="CONFIRMED",
        ))
        await orch._phase_verify_closure([finding], report)
        assert finding.verified_closed is False
        assert report.verified_closed == 0

    async def test_findings_without_successful_harden_are_skipped(self, orch, authorized):
        finding = _confirmed_finding()  # no harden_result
        report = self._report()
        orch._exploit_runner.check_cve = AsyncMock()
        await orch._phase_verify_closure([finding], report)
        orch._exploit_runner.check_cve.assert_not_called()


class TestPersistToDB:
    def _report(self):
        r = LoopReport(target="10.0.0.5", mode="full_auto", operator="o",
                       engagement_id="e", session_id="sess-1", started_at="n")
        f = _confirmed_finding()
        f.remediation = _safe_rem()
        r.findings = [f]
        return r

    async def test_writes_run_finding_and_remediation(self, orch, authorized):
        report = self._report()
        with patch("modules.orchestrator.loop.upsert_run") as ur, \
             patch("modules.orchestrator.loop.upsert_finding", return_value=1) as uf, \
             patch("modules.orchestrator.loop.insert_remediation") as ir:
            orch._persist_to_db(report, "/tmp/report.json")
        ur.assert_called_once()
        uf.assert_called_once()
        ir.assert_called_once()

    async def test_unconfirmed_findings_are_not_persisted(self, orch, authorized):
        report = self._report()
        report.findings[0].exploit_status = "NOT_EXPLOITABLE"
        with patch("modules.orchestrator.loop.upsert_run"), \
             patch("modules.orchestrator.loop.upsert_finding", return_value=1) as uf, \
             patch("modules.orchestrator.loop.insert_remediation") as ir:
            orch._persist_to_db(report, "/tmp/r.json")
        uf.assert_not_called()
        ir.assert_not_called()

    async def test_duplicate_ip_port_persisted_once(self, orch, authorized):
        report = self._report()
        dup = _confirmed_finding()  # same ip/port as the existing finding
        report.findings.append(dup)
        with patch("modules.orchestrator.loop.upsert_run"), \
             patch("modules.orchestrator.loop.upsert_finding", return_value=1) as uf, \
             patch("modules.orchestrator.loop.insert_remediation"):
            orch._persist_to_db(report, "/tmp/r.json")
        assert uf.call_count == 1


class TestDataModels:
    def test_loop_report_to_dict_shape(self):
        report = LoopReport(target="t", mode="full_auto", operator="o",
                            engagement_id="e", session_id="s", started_at="n")
        report.findings.append(_confirmed_finding())
        d = report.to_dict()
        assert d["summary"]["confirmed_exploitable"] == 0
        assert d["findings"][0]["cve_id"] == "CVE-2017-0144"
        assert d["findings"][0]["harden_applied"] is False

    def test_to_dict_reflects_remediation_state(self):
        report = LoopReport(target="t", mode="full_auto", operator="o",
                            engagement_id="e", session_id="s", started_at="n")
        f = _confirmed_finding()
        f.remediation = _safe_rem()
        report.findings.append(f)
        entry = report.to_dict()["findings"][0]
        assert entry["remediation_safe"] is True

    def test_loop_finding_defaults(self):
        f = LoopFinding(ip="i", port=1, service="s", version="v", cve_id="c")
        assert f.exploit_status == "NOT_CHECKED"
        assert f.attack_tags == []
        assert f.already_exploited is False
        assert f.remediation is None

    async def test_write_report_creates_a_json_file(self, orch, authorized, tmp_path):
        report = LoopReport(target="t", mode="recon_only", operator="o",
                            engagement_id="ENG-9", session_id="s", started_at="n")
        with patch.object(orch, "_persist_to_db"):
            orch._write_report(report)
        files = list((tmp_path / "loop").glob("loop_ENG-9_*.json"))
        assert len(files) == 1


class TestEntityProvenance:
    """The scan phase must record how each CVE was reached."""

    @staticmethod
    def _scan_result(services):
        result = ScanResult(target=Target.from_string("10.0.0.5"), module="vulnscan")
        result.add_finding(
            title="services", description="d", severity=Severity.INFO,
            data={"services": services},
        )
        return result

    async def _scan(self, orch, services, cves):
        with patch("modules.orchestrator.loop.NetworkScanner") as NS, \
             patch("modules.orchestrator.loop.CVELookup") as CL:
            NS.return_value.run = AsyncMock(return_value=self._scan_result(services))
            CL.return_value.lookup = AsyncMock(return_value=cves)
            report = LoopReport(
                target="10.0.0.5", mode="recon_only", operator="t",
                engagement_id="E", session_id="s", started_at="now",
            )
            await orch._phase_scan("10.0.0.5", "normal", report)
        return report

    async def test_finding_carries_its_discovery_chain(self, orch, authorized):
        report = await self._scan(
            orch,
            [{"target_ip": "10.0.0.5", "port": 445, "product": "Samba",
              "name": "microsoft-ds", "version": "4.1", "protocol": "tcp"}],
            [{"id": "CVE-2017-0144", "cvss_score": 9.8, "description": "eternalblue"}],
        )

        finding = report.findings[0]
        assert finding.entity_id
        assert report.entities.attack_path(finding.entity_id) == (
            "10.0.0.5 → 10.0.0.5 → 445/tcp microsoft-ds → CVE-2017-0144"
        )

    async def test_two_services_on_one_host_share_the_host_node(self, orch, authorized):
        from core.entities import EntityType

        report = await self._scan(
            orch,
            [
                {"target_ip": "10.0.0.5", "port": 445, "product": "Samba",
                 "name": "microsoft-ds", "version": "4.1", "protocol": "tcp"},
                {"target_ip": "10.0.0.5", "port": 22, "product": "OpenSSH",
                 "name": "ssh", "version": "8.2", "protocol": "tcp"},
            ],
            [{"id": "CVE-X", "cvss_score": 5.0, "description": ""}],
        )

        hosts = report.entities.by_type(EntityType.IP_ADDRESS)
        services = report.entities.by_type(EntityType.SERVICE)
        assert len(hosts) == 1
        assert len(services) == 2
        assert {s.parent_id for s in services} == {hosts[0].id}

    async def test_report_dict_exposes_the_graph_and_paths(self, orch, authorized):
        report = await self._scan(
            orch,
            [{"target_ip": "10.0.0.5", "port": 445, "product": "Samba",
              "name": "microsoft-ds", "version": "4.1", "protocol": "tcp"}],
            [{"id": "CVE-2017-0144", "cvss_score": 9.8, "description": ""}],
        )
        payload = report.to_dict()

        assert payload["entities"]["stats"]["vulnerability"] == 1
        assert payload["findings"][0]["attack_path"].endswith("CVE-2017-0144")

    async def test_scan_without_cves_still_records_the_surface(self, orch, authorized):
        from core.entities import EntityType

        report = await self._scan(
            orch,
            [{"target_ip": "10.0.0.5", "port": 9, "name": "discard",
              "version": "", "protocol": "tcp"}],
            [],
        )

        assert report.findings == []
        assert report.entities.by_type(EntityType.SERVICE)
        assert report.entities.by_type(EntityType.VULNERABILITY) == []
