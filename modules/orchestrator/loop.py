"""
RedBlueOrchestrator — the autonomous security loop.

Phases:
  RED-1  Scan (nmap + CVE lookup + risk scoring)
  RED-2  Exploit confirmation (Metasploit check-only mode)
  RED-3  ATT&CK tagging (MITRE mapper)
  BLUE-1 Threat hunt (were we already hit before we found this?)
  BLUE-2 AI remediation generation (Ollama → validated scripts)
  BLUE-3 Apply hardening (dry-run or live, with snapshot/rollback)
  BLUE-4 Verify closure (re-run exploit check, confirm NOT_EXPLOITABLE)

Modes:
  recon_only          — RED-1 only (scan + CVE lookup)
  confirm_only        — RED-1 + RED-2 (scan + exploit check, no blue team)
  confirm_and_plan    — Full red + AI-generated remediation plan (dry-run only)
  full_auto           — Full loop with automated remediation applied

All modes require a valid EngagementSession with matching ROE.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.db import insert_remediation, upsert_finding, upsert_run
from core.guardrails import guardrails
from core.logger import get_logger
from core.models import Target
from modules.exploit_engine.runner import ExploitResult, ExploitRunner
from modules.mitre.mapper import MITREMapper
from modules.remediation.ai_engine import MAX_RETRIES, RemediationAI, RemediationScript
from modules.remediation.hardener import AutoHardener, HardenResult
from modules.vulnscan import CVELookup, NetworkScanner
from modules.vulnscan.risk_scorer import RiskScorer

logger = get_logger("orchestrator.loop")

VALID_MODES = {"recon_only", "confirm_only", "confirm_and_plan", "full_auto"}


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class LoopFinding:
    """Enriched finding from the full red-blue loop."""
    ip: str
    port: int
    service: str
    version: str
    cve_id: str
    cvss_score: float = 0.0
    exploit_status: str = "NOT_CHECKED"     # CONFIRMED | NOT_EXPLOITABLE | UNKNOWN | BLOCKED
    attack_tags: list[dict] = field(default_factory=list)
    already_exploited: bool = False         # Threat hunt result
    hunt_evidence: list[str] = field(default_factory=list)
    remediation: RemediationScript | None = None
    harden_result: HardenResult | None = None
    verified_closed: bool = False


@dataclass
class LoopReport:
    """Complete report from an autonomous security loop run."""
    target: str
    mode: str
    operator: str
    engagement_id: str
    session_id: str
    started_at: str
    completed_at: str = ""
    scan_summary: dict = field(default_factory=dict)
    risk_score: int = 0
    risk_color: str = "UNKNOWN"
    total_hosts: int = 0
    total_services: int = 0
    total_cves: int = 0
    confirmed_exploitable: int = 0
    already_exploited: int = 0
    remediations_generated: int = 0
    remediations_applied: int = 0
    verified_closed: int = 0
    findings: list[LoopFinding] = field(default_factory=list)
    audit_log: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "operator": self.operator,
            "engagement_id": self.engagement_id,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "risk_score": self.risk_score,
            "risk_color": self.risk_color,
            "summary": {
                "hosts": self.total_hosts,
                "services": self.total_services,
                "cves": self.total_cves,
                "confirmed_exploitable": self.confirmed_exploitable,
                "already_exploited": self.already_exploited,
                "remediations_generated": self.remediations_generated,
                "remediations_applied": self.remediations_applied,
                "verified_closed": self.verified_closed,
            },
            "findings": [
                {
                    "ip": f.ip,
                    "port": f.port,
                    "service": f.service,
                    "version": f.version,
                    "cve_id": f.cve_id,
                    "cvss_score": f.cvss_score,
                    "exploit_status": f.exploit_status,
                    "attack_tags": f.attack_tags,
                    "already_exploited": f.already_exploited,
                    "hunt_evidence": f.hunt_evidence,
                    "remediation_safe": f.remediation.safe if f.remediation else None,
                    "remediation_explanation": f.remediation.explanation if f.remediation else None,
                    "harden_applied": bool(f.harden_result and f.harden_result.success),
                    "verified_closed": f.verified_closed,
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }


# ── Orchestrator ───────────────────────────────────────────────────────────────

class RedBlueOrchestrator:
    """
    Autonomous security loop controller.

    Requires an active EngagementSession before any method can run.
    All exploit and remediation operations are gated through guardrails.
    """

    def __init__(
        self,
        msf_host: str = "127.0.0.1",
        msf_port: int = 55553,
        msf_password: str = "",
        ollama_host: str = "http://localhost:11434",
        ollama_model: str = "llama3.1:latest",
        output_dir: str = "/tmp/secsuite-loop",
    ) -> None:
        self._exploit_runner = ExploitRunner(
            msf_host=msf_host, msf_port=msf_port, msf_password=msf_password,
        )
        self._remediation_ai = RemediationAI(model=ollama_model, ollama_host=ollama_host)
        self._hardener = AutoHardener(snapshot_dir=f"{output_dir}/snapshots")
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    async def run(
        self,
        target: str,
        mode: str = "confirm_only",
        scan_profile: str = "normal",
        os_hint: str = "Linux",
        max_exploit_concurrent: int = 5,
    ) -> LoopReport:
        """
        Execute the red-blue loop against a target.

        Args:
            target:                IP, CIDR, hostname, or range
            mode:                  recon_only | confirm_only | confirm_and_plan | full_auto
            scan_profile:          Scan intensity: quick | normal | full | stealth
            os_hint:               OS family for AI remediation prompts
            max_exploit_concurrent: Max parallel Metasploit check() calls
        """
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Choose from: {VALID_MODES}")

        session = guardrails.active_session()
        if not session:
            raise PermissionError(
                "No active engagement session. "
                "Call guardrails.create_session() before running the loop."
            )
        if session.is_expired():
            raise PermissionError("Engagement session has expired. Create a new session.")

        report = LoopReport(
            target=target,
            mode=mode,
            operator=session.operator,
            engagement_id=session.engagement_id,
            session_id=session.session_id,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        logger.info(f"[LOOP] Starting {mode} loop: {target} "
                    f"(operator: {session.operator}, engagement: {session.engagement_id})")

        # ── Phase RED-1: Scan + CVE lookup ────────────────────────────────────
        cve_findings = await self._phase_scan(target, scan_profile, report)
        if not cve_findings:
            report.completed_at = datetime.now(timezone.utc).isoformat()
            return report

        if mode == "recon_only":
            report.completed_at = datetime.now(timezone.utc).isoformat()
            report.audit_log = guardrails.get_audit_log()
            self._write_report(report)
            return report

        # ── Phase RED-2: Exploit confirmation ─────────────────────────────────
        await self._phase_exploit_check(cve_findings, report, max_exploit_concurrent)

        if mode == "confirm_only":
            report.completed_at = datetime.now(timezone.utc).isoformat()
            report.audit_log = guardrails.get_audit_log()
            self._write_report(report)
            return report

        # Only process confirmed findings for blue team phases.
        # Deduplicate by (ip, port) — multiple CVEs on the same exposed port
        # need only one remediation; pick the highest-CVSS representative.
        _seen: dict[tuple, LoopFinding] = {}
        for f in report.findings:
            if f.exploit_status != "CONFIRMED":
                continue
            key = (f.ip, f.port)
            if key not in _seen or f.cvss_score > _seen[key].cvss_score:
                _seen[key] = f
        confirmed = list(_seen.values())

        if not confirmed:
            logger.info("[LOOP] No confirmed exploitable findings — skipping blue team phases")
            report.completed_at = datetime.now(timezone.utc).isoformat()
            report.audit_log = guardrails.get_audit_log()
            self._write_report(report)
            return report

        logger.info(f"[LOOP] {len(confirmed)} unique confirmed exposures for blue team phases")

        # ── Phase BLUE-1: Threat hunt ──────────────────────────────────────────
        await self._phase_threat_hunt(confirmed, report)

        # ── Phase BLUE-2: AI remediation generation ───────────────────────────
        await self._phase_generate_remediations(confirmed, report, os_hint)

        if mode == "confirm_and_plan":
            report.completed_at = datetime.now(timezone.utc).isoformat()
            report.audit_log = guardrails.get_audit_log()
            self._write_report(report)
            return report

        # ── Phase BLUE-3: Apply hardening (full_auto only) ────────────────────
        await self._phase_apply_hardening(confirmed, report)

        # ── Phase BLUE-4: Verify closure ──────────────────────────────────────
        await self._phase_verify_closure(confirmed, report)

        report.completed_at = datetime.now(timezone.utc).isoformat()
        report.audit_log = guardrails.get_audit_log()
        self._write_report(report)
        logger.info(f"[LOOP] Completed. Confirmed: {report.confirmed_exploitable}, "
                    f"Remediated: {report.remediations_applied}, "
                    f"Verified closed: {report.verified_closed}")
        return report

    # ── Phases ─────────────────────────────────────────────────────────────────

    async def _phase_scan(self, target: str, profile: str, report: LoopReport) -> list[dict]:
        """RED-1: Network scan + CVE lookup per service."""
        logger.info(f"[RED-1] Scanning {target} (profile: {profile})")
        try:
            scanner = NetworkScanner(profile=profile, max_parallel=25)
            scan_target = Target(value=target, target_type="ip" if "/" not in target else "ip")
            scan_result = await scanner.run(scan_target)

            # Collect services from findings.
            # NetworkScanner packs services inside finding.data['services'] as a list,
            # each entry: {target_ip, port, protocol, name, product, version, extrainfo}
            services: list[dict] = []
            ips: set[str] = set()
            for finding in scan_result.findings:
                svc_list = finding.data.get("services", [])
                for svc in svc_list:
                    ip = svc.get("target_ip", "")
                    if ip:
                        ips.add(ip)
                    # Normalise field names for the rest of the pipeline
                    services.append({
                        "ip":      ip,
                        "port":    svc.get("port", 0),
                        "service": svc.get("product") or svc.get("name", ""),
                        "name":    svc.get("name", ""),
                        "version": svc.get("version", ""),
                    })

            report.total_hosts = len(ips)
            report.total_services = len(services)
            logger.info(f"[RED-1] Found {len(ips)} hosts, {len(services)} services")

            # CVE lookup per unique service
            lookup = CVELookup(max_results=5)
            cve_findings: list[dict] = []

            async def _enrich(svc: dict) -> None:
                product = svc.get("service", "")
                version = svc.get("version", "")
                if not product:
                    return
                try:
                    cves = await lookup.lookup(product, version)
                    for cve in cves:
                        raw_score = cve.get("cvss_score", 0)
                        try:
                            cvss = float(raw_score)
                        except (TypeError, ValueError):
                            cvss = 0.0
                        lf = LoopFinding(
                            ip=svc.get("ip", target),
                            port=int(svc.get("port", 0)),
                            service=product,
                            version=version,
                            cve_id=cve.get("id") or cve.get("cve_id", ""),
                            cvss_score=cvss,
                        )
                        # ATT&CK tagging
                        tags = MITREMapper.tag_finding(
                            cve.get("description", ""),
                            "",
                            cve_ids=[lf.cve_id],
                            service=svc.get("name", product),
                            port=lf.port,
                        )
                        lf.attack_tags = [t.to_dict() for t in tags]
                        report.findings.append(lf)
                        cve_findings.append(svc)
                except Exception as exc:
                    logger.warning(f"[RED-1] CVE lookup failed for {product}: {exc}")

            await asyncio.gather(*[_enrich(s) for s in services])

            report.total_cves = len(report.findings)
            all_cves = [{"cvss_score": f.cvss_score} for f in report.findings]
            # RiskScorer.score() returns (int, label) — unpack both
            score_val, score_label = RiskScorer.score(all_cves)
            report.risk_score = score_val
            report.risk_color = score_label

            logger.info(f"[RED-1] {report.total_cves} CVEs found, risk score: {report.risk_score}")
            return cve_findings

        except Exception as exc:
            err = f"RED-1 scan failed: {exc}"
            report.errors.append(err)
            logger.error(err)
            return []

    async def _phase_exploit_check(
        self, cve_findings: list[dict], report: LoopReport, max_concurrent: int
    ) -> None:
        """
        RED-2: Metasploit check-only confirmation.

        Strategy:
          1. CVE-based check  — look up CVE ID in our module map, run check()
          2. Service-based fallback — when CVE has no module, try service+port
             discovery checks (scanner/login modules, version scanners)
        Deduplicates checks per (ip, port) so we don't fire the same module twice.
        """
        logger.info(f"[RED-2] Exploit checking {len(report.findings)} findings "
                    f"(+ service-based fallback)")
        sem = asyncio.Semaphore(max_concurrent)
        checked_pairs: set[tuple] = set()          # (ip, port, module_path)
        cve_confirmed_pairs: set[tuple] = set()    # (ip, port) already counted

        async def _check_cve(finding: LoopFinding) -> None:
            if not finding.cve_id:
                return
            async with sem:
                result = await self._exploit_runner.check_cve(
                    finding.cve_id, finding.ip, finding.port
                )
                finding.exploit_status = result.status
                if result.attack_tags:
                    finding.attack_tags = result.attack_tags
                if result.status == "CONFIRMED":
                    pair_key = (finding.ip, finding.port)
                    if pair_key not in cve_confirmed_pairs:
                        cve_confirmed_pairs.add(pair_key)
                        report.confirmed_exploitable += 1
                    logger.warning(
                        f"[RED-2] CONFIRMED EXPLOITABLE: {finding.cve_id} @ "
                        f"{finding.ip}:{finding.port}"
                    )

        await asyncio.gather(*[_check_cve(f) for f in report.findings])

        # ── Service-based fallback for services with no CVE module hits ────────
        # Collect unique (ip, port, service_name) tuples where all CVE checks
        # returned NO_MODULE — these services haven't been probed at all.
        no_module_services: dict[tuple, str] = {}
        for f in report.findings:
            if f.exploit_status == "NO_MODULE":
                key = (f.ip, f.port)
                no_module_services[key] = f.service

        if no_module_services:
            logger.info(f"[RED-2] Service-fallback: checking {len(no_module_services)} "
                        "unique (ip,port) pairs with scanner modules")

            # Track confirmed (ip, port) pairs so we only count each once
            confirmed_pairs: set[tuple] = set()

            async def _check_service(ip: str, port: int, service: str) -> None:
                async with sem:
                    results = await self._exploit_runner.check_service(service, ip, port)
                    for r in results:
                        key = (ip, port, r.module_path)
                        if key in checked_pairs:
                            continue
                        checked_pairs.add(key)
                        if r.status == "CONFIRMED":
                            # Only increment confirmed_exploitable once per (ip, port)
                            pair_key = (ip, port)
                            if pair_key not in confirmed_pairs:
                                confirmed_pairs.add(pair_key)
                                report.confirmed_exploitable += 1
                            # Update all findings for this (ip, port)
                            for f in report.findings:
                                if f.ip == ip and f.port == port:
                                    f.exploit_status = "CONFIRMED"
                                    if r.attack_tags:
                                        f.attack_tags = r.attack_tags
                            logger.warning(
                                f"[RED-2] SERVICE-CHECK CONFIRMED: {service} @ "
                                f"{ip}:{port} via {r.module_path}"
                            )

            await asyncio.gather(*[
                _check_service(ip, port, svc)
                for (ip, port), svc in no_module_services.items()
            ])

        logger.info(f"[RED-2] Confirmed exploitable: {report.confirmed_exploitable}")

    async def _phase_threat_hunt(
        self, confirmed: list[LoopFinding], report: LoopReport
    ) -> None:
        """
        BLUE-1: Check if confirmed vulnerabilities show signs of prior exploitation.
        Inspects local log files for IOC patterns associated with each CVE.
        """
        logger.info(f"[BLUE-1] Threat hunting for {len(confirmed)} confirmed findings")

        IOC_PATTERNS: dict[str, list[str]] = {
            "CVE-2017-0144": [
                r"DOUBLEPULSAR", r"ms17-010", r"eternal", r"wannacry",
            ],
            "CVE-2021-44228": [
                r"\$\{jndi:", r"log4j", r"log4shell", r"ldap://",
            ],
            "CVE-2019-0708": [
                r"bluekeep", r"ms_rdp", r"CVE-2019-0708",
            ],
            "CVE-2021-26855": [
                r"ProxyLogon", r"autodiscover\.json", r"X-Rps-CAT",
            ],
        }

        LOG_FILES = [
            "/var/log/syslog", "/var/log/auth.log", "/var/log/messages",
            "/var/log/kern.log", "/var/log/nginx/access.log",
            "/var/log/apache2/access.log", "/var/log/httpd/access_log",
        ]

        import re  # noqa: PLC0415

        for finding in confirmed:
            patterns = IOC_PATTERNS.get(finding.cve_id, [])
            if not patterns:
                continue
            for log_path in LOG_FILES:
                if not os.path.isfile(log_path):
                    continue
                try:
                    with open(log_path, errors="replace") as f:
                        for i, line in enumerate(f):
                            for pat in patterns:
                                if re.search(pat, line, re.IGNORECASE):
                                    finding.already_exploited = True
                                    finding.hunt_evidence.append(
                                        f"{log_path}:{i+1}: {line.strip()[:200]}"
                                    )
                                    if len(finding.hunt_evidence) >= 5:
                                        break
                            if len(finding.hunt_evidence) >= 5:
                                break
                except OSError:
                    pass

            if finding.already_exploited:
                report.already_exploited += 1
                logger.critical(
                    f"[BLUE-1] POSSIBLE PRIOR EXPLOITATION: {finding.cve_id} @ {finding.ip} "
                    f"— {len(finding.hunt_evidence)} IOC hit(s) in logs"
                )

    # Maximum unique (ip, port) exposures to generate remediations for per run.
    # Keeps Ollama calls bounded even on large subnets.
    _MAX_REMEDIATION_TARGETS = 5

    async def _phase_generate_remediations(
        self, confirmed: list[LoopFinding], report: LoopReport, os_hint: str
    ) -> None:
        """BLUE-2: Generate AI remediation scripts for each confirmed finding.

        Capped at _MAX_REMEDIATION_TARGETS highest-CVSS unique exposures to
        bound AI inference time on large subnet scans.
        """
        # Sort by CVSS descending, take top N
        prioritised = sorted(confirmed, key=lambda f: f.cvss_score, reverse=True)
        capped = prioritised[: self._MAX_REMEDIATION_TARGETS]
        skipped = len(confirmed) - len(capped)
        if skipped:
            logger.info(
                f"[BLUE-2] Capping remediation to top {self._MAX_REMEDIATION_TARGETS} "
                f"(skipping {skipped} lower-priority exposures)"
            )
        logger.info(f"[BLUE-2] Generating remediations for {len(capped)} findings")

        async def _gen(finding: LoopFinding) -> None:
            logger.info(f"[AI] Generating remediation for {finding.service}-{finding.port} "
                        f"@ {finding.ip} (attempt 1/{MAX_RETRIES + 1})")
            try:
                # For service-exposure findings (cve_id starts with EXPOSED- or is blank),
                # use the service-specific prompt which gives the AI better context.
                if not finding.cve_id or finding.cve_id.startswith("EXPOSED-"):
                    rem = await self._remediation_ai.generate_from_service(
                        service=finding.service,
                        version=finding.version,
                        target=finding.ip,
                        port=finding.port,
                        issue=f"{finding.service} port {finding.port} is exposed on the LAN "
                              f"without firewall restriction (confirmed via TCP probe)",
                        os_hint=os_hint,
                    )
                else:
                    # Real CVE — use full exploit context
                    exploit_result = ExploitResult(
                        cve_id=finding.cve_id,
                        target=finding.ip,
                        port=finding.port,
                        module_path=finding.service,
                        status="CONFIRMED",
                        attack_tags=finding.attack_tags,
                    )
                    rem = await self._remediation_ai.generate_from_exploit(exploit_result, os_hint)

                finding.remediation = rem
                if rem.safe:
                    report.remediations_generated += 1
                    logger.info(f"[AI] Remediation script passed safety checks for "
                                f"{finding.service}-{finding.port}")
                    print(f"\n  SAFE: True  |  WARNINGS: {rem.warnings}")
                    print(f"\n  EXPLANATION:\n  {rem.explanation}")
                    print(f"\n  IMMEDIATE MITIGATION:\n{rem.immediate_mitigation}")
                    print(f"\n  PERMANENT FIX:\n{rem.permanent_fix}")
                    print(f"\n  ROLLBACK:\n{rem.rollback_script}")
                    print(f"\n  VERIFY:\n  {rem.verification_command}")
                else:
                    logger.warning(
                        f"[AI] Remediation for {finding.cve_id} failed safety check: "
                        f"{rem.validation.violations if rem.validation else 'unknown'}"
                    )
            except Exception as exc:
                logger.error(f"[BLUE-2] Remediation gen failed for {finding.cve_id}: {exc}")

        await asyncio.gather(*[_gen(f) for f in capped])

    async def _phase_apply_hardening(
        self, confirmed: list[LoopFinding], report: LoopReport
    ) -> None:
        """BLUE-3: Apply safe remediations with dry_run=False."""
        logger.info(f"[BLUE-3] Applying hardening for {report.remediations_generated} findings")
        for finding in confirmed:
            if not finding.remediation or not finding.remediation.safe:
                continue
            try:
                # Apply immediate mitigation first, then permanent fix
                await self._hardener.apply(
                    finding.remediation, dry_run=False, phase="immediate_mitigation"
                )
                h2 = await self._hardener.apply(
                    finding.remediation, dry_run=False, phase="permanent_fix"
                )
                finding.harden_result = h2
                if h2.success:
                    report.remediations_applied += 1
                    logger.info(
                        f"[BLUE-3] Hardening applied for {finding.cve_id} @ {finding.ip}"
                    )
                else:
                    logger.error(
                        f"[BLUE-3] Hardening FAILED for {finding.cve_id}: {h2.errors}"
                    )
            except Exception as exc:
                logger.error(f"[BLUE-3] Apply error for {finding.cve_id}: {exc}")

    async def _phase_verify_closure(
        self, confirmed: list[LoopFinding], report: LoopReport
    ) -> None:
        """BLUE-4: Re-run exploit check to confirm vulnerability is now closed."""
        logger.info("[BLUE-4] Verifying closure")
        for finding in confirmed:
            if not (finding.harden_result and finding.harden_result.success):
                continue
            try:
                recheck = await self._exploit_runner.check_cve(
                    finding.cve_id, finding.ip, finding.port
                )
                if recheck.status == "NOT_EXPLOITABLE":
                    finding.verified_closed = True
                    report.verified_closed += 1
                    logger.info(
                        f"[BLUE-4] VERIFIED CLOSED: {finding.cve_id} @ "
                        f"{finding.ip}:{finding.port}"
                    )
                else:
                    logger.warning(
                        f"[BLUE-4] Still exploitable after remediation: "
                        f"{finding.cve_id} @ {finding.ip} (status: {recheck.status})"
                    )
            except Exception as exc:
                logger.error(f"[BLUE-4] Verify error for {finding.cve_id}: {exc}")

    # ── Report writer ──────────────────────────────────────────────────────────

    def _write_report(self, report: LoopReport) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = os.path.join(
            self._output_dir,
            f"loop_{report.engagement_id}_{ts}.json",
        )
        with open(path, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        logger.info(f"[LOOP] Report written: {path}")

        # Persist to SQLite
        try:
            self._persist_to_db(report, path)
        except Exception as exc:
            logger.warning(f"[LOOP] DB persist failed (non-fatal): {exc}")

        return path

    def _persist_to_db(self, report: LoopReport, report_path: str) -> None:
        """Write run + confirmed findings + remediations to SQLite."""
        # Pass report attributes directly — to_dict() nests counters under "summary"
        # which upsert_run would not find at the top level.
        upsert_run(report.session_id, {
            "id": report.session_id,
            "engagement_id": report.engagement_id,
            "operator": report.operator,
            "target": report.target,
            "mode": report.mode,
            "started_at": report.started_at,
            "completed_at": report.completed_at,
            "risk_score": report.risk_score,
            "risk_color": report.risk_color,
            "total_hosts": report.total_hosts,
            "total_services": report.total_services,
            "total_cves": report.total_cves,
            "confirmed_exploitable": report.confirmed_exploitable,
            "already_exploited": report.already_exploited,
            "remediations_generated": report.remediations_generated,
            "remediations_applied": report.remediations_applied,
            "verified_closed": report.verified_closed,
            "errors": report.errors,
            "report_path": report_path,
        })

        # Persist unique confirmed findings (already deduped by ip+port in the run)
        seen: set[tuple] = set()
        for f in report.findings:
            key = (f.ip, f.port)
            if key in seen or f.exploit_status != "CONFIRMED":
                continue
            seen.add(key)
            fid = upsert_finding(report.session_id, {
                "ip": f.ip,
                "port": f.port,
                "service": f.service,
                "version": f.version,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "exploit_status": f.exploit_status,
                "attack_tags": f.attack_tags,
                "already_exploited": f.already_exploited,
                "hunt_evidence": f.hunt_evidence,
            })
            # Persist remediation if available
            if f.remediation and f.remediation.safe:
                rem = f.remediation
                insert_remediation(report.session_id, fid, {
                    "ip": f.ip,
                    "port": f.port,
                    "service": f.service,
                    "cve_id": f.cve_id,
                    "safe": rem.safe,
                    "explanation": rem.explanation,
                    "immediate_mitigation": rem.immediate_mitigation,
                    "permanent_fix": rem.permanent_fix,
                    "rollback_script": rem.rollback_script,
                    "verification_command": rem.verification_command,
                    "warnings": rem.warnings,
                    "model_used": rem.model_used,
                })
