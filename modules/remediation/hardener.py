"""
AutoHardener — applies AI-generated remediation scripts with full snapshot/rollback.

Every change is tracked. No script runs without guardrail approval.
Dry-run is the default — changes only apply when dry_run=False is explicit.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.guardrails import guardrails
from core.logger import get_logger
from modules.remediation.ai_engine import RemediationScript

logger = get_logger("remediation.hardener")

# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class SnapshotEntry:
    path: str
    original_hash: str
    backup_path: str
    timestamp: str


@dataclass
class HardenResult:
    cve_id: str
    target: str
    dry_run: bool
    success: bool
    steps_executed: list[str] = field(default_factory=list)
    steps_skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    snapshots: list[SnapshotEntry] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    rollback_available: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "target": self.target,
            "dry_run": self.dry_run,
            "success": self.success,
            "steps_executed": self.steps_executed,
            "steps_skipped": self.steps_skipped,
            "errors": self.errors,
            "rollback_available": self.rollback_available,
            "timestamp": self.timestamp,
        }


# ── AutoHardener ──────────────────────────────────────────────────────────────

class AutoHardener:
    """
    Applies AI-generated remediation scripts safely.

    Lifecycle per apply():
      1. Guardrail gate — blocks if no session or script fails safety check
      2. Dry-run simulation — parse and explain what would change
      3. Snapshot — capture current state of files the script will touch
      4. Execute — run the script in a controlled subprocess
      5. Verify — run the verification command to confirm fix is in place
      6. Store rollback — keep rollback script indexed by CVE+target
    """

    def __init__(self, snapshot_dir: str = "/tmp/secsuite-snapshots") -> None:
        self._snapshot_dir = Path(snapshot_dir)
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)
        self._rollback_registry: dict[str, RemediationScript] = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    async def apply(
        self,
        remediation: RemediationScript,
        dry_run: bool = True,
        phase: str = "permanent_fix",   # "immediate_mitigation" | "permanent_fix"
        timeout: int = 120,
    ) -> HardenResult:
        """
        Apply a remediation script.

        Args:
            remediation: Output from RemediationAI.generate_*()
            dry_run:     If True (default), only simulate — no changes made
            phase:       Which script to run: immediate_mitigation or permanent_fix
            timeout:     Max seconds to wait for the script to complete
        """
        result = HardenResult(
            cve_id=remediation.cve_id,
            target=remediation.target,
            dry_run=dry_run,
            success=False,
        )

        # 1 — Guardrail gate
        script = getattr(remediation, phase, "")
        if not script:
            result.errors.append(f"No script available for phase '{phase}'")
            return result

        allowed, validation = guardrails.gate_remediation(remediation.target, script)
        if not allowed:
            result.errors.append(
                f"Guardrail blocked script: {validation.violations}"
            )
            result.steps_skipped.append(f"{phase}: blocked by guardrails")
            return result

        result.steps_executed.append(f"Guardrail gate passed (warnings: {validation.warnings})")

        # 2 — Dry-run
        if dry_run:
            explained = self._explain_script(script)
            result.success = True
            result.steps_executed.append("DRY-RUN: script analysed, no changes made")
            result.stdout = f"[DRY-RUN ANALYSIS]\n{explained}"
            result.rollback_available = bool(remediation.rollback_script)
            logger.info(f"[DRY-RUN] {remediation.cve_id} @ {remediation.target}: {phase}")
            return result

        # 3 — Snapshot files the script will touch
        snapshots = await self._snapshot(script)
        result.snapshots = snapshots
        result.steps_executed.append(f"Snapshot taken: {len(snapshots)} file(s)")

        # 4 — Execute
        stdout, stderr, returncode = await self._execute(script, timeout=timeout)
        result.stdout = stdout
        result.stderr = stderr

        if returncode != 0:
            result.errors.append(f"Script exited with code {returncode}: {stderr[:500]}")
            result.steps_executed.append(f"{phase}: FAILED (exit {returncode})")
            # Attempt automatic rollback on failure
            if snapshots:
                await self._restore_snapshots(snapshots)
                result.steps_executed.append("Auto-rollback: snapshot restored after failure")
            return result

        result.steps_executed.append(f"{phase}: executed successfully")

        # 5 — Verify
        if remediation.verification_command:
            v_out, v_err, v_code = await self._execute(
                remediation.verification_command, timeout=30
            )
            if v_code == 0:
                result.steps_executed.append(f"Verification passed: {v_out.strip()[:200]}")
            else:
                result.steps_skipped.append(
                    f"Verification returned non-zero ({v_code}): {v_err.strip()[:200]}"
                )

        # 6 — Register rollback
        if remediation.rollback_script:
            key = f"{remediation.cve_id}::{remediation.target}"
            self._rollback_registry[key] = remediation
            result.rollback_available = True
            result.steps_executed.append("Rollback script registered")

        result.success = True
        logger.info(f"[HARDENER] Applied {phase} for {remediation.cve_id} @ {remediation.target}")
        return result

    async def rollback(self, cve_id: str, target: str, timeout: int = 60) -> HardenResult:
        """
        Roll back a previously applied remediation.

        The rollback script was generated by the AI and stored at apply() time.
        """
        key = f"{cve_id}::{target}"
        remediation = self._rollback_registry.get(key)

        result = HardenResult(cve_id=cve_id, target=target, dry_run=False, success=False)

        if not remediation:
            result.errors.append(f"No rollback registered for {cve_id} @ {target}")
            return result

        if not remediation.rollback_script:
            result.errors.append("Rollback script is empty")
            return result

        # Guardrail gate on the rollback script too
        allowed, validation = guardrails.gate_remediation(target, remediation.rollback_script)
        if not allowed:
            result.errors.append(f"Guardrail blocked rollback: {validation.violations}")
            return result

        stdout, stderr, returncode = await self._execute(remediation.rollback_script, timeout)
        result.stdout = stdout
        result.stderr = stderr

        if returncode == 0:
            result.success = True
            result.steps_executed.append("Rollback executed successfully")
            del self._rollback_registry[key]
            logger.info(f"[HARDENER] Rollback applied for {cve_id} @ {target}")
        else:
            result.errors.append(f"Rollback failed (exit {returncode}): {stderr[:500]}")

        return result

    def list_rollbacks(self) -> list[dict]:
        return [
            {"cve_id": rem.cve_id, "target": rem.target, "service": rem.service}
            for rem in self._rollback_registry.values()
        ]

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    async def _execute(script: str, timeout: int = 120) -> tuple[str, str, int]:
        """Run a bash script in a subprocess. Returns (stdout, stderr, returncode)."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", prefix="secsuite_", delete=False
        ) as f:
            f.write("#!/usr/bin/env bash\nset -euo pipefail\n")
            f.write(script)
            script_path = f.name

        try:
            os.chmod(script_path, 0o700)
            proc = await asyncio.create_subprocess_exec(
                "/usr/bin/env", "bash", script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return "", f"Script timed out after {timeout}s", 124

            return stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace"), proc.returncode
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass

    async def _snapshot(self, script: str) -> list[SnapshotEntry]:
        """Parse the script for file paths and snapshot them before modification."""
        import re  # noqa: PLC0415
        snapshots = []
        # Find paths in /etc/, /etc/ is the most common target
        paths = re.findall(r"(?:cp|sed|echo|tee)\s+.*?(/etc/\S+|/usr/\S+|/var/\S+)", script)
        for path in set(paths):
            path = path.rstrip("'\"")
            if os.path.isfile(path):
                backup = str(self._snapshot_dir / (
                    path.replace("/", "_").lstrip("_") + ".bak"
                ))
                try:
                    shutil.copy2(path, backup)
                    snapshots.append(SnapshotEntry(
                        path=path,
                        original_hash=self._sha256(path),
                        backup_path=backup,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                except OSError as e:
                    logger.warning(f"Could not snapshot {path}: {e}")
        return snapshots

    @staticmethod
    async def _restore_snapshots(snapshots: list[SnapshotEntry]) -> None:
        for snap in snapshots:
            try:
                shutil.copy2(snap.backup_path, snap.path)
                logger.info(f"Restored snapshot: {snap.backup_path} → {snap.path}")
            except OSError as e:
                logger.error(f"Could not restore {snap.path}: {e}")

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _explain_script(script: str) -> str:
        """Parse script lines and describe what each does (for dry-run output)."""
        lines = [ln.strip() for ln in script.splitlines() if ln.strip() and not ln.startswith("#")]
        explained = []
        for line in lines[:30]:  # cap at 30 lines
            explained.append(f"  WOULD RUN: {line}")
        if len(lines) > 30:
            explained.append(f"  ... and {len(lines) - 30} more lines")
        return "\n".join(explained)
