"""
RemediationAI — Ollama-powered, guardrail-validated remediation script generator.

For each confirmed finding, the AI generates:
  1. An immediate mitigation script (reduce exposure now)
  2. A permanent fix script (address root cause)
  3. A rollback script (undo the fix if it causes problems)
  4. A verification command (confirm the fix worked)

All output passes through GuardrailsEngine.validate_script() before being returned.
Scripts that contain banned patterns are rejected and the model is re-prompted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from core.guardrails import ScriptValidationResult, guardrails
from core.logger import get_logger
from modules.exploit_engine.runner import ExploitResult

logger = get_logger("remediation.ai_engine")

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_MODEL = "llama3.1:latest"   # Best instruction-following of the installed models
MAX_RETRIES = 2                      # Re-prompt if output fails safety check


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class RemediationScript:
    """AI-generated remediation package for a single confirmed finding."""
    cve_id: str
    target: str
    service: str
    version: str
    model_used: str

    immediate_mitigation: str = ""      # Quick block / reduce exposure
    permanent_fix: str = ""             # Root cause fix
    rollback_script: str = ""           # Undo permanent fix
    verification_command: str = ""      # Confirm fix worked
    explanation: str = ""               # Plain-English explanation

    validation: ScriptValidationResult | None = None
    safe: bool = False
    warnings: list[str] = field(default_factory=list)


# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an expert Linux and network security hardening engineer.
Your task: generate precise, executable remediation scripts for confirmed security vulnerabilities.

STRICT OUTPUT RULES — violating any rule makes your output invalid:
1. Output ONLY valid JSON matching the schema below. No explanation before or after the JSON.
2. Scripts must be idempotent (safe to run multiple times).
3. Scripts must include a comment "# BACKUP: <filename> -> <filename>.bak" before any file it modifies.
4. NEVER include: rm -rf, dd, mkfs, fork bombs, curl|bash, shutdown/reboot, iptables -F (without replacement), passwd root.
5. NEVER remove packages — only add, upgrade, or configure them.
6. NEVER stop SSH, networking, or the firewall without providing a replacement rule first.
7. rollback_script must exactly undo what permanent_fix does.
8. verification_command must be a single read-only command (no changes).

JSON SCHEMA:
{
  "immediate_mitigation": "<bash script — reduces exposure within seconds, no reboot needed>",
  "permanent_fix": "<bash script — addresses root cause, may require service restart>",
  "rollback_script": "<bash script — undoes permanent_fix exactly>",
  "verification_command": "<single bash command — confirms the fix is in place>",
  "explanation": "<2-3 sentence plain-English explanation of the vulnerability and the fix>"
}
"""


def _build_prompt(finding: ExploitResult, os_hint: str = "Linux") -> str:
    return f"""\
Confirmed vulnerability:
  CVE: {finding.cve_id}
  Target: {finding.target}:{finding.port}
  Service: {finding.module_path.split('/')[-1].replace('_', ' ')}
  OS: {os_hint}
  Exploit module: {finding.module_path}
  ATT&CK tags: {json.dumps(finding.attack_tags, indent=2)}

Generate remediation JSON following the system prompt rules exactly."""


def _build_service_prompt(service: str, version: str, port: int, issue: str,
                           os_hint: str = "Linux") -> str:
    return f"""\
Security issue (not CVE-specific):
  Service: {service} {version}
  Port: {port}
  Issue: {issue}
  OS: {os_hint}

Generate remediation JSON following the system prompt rules exactly."""


# ── AI engine ─────────────────────────────────────────────────────────────────

class RemediationAI:
    """
    Generates remediation scripts using a local Ollama model.

    All generated scripts are validated by the guardrails engine before being
    returned. If the script fails validation, the model is re-prompted with the
    specific violations as feedback (up to MAX_RETRIES attempts).
    """

    def __init__(self, model: str = DEFAULT_MODEL, ollama_host: str = "http://localhost:11434"):
        # Imported lazily so the rest of the remediation package (dataclasses,
        # the guardrail-gated AutoHardener) can be used without the optional
        # `ollama` dependency installed.
        import ollama  # noqa: PLC0415

        self.model = model
        self._client = ollama.Client(host=ollama_host)

    async def generate_from_exploit(
        self,
        result: ExploitResult,
        os_hint: str = "Linux",
    ) -> RemediationScript:
        """
        Generate remediation scripts for a confirmed exploit finding.

        Args:
            result:   An ExploitResult with status=CONFIRMED
            os_hint:  Target OS family hint (Linux / Windows / FreeBSD)
        """
        if not result.confirmed:
            logger.debug(f"Skipping remediation gen for non-confirmed result: {result.cve_id}")
            return RemediationScript(
                cve_id=result.cve_id, target=result.target,
                service=result.module_path, version="", model_used=self.model,
                explanation="Remediation skipped — vulnerability not confirmed exploitable.",
                safe=False,
            )

        prompt = _build_prompt(result, os_hint)
        return await self._generate(result.cve_id, result.target, result.module_path, "", prompt)

    async def generate_from_service(
        self,
        service: str,
        version: str,
        target: str,
        port: int,
        issue: str,
        os_hint: str = "Linux",
    ) -> RemediationScript:
        """
        Generate remediation scripts for a service misconfiguration (no CVE required).

        Useful for: exposed Redis, weak SSH config, open Telnet, missing TLS, etc.
        """
        prompt = _build_service_prompt(service, version, port, issue, os_hint)
        return await self._generate(f"{service}-{port}", target, service, version, prompt)

    # ── Internal ───────────────────────────────────────────────────────────────

    async def _generate(
        self, cve_id: str, target: str, service: str, version: str, prompt: str
    ) -> RemediationScript:
        script = RemediationScript(
            cve_id=cve_id, target=target, service=service,
            version=version, model_used=self.model,
        )

        current_prompt = prompt
        for attempt in range(MAX_RETRIES + 1):
            try:
                logger.info(f"[AI] Generating remediation for {cve_id} @ {target} "
                            f"(attempt {attempt + 1}/{MAX_RETRIES + 1})")

                raw = self._client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": current_prompt},
                    ],
                    options={"temperature": 0.1},  # Low temp = deterministic, precise output
                )
                content = raw["message"]["content"].strip()

                # Extract JSON (model sometimes wraps in markdown)
                parsed = self._extract_json(content)
                if not parsed:
                    logger.warning(f"[AI] Model output is not valid JSON (attempt {attempt+1})")
                    current_prompt = (
                        f"{prompt}\n\n[PREVIOUS OUTPUT WAS NOT VALID JSON. "
                        "Output ONLY the JSON object with no surrounding text.]"
                    )
                    continue

                # Populate script fields
                script.immediate_mitigation = parsed.get("immediate_mitigation", "")
                script.permanent_fix = parsed.get("permanent_fix", "")
                script.rollback_script = parsed.get("rollback_script", "")
                script.verification_command = parsed.get("verification_command", "")
                script.explanation = parsed.get("explanation", "")

                # Validate all script fields through guardrails
                combined = "\n".join([
                    script.immediate_mitigation,
                    script.permanent_fix,
                    script.rollback_script,
                ])
                validation = guardrails.validate_script(combined)
                script.validation = validation
                script.warnings = validation.warnings

                if validation.safe:
                    script.safe = True
                    logger.info(f"[AI] Remediation script passed safety checks for {cve_id}")
                    return script

                # Script failed — re-prompt with violations as context
                violations_text = "\n".join(f"  - {v}" for v in validation.violations)
                logger.warning(f"[AI] Script failed safety check (attempt {attempt+1}): "
                               f"{validation.violations}")
                current_prompt = (
                    f"{prompt}\n\n"
                    f"[YOUR PREVIOUS OUTPUT FAILED SAFETY VALIDATION. VIOLATIONS:\n"
                    f"{violations_text}\n"
                    "Fix all violations and output corrected JSON only.]"
                )

            except Exception as exc:
                logger.error(f"[AI] Ollama error on attempt {attempt+1}: {exc}")
                script.explanation = f"Remediation generation failed: {exc}"

        # All retries exhausted — return what we have (safe=False)
        script.safe = False
        if script.validation:
            script.explanation = (
                f"AI-generated scripts failed safety validation after {MAX_RETRIES+1} attempts. "
                f"Violations: {script.validation.violations}. "
                "Manual remediation required."
            )
        return script

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        """Extract JSON object from model output (handles markdown code fences)."""
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Extract from code fence
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Find first { ... } block
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return None
