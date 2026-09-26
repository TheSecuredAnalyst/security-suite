"""Enrich a correlate run with CVE findings.

The OSINT ``correlate`` module set discovers services but does not look up their
vulnerabilities, so the vulnerability-based correlation rules have nothing to
fire on. This runs a CVE lookup over the discovered services and returns a
``ScanResult`` of VULNERABILITY findings that the graph builder then hangs off
each service — turning "port 445 is open" into "port 445 → CVE-2017-0144".

The NVD lookup is injected (``lookup=``) so the pure shaping logic can be tested
without touching the network.
"""

from __future__ import annotations

from typing import Any, Protocol

from core.logger import get_logger
from core.models import ScanResult, Severity, Target

logger = get_logger("correlation.enrich")

CVE_SOURCE_MODULE = "vulnscan.cve_lookup"


class _Lookup(Protocol):
    async def lookup(
        self, product: str, version: str = "", service_name: str = ""
    ) -> list[dict[str, Any]]:
        """Return CVE dicts for a product/version (the CVELookup interface)."""


def cvss_to_severity(score: float) -> Severity:
    """Map a CVSS base score to the finding severity scale."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def extract_services(results: list[ScanResult]) -> list[dict[str, Any]]:
    """Pull identifiable services (those with a product) from port-scan results."""
    services: list[dict[str, Any]] = []
    for result in results:
        if "port_scan" not in (result.module or "") and not (result.module or "").endswith(".ports"):
            continue
        for svc in result.raw_data.get("services", []) or []:
            if not isinstance(svc, dict):
                continue
            product = (svc.get("product") or "").strip()
            if not product:
                continue
            services.append(
                {
                    "product": product,
                    "version": (svc.get("version") or "").strip(),
                    "service": svc.get("service") or svc.get("name") or "",
                    "port": svc.get("port"),
                }
            )
    return services


async def enrich_with_cves(
    target: str,
    results: list[ScanResult],
    *,
    lookup: _Lookup | None = None,
    max_services: int = 10,
) -> ScanResult | None:
    """Look up CVEs for discovered services; return a VULNERABILITY ScanResult.

    Returns None when there is nothing to add. Each finding carries the service
    port so the graph builder can nest the CVE under the right service.
    """
    services = extract_services(results)
    if not services:
        return None

    if lookup is None:
        from modules.vulnscan import CVELookup

        lookup = CVELookup(max_results=5)

    cve_result = ScanResult(target=Target.from_string(target), module=CVE_SOURCE_MODULE)
    seen: set[tuple[str, str]] = set()
    queried = 0

    for svc in services:
        key = (svc["product"], svc["version"])
        if key in seen:
            continue
        seen.add(key)
        if queried >= max_services:
            break
        queried += 1

        try:
            cves = await lookup.lookup(svc["product"], svc["version"], svc.get("service", ""))
        except Exception as exc:  # a lookup failure must not sink the whole run
            logger.warning("CVE lookup failed for %s %s: %s", svc["product"], svc["version"], exc)
            continue

        for cve in cves or []:
            cve_id = cve.get("id") or cve.get("cve_id") or ""
            if not cve_id:
                continue
            cvss = _to_float(cve.get("cvss_score", cve.get("cvss", 0)))
            refs = cve.get("references")
            cve_result.add_finding(
                title=f"{cve_id} ({svc['product']} {svc['version']})".strip(),
                description=cve.get("description", "") or cve_id,
                severity=cvss_to_severity(cvss),
                data={
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "product": svc["product"],
                    "version": svc["version"],
                    "port": svc.get("port"),
                },
                references=refs if isinstance(refs, list) else [],
            )

    return cve_result if cve_result.findings else None
