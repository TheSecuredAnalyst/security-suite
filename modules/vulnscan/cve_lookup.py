"""
CVE enrichment via NVD API v2.

Lookup strategy (stops at first non-empty result):

  1. Keyword: "product version"      — best specificity, CVSS >= 4.0, year >= 2015
     1b. Keyword: "product base_ver" — if 1 returns nothing, retry with normalised
         version ("8.4p1" → "8.4", "3.6.2b1" → "3.6.2")
  2. Product-only dual query (concurrent):
       a. keywordSearch=product + cvssV3Severity=CRITICAL  — catches top CRITICAL
          CVEs for the product regardless of age (filtered client-side to >= 2015)
       b. keywordSearch=product + pubStartDate/pubEndDate  — last 120 days of
          any-severity CVEs for recent exposure coverage
     Merge + dedup the two result sets, apply CVSS >= 7.0 floor.
  3. Skip generic service names — http/smtp/https etc. return [] to prevent noise

Year filtering is done CLIENT-SIDE via the CVE ID year prefix (CVE-YYYY-*)
for client-side steps.  The recency query (2b) uses NVD's own pubStartDate/
pubEndDate which have a 120-day maximum range — this is intentional.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timedelta, timezone

import httpx

from core.logger import get_logger

logger = get_logger("vulnscan.cve_lookup")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "UNKNOWN": 1}

# Only accept CVEs published this year or later (extracted from CVE-YYYY- prefix)
_MIN_CVE_YEAR = 2015

# Minimum CVSS for product+version queries
_MIN_CVSS_WITH_VERSION = 4.0

# Minimum CVSS for product-only queries (stricter, more noise risk)
_MIN_CVSS_PRODUCT_ONLY = 7.0

# Generic nmap service names that produce noise — suppress keyword lookup for these
_NOISY_SERVICE_NAMES = frozenset({
    "http", "https", "ssl/http", "ssl/https",
    "smtp", "smtps", "pop3", "pop3s", "imap", "imaps",
    "ftp", "ftps", "sftp", "telnet",
    "ssh",
    "rdp", "ms-wbt-server",
    "dns", "domain", "snmp", "ntp", "netbios", "smb",
    "ldap", "ldaps", "kerberos",
    "tcp", "udp", "ssl", "tls", "unknown",
    "tcpwrapped",
})


def _build_headers() -> dict[str, str]:
    key = os.getenv("NVD_API_KEY", "")
    return {"apiKey": key} if key else {}


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    """Extract best available CVSS score + severity label."""
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version_key)
        if entries:
            data = entries[0].get("cvssData", {})
            raw = data.get("baseScore")
            severity = data.get("baseSeverity", "")
            if raw is not None:
                score = float(raw)
                if not severity:
                    severity = (
                        "CRITICAL" if score >= 9.0 else
                        "HIGH"     if score >= 7.0 else
                        "MEDIUM"   if score >= 4.0 else "LOW"
                    )
                return score, severity.upper()
    return 0.0, "UNKNOWN"


def _cve_year(cve_id: str) -> int:
    """Extract year from CVE-YYYY-NNNN. Returns 0 on failure."""
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return 0


def _normalise_version(version: str) -> str:
    """
    Strip non-numeric patch suffixes so NVD keyword searches are more likely
    to match.

    Examples:
      "8.4p1"   → "8.4"
      "3.6.2b1" → "3.6.2"
      "1.24.0"  → "1.24.0"   (unchanged — all-numeric)
      "2.4.41"  → "2.4.41"   (unchanged)
    """
    m = re.match(r"^(\d+(?:\.\d+)*)", version)
    if not m:
        return version
    normalised = m.group(1)
    # Don't return the same string — caller checks for equality to avoid dup query
    return normalised if normalised != version else ""


async def _nvd_query(params: dict, headers: dict) -> list[dict]:
    """Make one NVD API call. Handles rate limiting with a single retry."""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(NVD_BASE, params=params, headers=headers)
            if resp.status_code == 429:
                logger.warning("NVD rate limit — retrying after 6s")
                await asyncio.sleep(6)
                resp = await client.get(NVD_BASE, params=params, headers=headers)
            if resp.status_code != 200 or not resp.content:
                if resp.status_code != 200:
                    logger.debug(f"NVD returned HTTP {resp.status_code} for {params}")
                return []
            return resp.json().get("vulnerabilities", [])
    except Exception as exc:
        logger.warning(f"NVD request failed: {exc}")
        return []


def _parse_vulns(
    vulns: list[dict],
    min_cvss: float = _MIN_CVSS_WITH_VERSION,
    min_year: int = _MIN_CVE_YEAR,
    max_results: int = 5,
) -> list[dict]:
    """
    Parse raw NVD vulnerability list into CVE dicts.
    Applies client-side CVSS and publication-year filters.
    """
    results = []
    for item in vulns:
        if len(results) >= max_results:
            break
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        year = _cve_year(cve_id)
        if year and year < min_year:
            continue  # skip ancient CVEs

        score, severity = _extract_cvss(cve_data.get("metrics", {}))
        if score < min_cvss:
            continue  # skip below CVSS threshold

        desc = "No description available"
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", desc)
                break

        results.append({
            "id": cve_id,
            "cvss_score": score,
            "severity": severity,
            "description": desc[:300] + "..." if len(desc) > 300 else desc,
        })
    return results


def _dedup(cves: list[dict]) -> list[dict]:
    """Deduplicate CVE list by id, keeping highest CVSS on collision."""
    seen: dict[str, dict] = {}
    for c in cves:
        cid = c["id"]
        if cid not in seen or c["cvss_score"] > seen[cid]["cvss_score"]:
            seen[cid] = c
    return list(seen.values())


class CVELookup:
    """
    CVE lookup using NVD REST API v2.

    Strategy:
      1.  Keyword "PRODUCT VERSION"       — specific, CVSS >= 4.0, year >= 2015
      1b. Keyword "PRODUCT BASE_VERSION"  — fallback when 1 returns nothing
          (strips patch suffix: "8.4p1" → "8.4")
      2.  Dual product-only lookup (concurrent):
            a) keywordSearch=PRODUCT + cvssV3Severity=CRITICAL  — HIGH/CRITICAL hits
            b) keywordSearch=PRODUCT + last-120-day pub window  — recent exposure
          Merged + deduped, CVSS >= 7.0
      3.  Generic service names (http/smtp/etc.) → always return []
    """

    def __init__(self, max_results: int = 5, max_retries: int = 2):
        self.max_results = max_results

    async def lookup(
        self,
        product: str,
        version: str = "",
        service_name: str = "",
    ) -> list[dict]:
        """
        Find CVEs for a product/version combination.

        Args:
            product:      Product name from nmap (e.g. "OpenSSH", "nginx")
            version:      Version string (e.g. "8.4p1", "1.24.0")
            service_name: nmap service name hint (e.g. "ssh", "http")

        Returns:
            List sorted by CVSS descending, at most max_results entries.
        """
        if not product and not service_name:
            return []

        headers = _build_headers()

        # Determine the effective product name for noise check
        effective_name = (product or service_name or "").lower().strip()
        if effective_name in _NOISY_SERVICE_NAMES:
            logger.debug(f"Suppressing NVD lookup for generic service: {effective_name!r}")
            return []

        # ── Step 1: Specific keyword — product + version ──────────────────────
        if product and version:
            query = f"{product} {version}"
            vulns = await _nvd_query(
                {"keywordSearch": query, "resultsPerPage": 20}, headers
            )
            if vulns:
                parsed = _parse_vulns(
                    vulns,
                    min_cvss=_MIN_CVSS_WITH_VERSION,
                    min_year=_MIN_CVE_YEAR,
                    max_results=self.max_results,
                )
                if parsed:
                    logger.debug(f"NVD keyword hit [{query!r}]: {len(parsed)} CVEs")
                    return self._sort(parsed)

            # ── Step 1b: Normalised version ("8.4p1" → "8.4") ────────────────
            base_ver = _normalise_version(version)
            if base_ver and base_ver != version:
                query2 = f"{product} {base_ver}"
                vulns2 = await _nvd_query(
                    {"keywordSearch": query2, "resultsPerPage": 20}, headers
                )
                if vulns2:
                    parsed2 = _parse_vulns(
                        vulns2,
                        min_cvss=_MIN_CVSS_WITH_VERSION,
                        min_year=_MIN_CVE_YEAR,
                        max_results=self.max_results,
                    )
                    if parsed2:
                        logger.debug(
                            f"NVD keyword hit (base ver) [{query2!r}]: {len(parsed2)} CVEs"
                        )
                        return self._sort(parsed2)

        # ── Step 2: Dual product-only lookup ──────────────────────────────────
        # Only for known products (not generic service names already filtered above)
        fallback_term = product or service_name
        if not fallback_term or len(fallback_term) <= 3:
            return []

        # 2a: Server-side CRITICAL filter — surfaces important CVEs regardless of age,
        #     then we apply client-side year filter (>= 2015) to remove ancient ones.
        # 2b: Last 120 days — catches recent CVEs that may not yet be CRITICAL-scored.
        now = datetime.now(timezone.utc)
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_start = (now - timedelta(days=119)).strftime("%Y-%m-%dT%H:%M:%S.000")

        vulns_a, vulns_b = await asyncio.gather(
            _nvd_query(
                {
                    "keywordSearch": fallback_term,
                    "cvssV3Severity": "CRITICAL",
                    "resultsPerPage": 20,
                },
                headers,
            ),
            _nvd_query(
                {
                    "keywordSearch": fallback_term,
                    "pubStartDate": pub_start,
                    "pubEndDate": pub_end,
                    "resultsPerPage": 20,
                },
                headers,
            ),
        )

        combined = vulns_a + vulns_b
        if combined:
            parsed = _parse_vulns(
                combined,
                min_cvss=_MIN_CVSS_PRODUCT_ONLY,
                min_year=_MIN_CVE_YEAR,
                max_results=self.max_results * 4,   # extra room before dedup
            )
            deduped = _dedup(parsed)
            top = self._sort(deduped)[: self.max_results]
            if top:
                logger.debug(
                    f"NVD dual product [{fallback_term!r}]: {len(top)} CVEs "
                    f"(critical={len(vulns_a)} recent={len(vulns_b)})"
                )
                return top

        return []

    @staticmethod
    def _sort(cves: list[dict]) -> list[dict]:
        return sorted(cves, key=lambda c: c.get("cvss_score", 0.0), reverse=True)


def calculate_risk_score(cve_details: list[dict]) -> tuple[int, str]:
    """Compute an absolute risk score (0–100) from a CVE list."""
    if not cve_details:
        return 0, "NONE"
    total = sum(
        _SEVERITY_WEIGHTS.get(c.get("severity", "UNKNOWN"), 1)
        for c in cve_details
    )
    score = min(int(total * 10), 100)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score >= 20:
        level = "LOW"
    else:
        level = "MINIMAL"
    return score, level
