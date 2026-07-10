"""
Multi-source IP threat intelligence — async port of Virustotal Scanner.

Sources: VirusTotal · ThreatFox · AbuseIPDB · Shodan · AlienVault OTX · GreyNoise
"""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from core.logger import get_logger
from core.models import ScanResult, Severity, Target

logger = get_logger("threat_intel.ip_scanner")

# ── Constants ─────────────────────────────────────────────────────────────────

VT_API_BASE     = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL   = "https://api.abuseipdb.com/api/v2/check"
SHODAN_URL      = "https://api.shodan.io/shodan/host"
THREATFOX_URL   = "https://threatfox-api.abuse.ch/api/v1/"
OTX_URL         = "https://otx.alienvault.com/api/v1/indicators/IPv4"
GREYNOISE_URL   = "https://api.greynoise.io/v3/community"

DEFAULT_CACHE_TTL = 24  # hours
DEFAULT_DELAY     = 15.0  # seconds between VT calls

_THREAT_LEVEL_ORDER = {"malicious": 0, "suspicious": 1, "clean": 2}

_CSV_FIELDS = [
    "ip", "threat_level", "malicious_count", "suspicious_count",
    "harmless_count", "undetected_count", "country", "as_owner",
    "network", "reputation",
    "abuse_score", "abuse_reports", "abuse_usage",
    "gn_noise", "gn_riot", "gn_classification", "gn_name",
    "otx_pulses", "shodan_ports", "shodan_vulns", "shodan_org",
    "cached_at",
]


# ── IP validation ─────────────────────────────────────────────────────────────

def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ── Cache ─────────────────────────────────────────────────────────────────────

class _Cache:
    def __init__(self, path: Path, ttl_hours: int = DEFAULT_CACHE_TTL):
        self.path = path
        self.ttl = ttl_hours
        self._data: dict[str, dict] = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def get(self, ip: str) -> dict | None:
        entry = self._data.get(ip)
        if not entry:
            return None
        cached_at = entry.get("cached_at")
        if not cached_at:
            return None
        age = datetime.now() - datetime.fromisoformat(cached_at)
        return entry if age < timedelta(hours=self.ttl) else None

    def set(self, ip: str, result: dict) -> None:
        result["cached_at"] = datetime.now().isoformat()
        self._data[ip] = result

    def save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2))


# ── Per-source async fetchers ─────────────────────────────────────────────────

async def _fetch_vt(ip: str, api_key: str, client: httpx.AsyncClient) -> dict | None:
    url = f"{VT_API_BASE}/ip_addresses/{ip}"
    for attempt in range(3):
        try:
            resp = await client.get(url, headers={"x-apikey": api_key})
            if resp.status_code == 429:
                wait = int(resp.headers.get("X-RateLimit-Reset", 60))
                await asyncio.sleep(wait)
                continue
            if resp.status_code == 200:
                return resp.json()
        except httpx.RequestError as e:
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
            else:
                logger.debug(f"VT fetch failed for {ip}: {e}")
    return None


async def _fetch_threatfox(ip: str, client: httpx.AsyncClient) -> dict | None:
    try:
        resp = await client.post(
            THREATFOX_URL,
            json={"query": "search_ioc", "search_term": ip},
        )
        return resp.json() if resp.status_code == 200 else None
    except httpx.RequestError as e:
        logger.debug(f"ThreatFox fetch failed for {ip}: {e}")
        return None


async def _fetch_abuseipdb(ip: str, api_key: str, client: httpx.AsyncClient) -> dict | None:
    try:
        resp = await client.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        return resp.json() if resp.status_code == 200 else None
    except httpx.RequestError as e:
        logger.debug(f"AbuseIPDB fetch failed for {ip}: {e}")
        return None


async def _fetch_shodan(ip: str, api_key: str, client: httpx.AsyncClient) -> dict | None:
    try:
        resp = await client.get(
            f"{SHODAN_URL}/{ip}",
            params={"key": api_key},
        )
        if resp.status_code == 404:
            return {}
        return resp.json() if resp.status_code == 200 else None
    except httpx.RequestError as e:
        logger.debug(f"Shodan fetch failed for {ip}: {e}")
        return None


async def _fetch_otx(ip: str, api_key: str, client: httpx.AsyncClient) -> dict | None:
    try:
        resp = await client.get(
            f"{OTX_URL}/{ip}/general",
            headers={"X-OTX-API-KEY": api_key},
        )
        return resp.json() if resp.status_code == 200 else None
    except httpx.RequestError as e:
        logger.debug(f"OTX fetch failed for {ip}: {e}")
        return None


async def _fetch_greynoise(ip: str, api_key: str, client: httpx.AsyncClient) -> dict | None:
    try:
        resp = await client.get(
            f"{GREYNOISE_URL}/{ip}",
            headers={"key": api_key},
        )
        if resp.status_code == 404:
            return {}
        return resp.json() if resp.status_code == 200 else None
    except httpx.RequestError as e:
        logger.debug(f"GreyNoise fetch failed for {ip}: {e}")
        return None


# ── Source parsers ────────────────────────────────────────────────────────────

def _parse_vt(data: dict | None, threshold: int = 1) -> dict | None:
    if not data or "data" not in data:
        return None
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    vendors: dict[str, list] = {}
    for vendor, res in attrs.get("last_analysis_results", {}).items():
        cat = res["category"]
        if cat in ("malicious", "suspicious"):
            vendors.setdefault(cat, []).append(vendor)
    if malicious >= threshold:
        level = "malicious"
    elif malicious > 0 or suspicious > 0:
        level = "suspicious"
    else:
        level = "clean"
    return {
        "ip": data["data"]["id"],
        "threat_level": level,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": stats.get("harmless", 0),
        "undetected_count": stats.get("undetected", 0),
        "country": attrs.get("country", "—"),
        "as_owner": attrs.get("as_owner", "—"),
        "network": attrs.get("network", "—"),
        "reputation": attrs.get("reputation", 0),
        "vt_vendors": vendors,
    }


def _parse_threatfox(data: dict | None) -> dict:
    if not data or data.get("query_status") not in ("ok", "no_results"):
        return {}
    iocs = data.get("data") or []
    return {
        "tf_malware": sorted({i.get("malware_printable", "") for i in iocs if i.get("malware_printable")}),
        "tf_tags": sorted({t for i in iocs for t in (i.get("tags") or [])}),
    }


def _parse_abuseipdb(data: dict | None) -> dict:
    if not data:
        return {}
    d = data.get("data", {})
    return {
        "abuse_score": d.get("abuseConfidenceScore", 0),
        "abuse_reports": d.get("totalReports", 0),
        "abuse_usage": d.get("usageType", ""),
    }


def _parse_shodan(data: dict | None) -> dict:
    if not data:
        return {}
    return {
        "shodan_ports": data.get("ports", []),
        "shodan_vulns": list(data.get("vulns", {}).keys()),
        "shodan_tags": data.get("tags", []),
        "shodan_org": data.get("org", ""),
    }


def _parse_otx(data: dict | None) -> dict:
    if not data:
        return {}
    pulse_info = data.get("pulse_info", {})
    return {
        "otx_pulses": pulse_info.get("count", 0),
        "otx_tags": sorted({
            t for p in pulse_info.get("pulses", []) for t in (p.get("tags") or [])
        })[:10],
    }


def _parse_greynoise(data: dict | None) -> dict:
    if not data:
        return {}
    return {
        "gn_noise": data.get("noise", False),
        "gn_riot": data.get("riot", False),
        "gn_classification": data.get("classification", ""),
        "gn_name": data.get("name", ""),
    }


# ── Core scanner ──────────────────────────────────────────────────────────────

class IPThreatScanner:
    """
    Async multi-source IP threat intelligence scanner.

    Wraps: VirusTotal, ThreatFox, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise.

    API keys are read from environment variables or can be passed directly:
        VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY,
        OTX_API_KEY, GREYNOISE_API_KEY
    """

    def __init__(
        self,
        vt_api_key: str | None = None,
        abuseipdb_key: str | None = None,
        shodan_key: str | None = None,
        otx_key: str | None = None,
        greynoise_key: str | None = None,
        threshold: int = 1,
        cache_path: Path | None = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        delay: float = DEFAULT_DELAY,
    ):
        self.keys = {
            "vt":        vt_api_key       or os.getenv("VT_API_KEY", ""),
            "abuseipdb": abuseipdb_key    or os.getenv("ABUSEIPDB_API_KEY", ""),
            "shodan":    shodan_key        or os.getenv("SHODAN_API_KEY", ""),
            "otx":       otx_key           or os.getenv("OTX_API_KEY", ""),
            "greynoise": greynoise_key     or os.getenv("GREYNOISE_API_KEY", ""),
        }
        self.threshold = threshold
        self.cache = _Cache(cache_path or Path("vt_cache.json"), cache_ttl)
        self.delay = delay

    @property
    def active_sources(self) -> list[str]:
        sources = ["VirusTotal", "ThreatFox"]
        source_map = {
            "abuseipdb": "AbuseIPDB",
            "shodan": "Shodan",
            "otx": "AlienVault OTX",
            "greynoise": "GreyNoise",
        }
        return sources + [label for k, label in source_map.items() if self.keys.get(k)]

    async def scan_ip(self, ip: str) -> dict | None:
        """Scan a single IP. Returns enriched result dict or None if VT fails."""
        if not _is_valid_ip(ip):
            logger.warning(f"Skipping invalid IP: {ip}")
            return None

        cached = self.cache.get(ip)
        if cached:
            logger.debug(f"Cache hit: {ip}")
            return cached

        async with httpx.AsyncClient(timeout=20) as client:
            tasks: dict[str, Any] = {
                "vt": _fetch_vt(ip, self.keys["vt"], client),
                "threatfox": _fetch_threatfox(ip, client),
            }
            if self.keys["abuseipdb"]:
                tasks["abuseipdb"] = _fetch_abuseipdb(ip, self.keys["abuseipdb"], client)
            if self.keys["shodan"]:
                tasks["shodan"] = _fetch_shodan(ip, self.keys["shodan"], client)
            if self.keys["otx"]:
                tasks["otx"] = _fetch_otx(ip, self.keys["otx"], client)
            if self.keys["greynoise"]:
                tasks["greynoise"] = _fetch_greynoise(ip, self.keys["greynoise"], client)

            raw = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values()), strict=True))

        result = _parse_vt(raw.get("vt"), self.threshold)
        if result is None:
            return None

        parsers = {
            "threatfox": _parse_threatfox,
            "abuseipdb": _parse_abuseipdb,
            "shodan": _parse_shodan,
            "otx": _parse_otx,
            "greynoise": _parse_greynoise,
        }
        for source, parse_fn in parsers.items():
            if source in raw:
                result.update(parse_fn(raw[source]))

        self.cache.set(ip, result)
        return result

    async def scan_many(self, ips: list[str]) -> list[dict]:
        """
        Scan multiple IPs sequentially (VT rate limits require this).
        Uses self.delay between calls.
        """
        if not self.keys["vt"]:
            raise ValueError("VT_API_KEY is required. Set env var or pass vt_api_key=")

        results: list[dict] = []
        for i, ip in enumerate(ips):
            result = await self.scan_ip(ip)
            if result:
                results.append(result)
            if i < len(ips) - 1:
                await asyncio.sleep(self.delay)

        self.cache.save()
        return results

    async def run(self, target: Target) -> ScanResult:
        """Security-suite compatible run() interface. Target value = single IP."""
        result = ScanResult(target=target, module="threat_intel.ip_scanner")

        if not _is_valid_ip(target.value):
            result.errors.append(f"Invalid IP address: {target.value}")
            result.success = False
            result.complete()
            return result

        intel = await self.scan_ip(target.value)

        if intel is None:
            result.errors.append("VT lookup failed — check VT_API_KEY")
            result.success = False
            result.complete()
            return result

        result.raw_data["intel"] = intel
        level = intel.get("threat_level", "clean")

        severity_map = {
            "malicious": Severity.CRITICAL,
            "suspicious": Severity.MEDIUM,
            "clean": Severity.INFO,
        }
        sev = severity_map.get(level, Severity.INFO)

        result.add_finding(
            title=f"IP Threat Level: {level.upper()}",
            description=(
                f"{intel['ip']} — {intel['malicious_count']} malicious / "
                f"{intel['suspicious_count']} suspicious detections on VirusTotal"
            ),
            severity=sev,
            data=intel,
        )

        if intel.get("abuse_score", 0) >= 50:
            result.add_finding(
                title="High AbuseIPDB Score",
                description=f"Abuse confidence: {intel['abuse_score']}%",
                severity=Severity.HIGH,
                data={"abuse_score": intel["abuse_score"], "reports": intel.get("abuse_reports")},
            )

        if intel.get("gn_noise") and not intel.get("gn_riot"):
            result.add_finding(
                title="GreyNoise: Internet Noise Source",
                description=f"Classified as {intel.get('gn_classification', 'unknown')} scanner noise",
                severity=Severity.MEDIUM,
                data={"gn_classification": intel.get("gn_classification")},
            )

        if intel.get("tf_malware"):
            result.add_finding(
                title="ThreatFox Malware Association",
                description=f"Associated with: {', '.join(intel['tf_malware'])}",
                severity=Severity.HIGH,
                data={"malware": intel["tf_malware"], "tags": intel.get("tf_tags", [])},
            )

        result.complete()
        return result

    # ── Export helpers ────────────────────────────────────────────────────────

    @staticmethod
    def to_csv(results: list[dict], path: str) -> str:
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore", restval="")
            writer.writeheader()
            writer.writerows(results)
        return path

    @staticmethod
    def to_json(results: list[dict], path: str) -> str:
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        return path

    @staticmethod
    def sorted_by_threat(results: list[dict]) -> list[dict]:
        return sorted(results, key=lambda r: _THREAT_LEVEL_ORDER.get(r.get("threat_level", "clean"), 99))
