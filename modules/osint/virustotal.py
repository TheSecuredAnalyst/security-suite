"""VirusTotal integration module."""


from core.config import get_settings
from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class VirusTotalScanner(OSINTModule):
    """Query VirusTotal for threat intelligence."""

    name = "virustotal"
    description = "Check domains/IPs/URLs against VirusTotal threat database"

    VT_API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None):
        super().__init__()
        self.api_key = api_key or get_settings().virustotal_api_key

    async def run(self, target: Target) -> ScanResult:
        """Query VirusTotal for target."""
        result = self.create_result(target)

        if not self.api_key:
            result.errors.append("VirusTotal API key not configured. Set SECSUITE_VIRUSTOTAL_API_KEY")
            result.success = False
            result.complete()
            return result

        self.logger.info(f"Querying VirusTotal for {target.value}")

        try:
            headers = {"x-apikey": self.api_key}

            async with HTTPClient(headers=headers) as client:
                if target.target_type == "domain":
                    await self._check_domain(client, target.value, result)
                elif target.target_type == "ip":
                    await self._check_ip(client, target.value, result)
                elif target.target_type == "url":
                    await self._check_url(client, target.value, result)
                else:
                    # Try domain lookup for unknown types
                    await self._check_domain(client, target.value, result)

        except Exception as e:
            result.errors.append(f"VirusTotal query failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    async def _check_domain(self, client: HTTPClient, domain: str, result: ScanResult) -> None:
        """Check domain reputation."""
        response = await client.get(f"{self.VT_API_BASE}/domains/{domain}")

        if response.status_code == 404:
            result.add_finding(
                title="Domain Not Found",
                description=f"Domain {domain} not found in VirusTotal database",
                severity=Severity.INFO,
            )
            return

        if response.status_code != 200:
            result.errors.append(f"VT API error: {response.status_code}")
            return

        data = response.json().get("data", {})
        attrs = data.get("attributes", {})

        result.raw_data["virustotal"] = attrs

        # Parse analysis stats
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        clean = stats.get("harmless", 0) + stats.get("undetected", 0)

        total_engines = malicious + suspicious + clean

        if malicious > 0:
            severity = Severity.CRITICAL if malicious >= 5 else Severity.HIGH
            result.add_finding(
                title="Malicious Domain Detected",
                description=f"{malicious}/{total_engines} security vendors flagged this domain as malicious",
                severity=severity,
                data={"malicious": malicious, "suspicious": suspicious, "clean": clean},
            )
        elif suspicious > 0:
            result.add_finding(
                title="Suspicious Domain",
                description=f"{suspicious}/{total_engines} vendors flagged this domain as suspicious",
                severity=Severity.MEDIUM,
                data={"malicious": malicious, "suspicious": suspicious, "clean": clean},
            )
        else:
            result.add_finding(
                title="Domain Reputation Clean",
                description=f"No malicious detections from {total_engines} security vendors",
                severity=Severity.INFO,
                data={"clean": clean},
            )

        # Check categories
        categories = attrs.get("categories", {})
        if categories:
            result.add_finding(
                title="Domain Categories",
                description=f"Domain categorized by {len(categories)} vendors",
                severity=Severity.INFO,
                data={"categories": categories},
            )

    async def _check_ip(self, client: HTTPClient, ip: str, result: ScanResult) -> None:
        """Check IP reputation."""
        response = await client.get(f"{self.VT_API_BASE}/ip_addresses/{ip}")

        if response.status_code != 200:
            result.errors.append(f"VT API error: {response.status_code}")
            return

        data = response.json().get("data", {})
        attrs = data.get("attributes", {})

        result.raw_data["virustotal"] = attrs

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            severity = Severity.CRITICAL if malicious >= 5 else Severity.HIGH
            result.add_finding(
                title="Malicious IP Detected",
                description=f"{malicious} security vendors flagged this IP as malicious",
                severity=severity,
                data=stats,
            )
        elif suspicious > 0:
            result.add_finding(
                title="Suspicious IP",
                description=f"{suspicious} vendors flagged this IP as suspicious",
                severity=Severity.MEDIUM,
                data=stats,
            )
        else:
            result.add_finding(
                title="IP Reputation Clean",
                description="No malicious detections from security vendors",
                severity=Severity.INFO,
            )

        # Check ASN info
        asn = attrs.get("asn")
        as_owner = attrs.get("as_owner")
        country = attrs.get("country")

        if asn:
            result.add_finding(
                title="IP Network Information",
                description=f"ASN: {asn} ({as_owner or 'Unknown'})",
                severity=Severity.INFO,
                data={"asn": asn, "as_owner": as_owner, "country": country},
            )

    async def _check_url(self, client: HTTPClient, url: str, result: ScanResult) -> None:
        """Check URL reputation."""
        import base64

        # VT requires base64-encoded URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = await client.get(f"{self.VT_API_BASE}/urls/{url_id}")

        if response.status_code == 404:
            # URL not in database - submit for scanning
            result.add_finding(
                title="URL Not Previously Scanned",
                description="URL not found in VirusTotal database",
                severity=Severity.INFO,
            )
            return

        if response.status_code != 200:
            result.errors.append(f"VT API error: {response.status_code}")
            return

        data = response.json().get("data", {})
        attrs = data.get("attributes", {})

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        if malicious > 0:
            result.add_finding(
                title="Malicious URL Detected",
                description=f"{malicious} vendors flagged this URL as malicious",
                severity=Severity.CRITICAL if malicious >= 5 else Severity.HIGH,
                data=stats,
            )
        else:
            result.add_finding(
                title="URL Reputation Clean",
                description="No malicious detections",
                severity=Severity.INFO,
            )
