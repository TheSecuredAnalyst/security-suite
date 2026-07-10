"""Shodan integration module."""


from core.config import get_settings
from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class ShodanScanner(OSINTModule):
    """Query Shodan for host intelligence."""

    name = "shodan"
    description = "Query Shodan for exposed services and vulnerabilities"

    SHODAN_API_BASE = "https://api.shodan.io"

    def __init__(self, api_key: str | None = None):
        super().__init__()
        self.api_key = api_key or get_settings().shodan_api_key

    async def run(self, target: Target) -> ScanResult:
        """Query Shodan for target."""
        result = self.create_result(target)

        if not self.api_key:
            result.errors.append("Shodan API key not configured. Set SECSUITE_SHODAN_API_KEY")
            result.success = False
            result.complete()
            return result

        self.logger.info(f"Querying Shodan for {target.value}")

        try:
            async with HTTPClient() as client:
                if target.target_type == "ip":
                    await self._host_lookup(client, target.value, result)
                elif target.target_type == "domain":
                    await self._dns_lookup(client, target.value, result)
                else:
                    # Resolve domain to IP first
                    host = self._extract_host(target.value)
                    await self._dns_lookup(client, host, result)

        except Exception as e:
            result.errors.append(f"Shodan query failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    async def _host_lookup(self, client: HTTPClient, ip: str, result: ScanResult) -> None:
        """Look up host information by IP."""
        response = await client.get(
            f"{self.SHODAN_API_BASE}/shodan/host/{ip}",
            params={"key": self.api_key}
        )

        if response.status_code == 404:
            result.add_finding(
                title="Host Not Found",
                description=f"IP {ip} not found in Shodan database",
                severity=Severity.INFO,
            )
            return

        if response.status_code != 200:
            result.errors.append(f"Shodan API error: {response.status_code}")
            return

        data = response.json()
        result.raw_data["shodan"] = data

        # Basic host info
        result.add_finding(
            title="Host Information",
            description=f"Found in Shodan - {data.get('org', 'Unknown Org')} ({data.get('country_name', 'Unknown')})",
            severity=Severity.INFO,
            data={
                "ip": ip,
                "org": data.get("org"),
                "asn": data.get("asn"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "hostnames": data.get("hostnames", []),
            },
        )

        # Open ports and services
        ports = data.get("ports", [])
        if ports:
            services = []
            for item in data.get("data", []):
                services.append({
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                })

            result.add_finding(
                title="Exposed Services",
                description=f"Found {len(ports)} open port(s): {', '.join(map(str, sorted(ports)))}",
                severity=Severity.INFO,
                data={"ports": ports, "services": services},
            )

        # Vulnerabilities
        vulns = data.get("vulns", [])
        if vulns:
            # Sort by CVSS if available
            critical_vulns = [v for v in vulns if v.startswith("CVE-")]

            result.add_finding(
                title="Known Vulnerabilities",
                description=f"Found {len(vulns)} potential vulnerability/vulnerabilities",
                severity=Severity.HIGH if len(vulns) > 5 else Severity.MEDIUM,
                data={"vulnerabilities": vulns},
                references=[f"https://nvd.nist.gov/vuln/detail/{v}" for v in critical_vulns[:10]],
            )

        # Check for risky services
        risky_services = []
        for item in data.get("data", []):
            port = item.get("port")
            product = item.get("product", "").lower()

            if port in [21, 23, 445, 3389, 5900]:
                risky_services.append({"port": port, "product": product})
            elif "telnet" in product or "ftp" in product:
                risky_services.append({"port": port, "product": product})

        if risky_services:
            result.add_finding(
                title="Potentially Risky Services",
                description=f"Found {len(risky_services)} service(s) that may pose security risks",
                severity=Severity.MEDIUM,
                data={"services": risky_services},
            )

    async def _dns_lookup(self, client: HTTPClient, domain: str, result: ScanResult) -> None:
        """Look up DNS information for domain."""
        response = await client.get(
            f"{self.SHODAN_API_BASE}/dns/resolve",
            params={"hostnames": domain, "key": self.api_key}
        )

        if response.status_code != 200:
            result.errors.append(f"Shodan DNS API error: {response.status_code}")
            return

        data = response.json()

        if domain in data and data[domain]:
            ip = data[domain]
            result.add_finding(
                title="Domain Resolved",
                description=f"{domain} resolves to {ip}",
                severity=Severity.INFO,
                data={"domain": domain, "ip": ip},
            )
            # Now do host lookup
            await self._host_lookup(client, ip, result)
        else:
            result.add_finding(
                title="Domain Not Resolved",
                description=f"Could not resolve {domain}",
                severity=Severity.INFO,
            )

    def _extract_host(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            return urlparse(value).netloc
        return value
