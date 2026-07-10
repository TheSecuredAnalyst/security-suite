"""Subdomain discovery module."""

import asyncio

import dns.asyncresolver

from core import load_wordlist
from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class SubdomainScanner(OSINTModule):
    """Discover subdomains using DNS bruteforce."""

    name = "subdomain"
    description = "Discover subdomains via DNS bruteforce and public sources"

    SECLISTS_RELATIVE_PATHS = (
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/subdomains-top1million-20000.txt",
    )

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "blog", "dev", "stage", "staging",
        "test", "api", "app", "admin", "portal", "secure", "vpn", "remote",
        "gateway", "proxy", "cdn", "static", "assets", "img", "images", "media",
        "shop", "store", "support", "help", "docs", "wiki", "status",
        "git", "gitlab", "jenkins", "ci", "build", "prod", "uat", "qa", "demo",
        "beta", "internal", "intranet", "corp", "exchange", "owa", "autodiscover",
        "cpanel", "panel", "dashboard", "console", "login", "sso", "auth",
        "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
        "cache", "mq", "data", "analytics", "logs", "grafana", "kibana",
        "aws", "cloud", "s3", "backup", "mobile", "m",
    ]

    def __init__(
        self,
        wordlist: list[str] | None = None,
        max_concurrent: int = 20,
        seclists_path: str | None = None,
    ):
        super().__init__()
        self.wordlist = wordlist or load_wordlist(
            self.SECLISTS_RELATIVE_PATHS,
            fallback=self.COMMON_SUBDOMAINS,
            seclists_path=seclists_path,
        )
        self.max_concurrent = max_concurrent

    async def run(self, target: Target) -> ScanResult:
        """Discover subdomains for target domain."""
        result = self.create_result(target)

        if target.target_type not in ("domain", "url"):
            result.errors.append(f"Invalid target type: {target.target_type}")
            result.success = False
            result.complete()
            return result

        domain = self._extract_domain(target.value)
        self.logger.info(f"Starting subdomain enumeration for {domain}")

        found_subdomains = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_subdomain(subdomain: str) -> dict | None:
            async with semaphore:
                fqdn = f"{subdomain}.{domain}"
                try:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 3.0
                    resolver.lifetime = 5.0
                    answers = await resolver.resolve(fqdn, "A")
                    ips = [str(rdata) for rdata in answers]
                    self.logger.debug(f"Found: {fqdn} -> {ips}")
                    return {"subdomain": subdomain, "fqdn": fqdn, "ips": ips}
                except Exception:
                    return None

        self.logger.info(f"Checking {len(self.wordlist)} potential subdomains...")
        tasks = [check_subdomain(sub) for sub in self.wordlist]
        results = await asyncio.gather(*tasks)

        found_subdomains = [r for r in results if r is not None]

        result.raw_data["subdomains"] = found_subdomains
        result.raw_data["checked_count"] = len(self.wordlist)

        if found_subdomains:
            result.add_finding(
                title="Subdomains Discovered",
                description=f"Found {len(found_subdomains)} active subdomain(s)",
                severity=Severity.INFO,
                data={"subdomains": [s["fqdn"] for s in found_subdomains]},
            )

            sensitive_keywords = ["admin", "internal", "dev", "staging", "test", "vpn", "jenkins", "git"]
            sensitive_found = [
                s for s in found_subdomains
                if any(kw in s["subdomain"].lower() for kw in sensitive_keywords)
            ]
            if sensitive_found:
                result.add_finding(
                    title="Potentially Sensitive Subdomains",
                    description=f"Found {len(sensitive_found)} subdomain(s) that may expose internal services",
                    severity=Severity.MEDIUM,
                    data={"subdomains": [s["fqdn"] for s in sensitive_found]},
                )

        result.complete()
        return result

    def _extract_domain(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            return urlparse(value).netloc
        return value
