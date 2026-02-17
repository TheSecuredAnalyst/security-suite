"""DNS enumeration module."""

import asyncio
import ipaddress
from typing import Optional

import dns.resolver
import dns.asyncresolver
import dns.reversename

from core.models import Target, ScanResult, Severity
from modules.osint.base import OSINTModule


class DNSEnumerator(OSINTModule):
    """Enumerate DNS records for a domain."""

    name = "dns_enum"
    description = "Enumerate DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

    async def run(self, target: Target) -> ScanResult:
        """Enumerate DNS records for the target domain."""
        result = self.create_result(target)

        # Handle IP targets with reverse DNS lookup
        if target.target_type == "ip":
            return await self._reverse_lookup(target, result)

        if target.target_type not in ("domain", "url"):
            result.errors.append(f"Invalid target type: {target.target_type}. Expected domain or IP.")
            result.success = False
            result.complete()
            return result

        domain = self._extract_domain(target.value)
        self.logger.info(f"Enumerating DNS records for {domain}")

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        records_found = {}

        for record_type in self.RECORD_TYPES:
            try:
                answers = await resolver.resolve(domain, record_type)
                records = []
                for rdata in answers:
                    records.append(str(rdata))
                if records:
                    records_found[record_type] = records
                    self.logger.debug(f"Found {len(records)} {record_type} records")
            except dns.resolver.NXDOMAIN:
                result.errors.append(f"Domain {domain} does not exist")
                result.success = False
                break
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NoNameservers:
                result.errors.append(f"No nameservers available for {domain}")
                break
            except Exception as e:
                self.logger.debug(f"Error querying {record_type}: {e}")

        if records_found:
            result.raw_data["dns_records"] = records_found

            if "A" in records_found:
                result.add_finding(
                    title="IPv4 Addresses Found",
                    description=f"Domain resolves to {len(records_found['A'])} IPv4 address(es)",
                    severity=Severity.INFO,
                    data={"addresses": records_found["A"]},
                )

            if "MX" in records_found:
                result.add_finding(
                    title="Mail Servers Found",
                    description=f"Found {len(records_found['MX'])} mail server(s)",
                    severity=Severity.INFO,
                    data={"servers": records_found["MX"]},
                )

            if "TXT" in records_found:
                txt_data = records_found["TXT"]
                spf_records = [r for r in txt_data if "v=spf1" in r.lower()]

                if spf_records:
                    result.add_finding(
                        title="SPF Record Found",
                        description="Domain has SPF email authentication configured",
                        severity=Severity.INFO,
                        data={"spf": spf_records},
                    )
                else:
                    result.add_finding(
                        title="No SPF Record",
                        description="Domain lacks SPF record - may be vulnerable to email spoofing",
                        severity=Severity.LOW,
                    )

            if "NS" in records_found:
                result.add_finding(
                    title="Nameservers Identified",
                    description=f"Found {len(records_found['NS'])} nameserver(s)",
                    severity=Severity.INFO,
                    data={"nameservers": records_found["NS"]},
                )

        result.complete()
        return result

    async def _reverse_lookup(self, target: Target, result: ScanResult) -> ScanResult:
        """Perform reverse DNS (PTR) lookup for an IP address."""
        ip = target.value
        self.logger.info(f"Performing reverse DNS lookup for {ip}")

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        try:
            rev_name = dns.reversename.from_address(ip)
            answers = await resolver.resolve(rev_name, "PTR")
            hostnames = [str(rdata).rstrip(".") for rdata in answers]

            result.raw_data["reverse_dns"] = {"ip": ip, "hostnames": hostnames}
            result.add_finding(
                title="Reverse DNS (PTR) Records",
                description=f"IP {ip} resolves to {len(hostnames)} hostname(s)",
                severity=Severity.INFO,
                data={"ip": ip, "hostnames": hostnames},
            )
        except dns.resolver.NXDOMAIN:
            result.raw_data["reverse_dns"] = {"ip": ip, "hostnames": []}
            result.add_finding(
                title="No Reverse DNS Record",
                description=f"No PTR record found for {ip}",
                severity=Severity.INFO,
                data={"ip": ip},
            )
        except Exception as e:
            result.raw_data["reverse_dns"] = {"ip": ip, "error": str(e)}
            result.add_finding(
                title="Reverse DNS Lookup",
                description=f"PTR lookup for {ip} failed: {e}",
                severity=Severity.INFO,
                data={"ip": ip, "error": str(e)},
            )

        result.complete()
        return result

    def _extract_domain(self, value: str) -> str:
        """Extract domain from URL or return as-is."""
        if value.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            return urlparse(value).netloc
        return value
