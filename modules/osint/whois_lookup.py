"""WHOIS lookup module."""

import whois

from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class WhoisLookup(OSINTModule):
    """Perform WHOIS lookups for domains and IPs."""

    name = "whois"
    description = "Retrieve WHOIS registration information"

    async def run(self, target: Target) -> ScanResult:
        """Perform WHOIS lookup on target."""
        result = self.create_result(target)

        if target.target_type not in ("domain", "ip", "url"):
            result.errors.append(f"Invalid target type: {target.target_type}")
            result.success = False
            result.complete()
            return result

        domain = self._extract_domain(target.value)
        self.logger.info(f"Performing WHOIS lookup for {domain}")

        try:
            w = whois.whois(domain)

            if w.domain_name is None:
                result.errors.append("No WHOIS data found")
                result.success = False
                result.complete()
                return result

            whois_data = {
                "domain_name": self._normalize(w.domain_name),
                "registrar": w.registrar,
                "creation_date": self._format_date(w.creation_date),
                "expiration_date": self._format_date(w.expiration_date),
                "updated_date": self._format_date(w.updated_date),
                "name_servers": self._normalize(w.name_servers),
                "status": self._normalize(w.status),
                "emails": self._normalize(w.emails),
                "org": w.org,
                "country": w.country,
                "state": w.state,
                "city": w.city,
            }

            whois_data = {k: v for k, v in whois_data.items() if v is not None}
            result.raw_data["whois"] = whois_data

            result.add_finding(
                title="WHOIS Registration Data",
                description=f"Domain registered with {w.registrar or 'unknown registrar'}",
                severity=Severity.INFO,
                data=whois_data,
            )

            if w.expiration_date:
                from datetime import datetime
                exp_date = w.expiration_date
                if isinstance(exp_date, list):
                    exp_date = exp_date[0]
                if isinstance(exp_date, datetime):
                    days_until_expiry = (exp_date - datetime.now()).days
                    if days_until_expiry < 30:
                        result.add_finding(
                            title="Domain Expiring Soon",
                            description=f"Domain expires in {days_until_expiry} days",
                            severity=Severity.MEDIUM,
                            data={"expiration_date": str(exp_date), "days_remaining": days_until_expiry},
                        )

            if w.creation_date:
                from datetime import datetime
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if isinstance(creation, datetime):
                    age_days = (datetime.now() - creation).days
                    if age_days < 90:
                        result.add_finding(
                            title="Newly Registered Domain",
                            description=f"Domain is only {age_days} days old - potentially suspicious",
                            severity=Severity.LOW,
                            data={"age_days": age_days, "creation_date": str(creation)},
                        )

        except Exception as e:
            result.errors.append(f"WHOIS lookup failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    def _extract_domain(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            return urlparse(value).netloc
        return value

    def _normalize(self, value):
        if isinstance(value, list):
            return value if len(value) > 1 else value[0]
        return value

    def _format_date(self, value):
        if value is None:
            return None
        if isinstance(value, list):
            value = value[0]
        return str(value) if value else None
