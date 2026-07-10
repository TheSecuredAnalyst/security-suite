"""Email harvester module."""

import re
from urllib.parse import urljoin, urlparse

from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class EmailHarvester(OSINTModule):
    """Harvest email addresses from web pages."""

    name = "email_harvest"
    description = "Extract email addresses from target website"

    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I)

    CONTACT_PATHS = [
        "/", "/contact", "/contact-us", "/about", "/about-us",
        "/team", "/support", "/help", "/impressum",
    ]

    def __init__(self, max_pages: int = 10):
        super().__init__()
        self.max_pages = max_pages

    async def run(self, target: Target) -> ScanResult:
        """Harvest emails from target."""
        result = self.create_result(target)
        base_url = self._build_url(target)
        domain = urlparse(base_url).netloc
        self.logger.info(f"Harvesting emails from {domain}")

        found_emails: set[str] = set()
        scanned_pages: set[str] = set()

        try:
            async with HTTPClient() as client:
                for path in self.CONTACT_PATHS:
                    if len(scanned_pages) >= self.max_pages:
                        break

                    url = urljoin(base_url, path)
                    if url in scanned_pages:
                        continue

                    try:
                        response = await client.get(url)
                        scanned_pages.add(url)
                        if response.status_code == 200:
                            emails = self._extract_emails(response.text)
                            found_emails.update(emails)
                    except Exception:
                        pass

                result.raw_data["emails"] = list(found_emails)
                result.raw_data["pages_scanned"] = len(scanned_pages)

                if found_emails:
                    result.add_finding(
                        title="Email Addresses Found",
                        description=f"Discovered {len(found_emails)} email address(es)",
                        severity=Severity.INFO,
                        data={"emails": list(found_emails)},
                    )

        except Exception as e:
            result.errors.append(f"Email harvesting failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    def _extract_emails(self, html: str) -> set[str]:
        emails = set()
        matches = self.EMAIL_PATTERN.findall(html)
        invalid = [".png", ".jpg", ".gif", ".css", ".js", "example.com"]
        for email in matches:
            if not any(x in email.lower() for x in invalid):
                emails.add(email.lower())
        return emails

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
