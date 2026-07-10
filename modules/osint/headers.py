"""HTTP header analysis module."""

from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class HeaderAnalyzer(OSINTModule):
    """Analyze HTTP headers for security issues."""

    name = "headers"
    description = "Analyze HTTP response headers for security misconfigurations"

    SECURITY_HEADERS = {
        "strict-transport-security": {"name": "HSTS", "severity": Severity.MEDIUM},
        "content-security-policy": {"name": "CSP", "severity": Severity.MEDIUM},
        "x-frame-options": {"name": "X-Frame-Options", "severity": Severity.LOW},
        "x-content-type-options": {"name": "X-Content-Type-Options", "severity": Severity.LOW},
        "x-xss-protection": {"name": "X-XSS-Protection", "severity": Severity.LOW},
        "referrer-policy": {"name": "Referrer-Policy", "severity": Severity.LOW},
        "permissions-policy": {"name": "Permissions-Policy", "severity": Severity.LOW},
    }

    INFO_DISCLOSURE_HEADERS = [
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-drupal-cache", "x-runtime", "x-version",
    ]

    async def run(self, target: Target) -> ScanResult:
        """Analyze HTTP headers for security issues."""
        result = self.create_result(target)
        url = self._build_url(target)
        self.logger.info(f"Analyzing headers for {url}")

        try:
            async with HTTPClient() as client:
                response = await client.get(url)
                headers = dict(response.headers)
                headers_lower = {k.lower(): v for k, v in headers.items()}

                result.raw_data["url"] = str(response.url)
                result.raw_data["status_code"] = response.status_code
                result.raw_data["headers"] = headers

                missing_headers = []
                present_headers = []

                for header, info in self.SECURITY_HEADERS.items():
                    if header in headers_lower:
                        present_headers.append({"header": info["name"], "value": headers_lower[header]})
                    else:
                        missing_headers.append({"header": info["name"], "severity": info["severity"]})

                if missing_headers:
                    medium_missing = [h for h in missing_headers if h["severity"] == Severity.MEDIUM]
                    if medium_missing:
                        result.add_finding(
                            title="Missing Important Security Headers",
                            description=f"Missing {len(medium_missing)} important security header(s)",
                            severity=Severity.MEDIUM,
                            data={"missing": [h["header"] for h in medium_missing]},
                        )

                if present_headers:
                    result.add_finding(
                        title="Security Headers Present",
                        description=f"Found {len(present_headers)} security header(s)",
                        severity=Severity.INFO,
                        data={"headers": present_headers},
                    )

                disclosed = []
                for header in self.INFO_DISCLOSURE_HEADERS:
                    if header in headers_lower:
                        disclosed.append({"header": header, "value": headers_lower[header]})

                if disclosed:
                    result.add_finding(
                        title="Information Disclosure in Headers",
                        description=f"Found {len(disclosed)} header(s) revealing server info",
                        severity=Severity.LOW,
                        data={"headers": disclosed},
                    )

        except Exception as e:
            result.errors.append(f"Failed to fetch headers: {str(e)}")
            result.success = False

        result.complete()
        return result

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
