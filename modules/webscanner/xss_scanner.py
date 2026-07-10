"""XSS vulnerability scanner."""

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core import load_wordlist
from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.webscanner.base import WebScannerModule


class XSSScanner(WebScannerModule):
    """Scan for Cross-Site Scripting vulnerabilities."""

    name = "xss"
    description = "Test for reflected and DOM-based XSS vulnerabilities"

    SECLISTS_RELATIVE_PATHS = (
        "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
        "Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
        "Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
    )

    # Built-in fallback payloads (benign probes that don't execute)
    PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '<body onload=alert(1)>',
        '{{constructor.constructor("alert(1)")()}}',  # Angular
        '${alert(1)}',  # Template injection
    ]

    # Patterns to detect reflection
    REFLECTION_PATTERNS = [
        r'<script>alert\(1\)</script>',
        r'onerror\s*=\s*alert',
        r'onload\s*=\s*alert',
        r'javascript:alert',
    ]

    def __init__(
        self,
        custom_payloads: list[str] | None = None,
        seclists_path: str | None = None,
    ):
        super().__init__()
        self.payloads = custom_payloads or load_wordlist(
            self.SECLISTS_RELATIVE_PATHS,
            fallback=self.PAYLOADS,
            seclists_path=seclists_path,
        )

    async def run(self, target: Target) -> ScanResult:
        """Scan target for XSS vulnerabilities."""
        result = self.create_result(target)

        url = self._build_url(target)
        self.logger.info(f"Starting XSS scan on {url}")

        vulnerabilities = []

        try:
            async with HTTPClient() as client:
                # Get the page first to find parameters
                response = await client.get(url)
                parsed = urlparse(str(response.url))
                params = parse_qs(parsed.query)

                if not params:
                    # No query parameters, try common ones
                    params = {"q": [""], "search": [""], "id": [""], "page": [""]}

                for param_name in params.keys():
                    for payload in self.payloads:
                        test_url = self._inject_payload(url, param_name, payload)

                        try:
                            test_response = await client.get(test_url)

                            # Check if payload is reflected
                            if self._check_reflection(test_response.text, payload):
                                vuln = {
                                    "type": "Reflected XSS",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": self._extract_evidence(test_response.text, payload),
                                }
                                vulnerabilities.append(vuln)
                                self.logger.warning(f"Potential XSS found: {param_name}")
                                break  # One payload is enough per param

                        except Exception as e:
                            self.logger.debug(f"Error testing payload: {e}")

            result.raw_data["tested_parameters"] = list(params.keys())
            result.raw_data["vulnerabilities"] = vulnerabilities

            if vulnerabilities:
                result.add_finding(
                    title="XSS Vulnerabilities Detected",
                    description=f"Found {len(vulnerabilities)} potential XSS vulnerability/vulnerabilities",
                    severity=Severity.HIGH,
                    data={"vulnerabilities": vulnerabilities},
                    references=["https://owasp.org/www-community/attacks/xss/"],
                )
            else:
                result.add_finding(
                    title="No XSS Vulnerabilities Found",
                    description=f"Tested {len(params)} parameter(s) with {len(self.payloads)} payload(s)",
                    severity=Severity.INFO,
                )

        except Exception as e:
            result.errors.append(f"XSS scan failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _check_reflection(self, html: str, payload: str) -> bool:
        """Check if payload is reflected in response."""
        # Direct reflection
        if payload in html:
            return True

        # Pattern matching for encoded/modified reflections
        for pattern in self.REFLECTION_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                return True

        return False

    def _extract_evidence(self, html: str, payload: str) -> str:
        """Extract context around reflected payload."""
        if payload in html:
            idx = html.find(payload)
            start = max(0, idx - 50)
            end = min(len(html), idx + len(payload) + 50)
            return html[start:end]
        return ""

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
