"""API endpoint security tester."""

import re
from dataclasses import dataclass, field

import httpx

from core import load_wordlist
from core.logger import get_logger
from core.models import Finding, ScanResult, Severity, Target
from core.url_guard import safe_join, validate_outbound_url
from modules.apisec.openapi_parser import APIEndpoint, ParsedAPI


@dataclass
class EndpointTestResult:
    """Result of testing an endpoint."""
    endpoint: APIEndpoint
    findings: list[Finding] = field(default_factory=list)
    response_code: int | None = None
    response_time: float = 0.0
    error: str | None = None


class APIEndpointTester:
    """Security tester for API endpoints."""

    # SecLists paths for injection payload categories
    SECLISTS_LFI_PATHS = (
        "Fuzzing/LFI/LFI-Jhaddix.txt",
        "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    )
    SECLISTS_CMDI_PATHS = (
        "Fuzzing/command-injection-commix.txt",
        "Fuzzing/UnixAttacks.fuzzdb.txt",
    )

    # BOLA/IDOR test IDs
    IDOR_TEST_IDS = ["1", "2", "999", "0", "-1", "admin", "test", "../1"]

    # SQL injection payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "1 UNION SELECT NULL--",
        "' OR 1=1--",
    ]

    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
    ]

    # Fallback command injection payloads
    CMDI_PAYLOADS = [
        "; ls",
        "| cat /etc/passwd",
        "`id`",
        "$(whoami)",
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://169.254.169.254",  # AWS metadata
        "http://[::1]",
    ]

    # Fallback LFI payloads
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "../../../../etc/shadow",
        "/etc/passwd",
    ]

    def __init__(
        self,
        timeout: float = 10.0,
        auth_header: str | None = None,
        auth_token: str | None = None,
        seclists_path: str | None = None,
    ):
        self.logger = get_logger("apisec.endpoint_tester")
        self.timeout = timeout
        self.auth_header = auth_header
        self.auth_token = auth_token
        # Load LFI and command injection payloads from SecLists when available
        self.lfi_payloads: list[str] = load_wordlist(
            self.SECLISTS_LFI_PATHS,
            fallback=self.LFI_PAYLOADS,
            seclists_path=seclists_path,
        )
        self.cmdi_payloads: list[str] = load_wordlist(
            self.SECLISTS_CMDI_PATHS,
            fallback=self.CMDI_PAYLOADS,
            seclists_path=seclists_path,
            max_entries=100,
        )

    async def test_api(self, api: ParsedAPI) -> ScanResult:
        """Test all endpoints in an API.

        Args:
            api: Parsed API specification

        Returns:
            Scan result with findings
        """
        target = Target.from_string(api.base_url)
        self.logger.info(f"Testing {len(api.endpoints)} endpoints for {api.title}")

        all_findings = []

        # Test each endpoint
        for endpoint in api.endpoints:
            result = await self.test_endpoint(api.base_url, endpoint)
            all_findings.extend(result.findings)

        # Check for API-level security issues
        api_findings = self._check_api_security(api)
        all_findings.extend(api_findings)

        return ScanResult(
            module="apisec.endpoint_tester",
            target=target,
            success=True,
            findings=all_findings,
            data={
                "api_title": api.title,
                "endpoints_tested": len(api.endpoints),
                "base_url": api.base_url,
            },
        )

    async def test_endpoint(
        self, base_url: str, endpoint: APIEndpoint
    ) -> EndpointTestResult:
        """Test a single endpoint for security issues.

        Args:
            base_url: API base URL
            endpoint: Endpoint to test

        Returns:
            Test result with findings

        Raises:
            BlockedTargetError: base_url is not a fetchable public http(s) target.
        """
        # base_url comes from the `servers` block of a fetched spec, i.e. from
        # whoever wrote the spec — validate before it becomes a request target.
        base_url = validate_outbound_url(base_url)

        result = EndpointTestResult(endpoint=endpoint)
        url = safe_join(base_url, endpoint.path)

        self.logger.debug(f"Testing {endpoint.method} {url}")

        headers = self._get_headers()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Basic request to check accessibility
                response = await self._make_request(
                    client, endpoint.method, url, headers
                )
                result.response_code = response.status_code
                result.response_time = response.elapsed.total_seconds()

                # Check for security issues
                result.findings.extend(
                    self._check_response_security(endpoint, response)
                )

                # Test for BOLA/IDOR if path has ID parameter
                if self._has_id_parameter(endpoint):
                    idor_findings = await self._test_bola(
                        client, base_url, endpoint, headers
                    )
                    result.findings.extend(idor_findings)

                # Test for injection vulnerabilities
                injection_findings = await self._test_injections(
                    client, base_url, endpoint, headers
                )
                result.findings.extend(injection_findings)

                # Test for mass assignment
                if endpoint.method in ["POST", "PUT", "PATCH"]:
                    mass_assign_findings = await self._test_mass_assignment(
                        client, url, endpoint, headers
                    )
                    result.findings.extend(mass_assign_findings)

        except httpx.TimeoutException:
            result.error = "Request timeout"
        except Exception as e:
            result.error = str(e)

        return result

    def _get_headers(self) -> dict:
        """Get request headers including auth."""
        headers = {
            "User-Agent": "SecuritySuite-APISec/1.0",
            "Accept": "application/json",
        }

        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_header:
            headers["Authorization"] = self.auth_header

        return headers

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict,
        params: dict | None = None,
        json_data: dict | None = None,
    ) -> httpx.Response:
        """Make HTTP request."""
        return await client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json_data,
            follow_redirects=True,
        )

    def _check_response_security(
        self, endpoint: APIEndpoint, response: httpx.Response
    ) -> list[Finding]:
        """Check response for security issues."""
        findings = []

        # Check for sensitive data in error responses
        if response.status_code >= 400:
            body = response.text.lower()
            sensitive_patterns = [
                (r"stack\s*trace", "Stack trace exposed"),
                (r"sql\s*(syntax|error)", "SQL error exposed"),
                (r"exception|traceback", "Exception details exposed"),
                (r"password|secret|key", "Sensitive keywords in error"),
            ]

            for pattern, desc in sensitive_patterns:
                if re.search(pattern, body):
                    findings.append(Finding(
                        title=f"Information Disclosure: {desc}",
                        description=f"{endpoint.method} {endpoint.path} exposes {desc} in error response",
                        severity=Severity.MEDIUM,
                        source="apisec.endpoint_tester",
                        data={"endpoint": endpoint.path, "status_code": response.status_code},
                    ))

        # Check for missing security headers
        security_headers = {
            "x-content-type-options": "Missing X-Content-Type-Options header",
            "x-frame-options": "Missing X-Frame-Options header",
            "content-security-policy": "Missing Content-Security-Policy header",
        }

        for header, desc in security_headers.items():
            if header not in [h.lower() for h in response.headers.keys()]:
                findings.append(Finding(
                    title=desc,
                    description=f"{endpoint.method} {endpoint.path}: {desc}",
                    severity=Severity.LOW,
                    source="apisec.endpoint_tester",
                    data={"endpoint": endpoint.path},
                ))

        # Check for verbose headers
        verbose_headers = ["x-powered-by", "server"]
        for header in verbose_headers:
            if header in [h.lower() for h in response.headers.keys()]:
                findings.append(Finding(
                    title=f"Information Disclosure: {header} header",
                    description=f"Server exposes {header}: {response.headers.get(header, '')}",
                    severity=Severity.INFO,
                    source="apisec.endpoint_tester",
                    data={"header": header, "value": response.headers.get(header)},
                ))

        return findings

    def _has_id_parameter(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint has ID-like parameter."""
        # Check path for ID patterns
        if re.search(r'\{[^}]*id[^}]*\}', endpoint.path, re.IGNORECASE):
            return True

        # Check parameters
        for param in endpoint.parameters:
            if "id" in param.name.lower() and param.location == "path":
                return True

        return False

    async def _test_bola(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: APIEndpoint,
        headers: dict,
    ) -> list[Finding]:
        """Test for Broken Object Level Authorization (BOLA/IDOR)."""
        findings = []

        # Replace ID parameters with test values
        for test_id in self.IDOR_TEST_IDS:
            test_path = re.sub(r'\{[^}]*\}', test_id, endpoint.path)
            url = safe_join(base_url, test_path)

            try:
                response = await self._make_request(
                    client, endpoint.method, url, headers
                )

                # If we get 200 with different IDs, potential BOLA
                if response.status_code == 200:
                    findings.append(Finding(
                        title="Potential BOLA/IDOR Vulnerability",
                        description=f"{endpoint.method} {endpoint.path} may be vulnerable to IDOR. "
                                   f"Test ID '{test_id}' returned 200 OK",
                        severity=Severity.HIGH,
                        source="apisec.endpoint_tester",
                        data={
                            "endpoint": endpoint.path,
                            "test_id": test_id,
                            "status_code": response.status_code,
                        },
                    ))
                    break  # One finding is enough

            except Exception:
                pass

        return findings

    async def _test_injections(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: APIEndpoint,
        headers: dict,
    ) -> list[Finding]:
        """Test for injection vulnerabilities."""
        findings = []

        # Get parameters that accept user input
        injectable_params = [
            p for p in endpoint.parameters
            if p.location in ["query", "path"] and p.param_type == "string"
        ]

        if not injectable_params:
            return findings

        for param in injectable_params[:2]:  # Limit to first 2 params
            # Test SQL injection
            for payload in self.SQLI_PAYLOADS[:2]:
                finding = await self._test_injection(
                    client, base_url, endpoint, headers, param.name, payload, "SQL"
                )
                if finding:
                    findings.append(finding)
                    break

            # Test command injection (SecLists-backed when available)
            for payload in self.cmdi_payloads[:5]:
                finding = await self._test_injection(
                    client, base_url, endpoint, headers, param.name, payload, "Command"
                )
                if finding:
                    findings.append(finding)
                    break

            # Test LFI / path traversal (SecLists-backed when available)
            for payload in self.lfi_payloads[:5]:
                finding = await self._test_injection(
                    client, base_url, endpoint, headers, param.name, payload, "LFI"
                )
                if finding:
                    findings.append(finding)
                    break

        return findings

    async def _test_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: APIEndpoint,
        headers: dict,
        param_name: str,
        payload: str,
        injection_type: str,
    ) -> Finding | None:
        """Test single injection payload."""
        url = safe_join(base_url, endpoint.path)

        try:
            response = await self._make_request(
                client, endpoint.method, url, headers,
                params={param_name: payload}
            )

            # Check for error indicators
            body = response.text.lower()
            error_patterns = [
                r"sql\s*(syntax|error)",
                r"mysql|postgresql|sqlite|oracle|mssql",
                r"unclosed\s*quotation",
                r"unterminated\s*string",
            ]

            for pattern in error_patterns:
                if re.search(pattern, body):
                    return Finding(
                        title=f"Potential {injection_type} Injection",
                        description=f"{endpoint.method} {endpoint.path} parameter '{param_name}' "
                                   f"may be vulnerable to {injection_type} injection",
                        severity=Severity.CRITICAL,
                        source="apisec.endpoint_tester",
                        data={
                            "endpoint": endpoint.path,
                            "parameter": param_name,
                            "payload": payload,
                        },
                    )

        except Exception:
            pass

        return None

    async def _test_mass_assignment(
        self,
        client: httpx.AsyncClient,
        url: str,
        endpoint: APIEndpoint,
        headers: dict,
    ) -> list[Finding]:
        """Test for mass assignment vulnerabilities."""
        findings = []

        # Try to add privileged fields
        privileged_fields = {
            "admin": True,
            "is_admin": True,
            "role": "admin",
            "roles": ["admin"],
            "permissions": ["*"],
            "verified": True,
            "email_verified": True,
        }

        try:
            response = await self._make_request(
                client, endpoint.method, url, headers,
                json_data=privileged_fields
            )

            # Check if any privileged fields were accepted
            if response.status_code in [200, 201]:
                try:
                    resp_data = response.json()
                    for field in privileged_fields:
                        if field in resp_data:
                            findings.append(Finding(
                                title="Potential Mass Assignment Vulnerability",
                                description=f"{endpoint.method} {endpoint.path} may accept "
                                           f"privileged field '{field}'",
                                severity=Severity.HIGH,
                                source="apisec.endpoint_tester",
                                data={"endpoint": endpoint.path, "field": field},
                            ))
                except Exception:
                    pass

        except Exception:
            pass

        return findings

    def _check_api_security(self, api: ParsedAPI) -> list[Finding]:
        """Check API-level security issues."""
        findings = []

        # Check for missing authentication
        unauthenticated_endpoints = [
            ep for ep in api.endpoints
            if not ep.security and ep.method in ["POST", "PUT", "PATCH", "DELETE"]
        ]

        if unauthenticated_endpoints:
            findings.append(Finding(
                title="Endpoints Without Authentication",
                description=f"{len(unauthenticated_endpoints)} write endpoints have no authentication defined",
                severity=Severity.MEDIUM,
                source="apisec.endpoint_tester",
                data={"endpoints": [ep.path for ep in unauthenticated_endpoints[:5]]},
            ))

        # Check for weak security schemes
        for name, scheme in api.security_schemes.items():
            if scheme.scheme_type == "http" and scheme.scheme == "basic":
                findings.append(Finding(
                    title="Basic Authentication Used",
                    description=f"API uses HTTP Basic Auth ({name}), which sends credentials in easily decoded format",
                    severity=Severity.MEDIUM,
                    source="apisec.endpoint_tester",
                    data={"scheme": name},
                ))

            if scheme.scheme_type == "apiKey" and scheme.location == "query":
                findings.append(Finding(
                    title="API Key in Query String",
                    description=f"API key ({name}) sent in query string, may be logged or cached",
                    severity=Severity.MEDIUM,
                    source="apisec.endpoint_tester",
                    data={"scheme": name},
                ))

        return findings
