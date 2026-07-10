"""API Fuzzer for automated security testing."""

import asyncio
import random
import string
from collections.abc import AsyncIterator
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from core import load_wordlist
from core.logger import get_logger
from core.models import Finding, ScanResult, Severity, Target
from modules.apisec.openapi_parser import APIEndpoint, APIParameter, ParsedAPI


@dataclass
class FuzzResult:
    """Result of a fuzz test."""
    endpoint: str
    method: str
    parameter: str
    payload: str
    status_code: int
    response_time: float
    anomaly: bool = False
    finding: Finding | None = None


class APIFuzzer:
    """Automated API fuzzer for security testing."""

    # SecLists paths for general fuzzing strings
    SECLISTS_FUZZ_PATHS = (
        "Fuzzing/big-list-of-naughty-strings.txt",
        "Fuzzing/FuzzingStrings-SkullSecurity.org.txt",
    )

    # Fuzz payloads by category
    PAYLOADS = {
        "string": [
            "",  # Empty
            " ",  # Space
            "null",
            "undefined",
            "None",
            "true",
            "false",
            "0",
            "-1",
            "999999999999",
            "A" * 1000,  # Long string
            "A" * 10000,  # Very long string
            "<script>alert(1)</script>",  # XSS
            "{{7*7}}",  # Template injection
            "${7*7}",  # Template injection
            "#{7*7}",  # Template injection
            "../../../etc/passwd",  # Path traversal
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%00",  # Null byte
            "%0d%0a",  # CRLF
            "\r\n",  # CRLF
            "admin'--",  # SQL
            "1; DROP TABLE users",  # SQL
            '{"$gt": ""}',  # NoSQL
            "`id`",  # Command injection
            "| ls",  # Command injection
        ],
        "integer": [
            0,
            -1,
            1,
            2147483647,  # Max int32
            -2147483648,  # Min int32
            9999999999999999,  # Large number
            1.5,  # Float as int
            "1",  # String as int
            "abc",  # Invalid
            None,
        ],
        "boolean": [
            True,
            False,
            "true",
            "false",
            1,
            0,
            "yes",
            "no",
            None,
        ],
        "array": [
            [],
            [None],
            [""],
            [1, 2, 3] * 1000,  # Large array
            "not_an_array",
        ],
        "object": [
            {},
            None,
            {"__proto__": {"admin": True}},  # Prototype pollution
            {"constructor": {"prototype": {"admin": True}}},
            "not_an_object",
        ],
    }

    def __init__(
        self,
        timeout: float = 10.0,
        max_requests: int = 100,
        delay: float = 0.1,
        auth_token: str | None = None,
        seclists_path: str | None = None,
    ):
        self.logger = get_logger("apisec.fuzzer")
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        self.auth_token = auth_token
        # Extend string payloads with curated SecLists naughty strings (capped at 200)
        self._seclists_strings: list[str] = load_wordlist(
            self.SECLISTS_FUZZ_PATHS,
            fallback=[],
            seclists_path=seclists_path,
            max_entries=200,
        )

    async def fuzz_api(self, api: ParsedAPI) -> ScanResult:
        """Fuzz all endpoints in an API.

        Args:
            api: Parsed API specification

        Returns:
            Scan result with findings
        """
        target = Target.from_string(api.base_url)
        self.logger.info(f"Fuzzing {api.title} ({len(api.endpoints)} endpoints)")

        all_findings = []
        request_count = 0

        async for result in self._fuzz_endpoints(api):
            if result.finding:
                all_findings.append(result.finding)

            request_count += 1
            if request_count >= self.max_requests:
                self.logger.info(f"Reached max requests limit ({self.max_requests})")
                break

        return ScanResult(
            module="apisec.fuzzer",
            target=target,
            success=True,
            findings=all_findings,
            data={
                "api_title": api.title,
                "requests_sent": request_count,
                "findings_count": len(all_findings),
            },
        )

    async def _fuzz_endpoints(self, api: ParsedAPI) -> AsyncIterator[FuzzResult]:
        """Fuzz all endpoints.

        Yields:
            FuzzResult for each test
        """
        headers = self._get_headers()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in api.endpoints:
                # Get baseline response
                baseline = await self._get_baseline(client, api.base_url, endpoint, headers)

                # Fuzz each parameter
                for param in endpoint.parameters:
                    payloads = self._get_payloads_for_type(param.param_type)

                    for payload in payloads:
                        result = await self._fuzz_parameter(
                            client, api.base_url, endpoint, param, payload, headers, baseline
                        )
                        yield result

                        if self.delay:
                            await asyncio.sleep(self.delay)

                # Fuzz request body if applicable
                if endpoint.request_body and endpoint.method in ["POST", "PUT", "PATCH"]:
                    async for result in self._fuzz_body(
                        client, api.base_url, endpoint, headers, baseline
                    ):
                        yield result

    def _get_headers(self) -> dict:
        """Get request headers."""
        headers = {
            "User-Agent": "SecuritySuite-Fuzzer/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        return headers

    async def _get_baseline(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: APIEndpoint,
        headers: dict,
    ) -> httpx.Response | None:
        """Get baseline response for comparison."""
        url = urljoin(base_url, endpoint.path.replace("{", "1").replace("}", ""))

        try:
            return await client.request(
                method=endpoint.method,
                url=url,
                headers=headers,
            )
        except Exception:
            return None

    def _get_payloads_for_type(self, param_type: str) -> list:
        """Get fuzz payloads for parameter type."""
        type_lower = param_type.lower()

        if type_lower in ("integer", "number", "int", "float"):
            return self.PAYLOADS["integer"]
        elif type_lower in ("boolean", "bool"):
            return self.PAYLOADS["boolean"]
        elif type_lower == "array":
            return self.PAYLOADS["array"]
        elif type_lower == "object":
            return self.PAYLOADS["object"]
        else:
            # Combine built-in payloads with SecLists payloads (deduplicated, stable order)
            builtin = list(self.PAYLOADS["string"])
            extra = [payload for payload in self._seclists_strings if payload not in builtin]
            return builtin + extra

    async def _fuzz_parameter(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: APIEndpoint,
        param: APIParameter,
        payload: any,
        headers: dict,
        baseline: httpx.Response | None,
    ) -> FuzzResult:
        """Fuzz a single parameter."""
        url = urljoin(base_url, endpoint.path.replace("{", "1").replace("}", ""))

        result = FuzzResult(
            endpoint=endpoint.path,
            method=endpoint.method,
            parameter=param.name,
            payload=str(payload)[:100],  # Truncate for logging
            status_code=0,
            response_time=0.0,
        )

        try:
            # Build request based on parameter location
            kwargs = {"headers": headers}

            if param.location == "query":
                kwargs["params"] = {param.name: payload}
            elif param.location == "path":
                url = url.replace("1", str(payload))
            elif param.location == "header":
                kwargs["headers"] = {**headers, param.name: str(payload)}

            response = await client.request(
                method=endpoint.method,
                url=url,
                **kwargs,
            )

            result.status_code = response.status_code
            result.response_time = response.elapsed.total_seconds()

            # Check for anomalies
            finding = self._check_anomaly(endpoint, param, payload, response, baseline)
            if finding:
                result.anomaly = True
                result.finding = finding

        except httpx.TimeoutException:
            result.anomaly = True
            result.finding = Finding(
                title="Request Timeout on Fuzz Input",
                description=f"{endpoint.method} {endpoint.path} timed out with payload in {param.name}",
                severity=Severity.LOW,
                source="apisec.fuzzer",
                data={"parameter": param.name, "payload": str(payload)[:100]},
            )
        except Exception as e:
            self.logger.debug(f"Fuzz error: {e}")

        return result

    async def _fuzz_body(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: APIEndpoint,
        headers: dict,
        baseline: httpx.Response | None,
    ) -> AsyncIterator[FuzzResult]:
        """Fuzz request body."""
        url = urljoin(base_url, endpoint.path.replace("{", "1").replace("}", ""))

        # Test various malformed bodies
        test_bodies = [
            None,  # Null
            "",  # Empty string
            "not json",  # Invalid JSON
            [],  # Array instead of object
            {"__proto__": {"admin": True}},  # Prototype pollution
            {"a": "b" * 10000},  # Large value
        ]

        for body in test_bodies:
            result = FuzzResult(
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter="request_body",
                payload=str(body)[:100],
                status_code=0,
                response_time=0.0,
            )

            try:
                if body is None:
                    response = await client.request(
                        method=endpoint.method,
                        url=url,
                        headers=headers,
                    )
                elif isinstance(body, str):
                    response = await client.request(
                        method=endpoint.method,
                        url=url,
                        headers=headers,
                        content=body,
                    )
                else:
                    response = await client.request(
                        method=endpoint.method,
                        url=url,
                        headers=headers,
                        json=body,
                    )

                result.status_code = response.status_code
                result.response_time = response.elapsed.total_seconds()

                # Check for anomalies
                finding = self._check_body_anomaly(endpoint, body, response, baseline)
                if finding:
                    result.anomaly = True
                    result.finding = finding

            except Exception as e:
                self.logger.debug(f"Body fuzz error: {e}")

            yield result

            if self.delay:
                await asyncio.sleep(self.delay)

    def _check_anomaly(
        self,
        endpoint: APIEndpoint,
        param: APIParameter,
        payload: any,
        response: httpx.Response,
        baseline: httpx.Response | None,
    ) -> Finding | None:
        """Check for anomalies in response."""
        body = response.text.lower()

        # Check for error disclosure
        error_patterns = [
            ("stack trace", "Stack Trace Disclosure", Severity.MEDIUM),
            ("exception", "Exception Disclosure", Severity.MEDIUM),
            ("sql syntax", "SQL Error Disclosure", Severity.HIGH),
            ("mysql", "Database Error Disclosure", Severity.HIGH),
            ("postgresql", "Database Error Disclosure", Severity.HIGH),
            ("syntax error", "Syntax Error Disclosure", Severity.MEDIUM),
            ("undefined", "Undefined Variable Disclosure", Severity.LOW),
            ("null pointer", "Null Pointer Disclosure", Severity.MEDIUM),
        ]

        for pattern, title, severity in error_patterns:
            if pattern in body:
                # Verify it's not in baseline
                if baseline and pattern in baseline.text.lower():
                    continue

                return Finding(
                    title=title,
                    description=f"{endpoint.method} {endpoint.path} exposes {title.lower()} "
                               f"when parameter '{param.name}' receives fuzz input",
                    severity=severity,
                    source="apisec.fuzzer",
                    data={
                        "parameter": param.name,
                        "payload": str(payload)[:100],
                        "status_code": response.status_code,
                    },
                )

        # Check for reflected input (potential XSS)
        payload_str = str(payload)
        if len(payload_str) > 3 and payload_str in response.text:
            if "<script>" in payload_str or "{{" in payload_str:
                return Finding(
                    title="Input Reflection (Potential XSS/Injection)",
                    description=f"{endpoint.method} {endpoint.path} reflects input from '{param.name}' in response",
                    severity=Severity.MEDIUM,
                    source="apisec.fuzzer",
                    data={
                        "parameter": param.name,
                        "payload": payload_str[:100],
                    },
                )

        # Check for unexpected 200 on invalid input
        if response.status_code == 200 and baseline:
            if baseline.status_code != 200:
                return Finding(
                    title="Unexpected Success on Invalid Input",
                    description=f"{endpoint.method} {endpoint.path} returns 200 with invalid input in '{param.name}'",
                    severity=Severity.LOW,
                    source="apisec.fuzzer",
                    data={
                        "parameter": param.name,
                        "payload": str(payload)[:100],
                    },
                )

        # Check for 500 errors (unhandled exceptions)
        if response.status_code >= 500:
            return Finding(
                title="Server Error on Fuzz Input",
                description=f"{endpoint.method} {endpoint.path} returns {response.status_code} "
                           f"with fuzz input in '{param.name}'",
                severity=Severity.MEDIUM,
                source="apisec.fuzzer",
                data={
                    "parameter": param.name,
                    "payload": str(payload)[:100],
                    "status_code": response.status_code,
                },
            )

        return None

    def _check_body_anomaly(
        self,
        endpoint: APIEndpoint,
        body: any,
        response: httpx.Response,
        baseline: httpx.Response | None,
    ) -> Finding | None:
        """Check for anomalies in body fuzz response."""
        resp_text = response.text.lower()

        # Check for prototype pollution indicators
        if isinstance(body, dict) and "__proto__" in body:
            if "admin" in resp_text or response.status_code == 200:
                return Finding(
                    title="Potential Prototype Pollution",
                    description=f"{endpoint.method} {endpoint.path} may be vulnerable to prototype pollution",
                    severity=Severity.HIGH,
                    source="apisec.fuzzer",
                    data={"endpoint": endpoint.path},
                )

        # Check for 500 on malformed body
        if response.status_code >= 500:
            return Finding(
                title="Server Error on Malformed Body",
                description=f"{endpoint.method} {endpoint.path} returns {response.status_code} with malformed body",
                severity=Severity.MEDIUM,
                source="apisec.fuzzer",
                data={
                    "body": str(body)[:100],
                    "status_code": response.status_code,
                },
            )

        return None

    def generate_random_string(self, length: int = 10) -> str:
        """Generate random string for fuzzing."""
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))
