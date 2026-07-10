"""API Authentication security tester."""

import base64
import json
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from core import load_wordlist
from core.logger import get_logger
from core.models import Finding, ScanResult, Severity, Target
from modules.apisec.openapi_parser import ParsedAPI


@dataclass
class AuthTestResult:
    """Result of authentication testing."""
    findings: list[Finding] = field(default_factory=list)
    auth_bypasses: list[str] = field(default_factory=list)
    weak_tokens: list[str] = field(default_factory=list)


class APIAuthTester:
    """Authentication security tester for APIs."""

    # SecLists paths for JWT secret wordlists
    SECLISTS_JWT_PATHS = (
        "Passwords/scraped-JWT-secrets.txt",
    )

    # Common weak JWT secrets (built-in fallback)
    WEAK_JWT_SECRETS = [
        "secret",
        "password",
        "123456",
        "key",
        "private",
        "jwt_secret",
        "your-256-bit-secret",
        "your-secret-key",
    ]

    # Bypass techniques
    AUTH_BYPASS_HEADERS = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
    ]

    def __init__(self, timeout: float = 10.0, seclists_path: str | None = None):
        self.logger = get_logger("apisec.auth_tester")
        self.timeout = timeout
        # Load JWT secrets: SecLists file if available, else built-in fallback
        self.jwt_secrets: list[str] = load_wordlist(
            self.SECLISTS_JWT_PATHS,
            fallback=self.WEAK_JWT_SECRETS,
            seclists_path=seclists_path,
            max_entries=500,
        )

    async def test_api_auth(self, api: ParsedAPI) -> ScanResult:
        """Test API authentication security.

        Args:
            api: Parsed API specification

        Returns:
            Scan result with findings
        """
        target = Target.from_string(api.base_url)
        self.logger.info(f"Testing authentication for {api.title}")

        findings = []

        # Test authentication bypass
        bypass_findings = await self._test_auth_bypass(api)
        findings.extend(bypass_findings)

        # Test for broken authentication
        broken_auth_findings = await self._test_broken_auth(api)
        findings.extend(broken_auth_findings)

        # Test JWT security if applicable
        jwt_findings = self._analyze_jwt_security(api)
        findings.extend(jwt_findings)

        # Test rate limiting on auth endpoints
        rate_limit_findings = await self._test_auth_rate_limiting(api)
        findings.extend(rate_limit_findings)

        return ScanResult(
            module="apisec.auth_tester",
            target=target,
            success=True,
            findings=findings,
            data={"api_title": api.title},
        )

    async def _test_auth_bypass(self, api: ParsedAPI) -> list[Finding]:
        """Test for authentication bypass vulnerabilities."""
        findings = []

        # Find protected endpoints
        protected_endpoints = [
            ep for ep in api.endpoints
            if ep.security or any(
                tag.lower() in ["admin", "protected", "private"]
                for tag in ep.tags
            )
        ]

        if not protected_endpoints:
            return findings

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in protected_endpoints[:5]:  # Limit testing
                url = urljoin(api.base_url, endpoint.path)

                # Test without auth
                try:
                    response = await client.request(
                        method=endpoint.method,
                        url=url,
                        headers={"Accept": "application/json"},
                    )

                    if response.status_code == 200:
                        findings.append(Finding(
                            title="Authentication Bypass - No Auth Required",
                            description=f"{endpoint.method} {endpoint.path} accessible without authentication",
                            severity=Severity.CRITICAL,
                            source="apisec.auth_tester",
                            data={"endpoint": endpoint.path, "method": endpoint.method},
                        ))
                        continue

                except Exception:
                    pass

                # Test bypass headers
                for bypass_headers in self.AUTH_BYPASS_HEADERS:
                    try:
                        response = await client.request(
                            method=endpoint.method,
                            url=url,
                            headers={**bypass_headers, "Accept": "application/json"},
                        )

                        if response.status_code == 200:
                            findings.append(Finding(
                                title="Authentication Bypass via Header Manipulation",
                                description=f"{endpoint.method} {endpoint.path} bypassed using {list(bypass_headers.keys())}",
                                severity=Severity.CRITICAL,
                                source="apisec.auth_tester",
                                data={
                                    "endpoint": endpoint.path,
                                    "bypass_headers": bypass_headers,
                                },
                            ))
                            break

                    except Exception:
                        pass

        return findings

    async def _test_broken_auth(self, api: ParsedAPI) -> list[Finding]:
        """Test for broken authentication issues."""
        findings = []

        # Find login/auth endpoints
        auth_endpoints = [
            ep for ep in api.endpoints
            if any(
                keyword in ep.path.lower()
                for keyword in ["login", "auth", "token", "signin", "session"]
            )
        ]

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in auth_endpoints:
                url = urljoin(api.base_url, endpoint.path)

                # Test with empty credentials
                try:
                    response = await client.request(
                        method=endpoint.method,
                        url=url,
                        json={"username": "", "password": ""},
                        headers={"Content-Type": "application/json"},
                    )

                    if response.status_code == 200:
                        findings.append(Finding(
                            title="Empty Credentials Accepted",
                            description=f"{endpoint.method} {endpoint.path} accepts empty credentials",
                            severity=Severity.CRITICAL,
                            source="apisec.auth_tester",
                            data={"endpoint": endpoint.path},
                        ))

                except Exception:
                    pass

                # Test credential enumeration
                try:
                    # Test with known-invalid user
                    resp1 = await client.request(
                        method=endpoint.method,
                        url=url,
                        json={"username": "definitely_not_a_user_12345", "password": "wrong"},
                        headers={"Content-Type": "application/json"},
                    )

                    # Test with potentially valid user pattern
                    resp2 = await client.request(
                        method=endpoint.method,
                        url=url,
                        json={"username": "admin", "password": "wrong"},
                        headers={"Content-Type": "application/json"},
                    )

                    # Different responses may indicate user enumeration
                    if (resp1.status_code != resp2.status_code or
                        len(resp1.text) != len(resp2.text)):
                        findings.append(Finding(
                            title="Potential User Enumeration",
                            description=f"{endpoint.method} {endpoint.path} returns different responses for valid/invalid users",
                            severity=Severity.MEDIUM,
                            source="apisec.auth_tester",
                            data={"endpoint": endpoint.path},
                        ))

                except Exception:
                    pass

        return findings

    def _analyze_jwt_security(self, api: ParsedAPI) -> list[Finding]:
        """Analyze JWT security configuration."""
        findings = []

        for name, scheme in api.security_schemes.items():
            if scheme.scheme_type == "http" and scheme.scheme == "bearer":
                # Check bearer format
                if scheme.bearer_format and scheme.bearer_format.lower() == "jwt":
                    findings.append(Finding(
                        title="JWT Authentication Detected",
                        description=f"API uses JWT authentication ({name}). Ensure proper validation.",
                        severity=Severity.INFO,
                        source="apisec.auth_tester",
                        data={"scheme": name, "recommendations": [
                            "Verify JWT signature validation is enforced",
                            "Check for 'none' algorithm acceptance",
                            "Ensure tokens have reasonable expiration",
                            "Implement token refresh mechanism",
                        ]},
                    ))

        return findings

    async def test_jwt_vulnerabilities(
        self, token: str, api: ParsedAPI
    ) -> list[Finding]:
        """Test specific JWT for vulnerabilities.

        Args:
            token: JWT token to test
            api: Parsed API specification

        Returns:
            List of findings
        """
        findings = []

        try:
            # Decode JWT header and payload (without verification)
            parts = token.split(".")
            if len(parts) != 3:
                return findings

            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

            # Check for weak algorithm
            alg = header.get("alg", "").upper()
            if alg == "NONE":
                findings.append(Finding(
                    title="JWT None Algorithm",
                    description="JWT uses 'none' algorithm - signature not verified",
                    severity=Severity.CRITICAL,
                    source="apisec.auth_tester",
                ))
            elif alg == "HS256":
                findings.append(Finding(
                    title="JWT Symmetric Algorithm",
                    description="JWT uses HS256 - if secret is weak, tokens can be forged",
                    severity=Severity.LOW,
                    source="apisec.auth_tester",
                ))

            # Check for missing expiration
            if "exp" not in payload:
                findings.append(Finding(
                    title="JWT Missing Expiration",
                    description="JWT token has no expiration claim",
                    severity=Severity.MEDIUM,
                    source="apisec.auth_tester",
                ))

            # Check for sensitive data in payload
            sensitive_fields = ["password", "secret", "ssn", "credit_card"]
            for field in sensitive_fields:
                if field in payload:
                    findings.append(Finding(
                        title="Sensitive Data in JWT",
                        description=f"JWT payload contains sensitive field: {field}",
                        severity=Severity.HIGH,
                        source="apisec.auth_tester",
                    ))

            # Test algorithm confusion attack
            if alg.startswith("RS"):
                confusion_findings = await self._test_alg_confusion(
                    token, api
                )
                findings.extend(confusion_findings)

        except Exception as e:
            self.logger.debug(f"JWT analysis error: {e}")

        return findings

    async def _test_alg_confusion(
        self, token: str, api: ParsedAPI
    ) -> list[Finding]:
        """Test for JWT algorithm confusion vulnerability."""
        findings = []

        try:
            # This is a detection test, not exploitation
            parts = token.split(".")

            # Create test token with HS256 using public key as secret
            test_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
            ).decode().rstrip("=")

            # Keep original payload
            test_token = f"{test_header}.{parts[1]}.test_signature"

            # Try using the modified token
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for endpoint in api.endpoints[:3]:
                    if endpoint.security:
                        url = urljoin(api.base_url, endpoint.path)
                        try:
                            response = await client.request(
                                method=endpoint.method,
                                url=url,
                                headers={
                                    "Authorization": f"Bearer {test_token}",
                                    "Accept": "application/json",
                                },
                            )

                            # If we get a 200, algorithm confusion might be possible
                            if response.status_code == 200:
                                findings.append(Finding(
                                    title="Potential JWT Algorithm Confusion",
                                    description="API may be vulnerable to JWT algorithm confusion attack",
                                    severity=Severity.CRITICAL,
                                    source="apisec.auth_tester",
                                    data={"endpoint": endpoint.path},
                                ))
                                break

                        except Exception:
                            pass

        except Exception:
            pass

        return findings

    async def _test_auth_rate_limiting(self, api: ParsedAPI) -> list[Finding]:
        """Test rate limiting on authentication endpoints."""
        findings = []

        # Find auth endpoints
        auth_endpoints = [
            ep for ep in api.endpoints
            if any(
                keyword in ep.path.lower()
                for keyword in ["login", "auth", "token"]
            ) and ep.method == "POST"
        ]

        if not auth_endpoints:
            return findings

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in auth_endpoints[:2]:
                url = urljoin(api.base_url, endpoint.path)

                # Send multiple rapid requests
                responses = []
                for _ in range(10):
                    try:
                        response = await client.post(
                            url,
                            json={"username": "test", "password": "wrong"},
                            headers={"Content-Type": "application/json"},
                        )
                        responses.append(response.status_code)
                    except Exception:
                        break

                # Check if any rate limiting occurred
                if responses and 429 not in responses:
                    findings.append(Finding(
                        title="No Rate Limiting on Auth Endpoint",
                        description=f"{endpoint.path} has no rate limiting - vulnerable to brute force",
                        severity=Severity.MEDIUM,
                        source="apisec.auth_tester",
                        data={"endpoint": endpoint.path, "requests_sent": len(responses)},
                    ))

        return findings
