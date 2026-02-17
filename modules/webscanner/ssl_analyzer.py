"""SSL/TLS certificate and configuration analyzer."""

import ssl
import socket
import asyncio
from datetime import datetime
from typing import Optional

from core.models import Target, ScanResult, Severity
from modules.webscanner.base import WebScannerModule


class SSLAnalyzer(WebScannerModule):
    """Analyze SSL/TLS configuration and certificates."""

    name = "ssl"
    description = "Analyze SSL/TLS certificates and configuration"

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"
    ]

    def __init__(self):
        super().__init__()

    async def run(self, target: Target) -> ScanResult:
        """Analyze SSL/TLS configuration."""
        result = self.create_result(target)

        host = self._extract_host(target.value)
        port = 443
        self.logger.info(f"Analyzing SSL/TLS for {host}:{port}")

        try:
            # Get certificate info
            cert_info = await self._get_certificate(host, port)
            if cert_info:
                result.raw_data["certificate"] = cert_info

                result.add_finding(
                    title="Certificate Information",
                    description=f"Certificate issued to {cert_info.get('subject', 'Unknown')}",
                    severity=Severity.INFO,
                    data=cert_info,
                )

                # Check expiration
                if cert_info.get("not_after"):
                    expiry = datetime.fromisoformat(cert_info["not_after"])
                    days_until_expiry = (expiry - datetime.now()).days

                    if days_until_expiry < 0:
                        result.add_finding(
                            title="Certificate Expired",
                            description=f"Certificate expired {abs(days_until_expiry)} days ago",
                            severity=Severity.CRITICAL,
                        )
                    elif days_until_expiry < 30:
                        result.add_finding(
                            title="Certificate Expiring Soon",
                            description=f"Certificate expires in {days_until_expiry} days",
                            severity=Severity.MEDIUM,
                        )

                # Check for self-signed
                if cert_info.get("issuer") == cert_info.get("subject"):
                    result.add_finding(
                        title="Self-Signed Certificate",
                        description="Certificate appears to be self-signed",
                        severity=Severity.MEDIUM,
                    )

            # Check TLS versions
            tls_versions = await self._check_tls_versions(host, port)
            result.raw_data["tls_versions"] = tls_versions

            if tls_versions:
                supported = [v for v, s in tls_versions.items() if s]

                if not supported:
                    result.add_finding(
                        title="No TLS/SSL Configured",
                        description=f"No TLS/SSL listener detected on {host}:{port} - traffic is unencrypted",
                        severity=Severity.HIGH,
                        data=tls_versions,
                    )
                else:
                    result.add_finding(
                        title="TLS Versions Supported",
                        description=f"Supported: {', '.join(supported)}",
                        severity=Severity.INFO,
                        data=tls_versions,
                    )

                # Flag old TLS versions
                if tls_versions.get("TLSv1.0") or tls_versions.get("TLSv1.1"):
                    result.add_finding(
                        title="Deprecated TLS Versions Enabled",
                        description="TLSv1.0 or TLSv1.1 is still enabled - these are deprecated",
                        severity=Severity.MEDIUM,
                        references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                    )

                if tls_versions.get("SSLv3"):
                    result.add_finding(
                        title="SSLv3 Enabled",
                        description="SSLv3 is enabled - vulnerable to POODLE attack",
                        severity=Severity.HIGH,
                    )

        except Exception as e:
            result.errors.append(f"SSL analysis failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    async def _get_certificate(self, host: str, port: int) -> Optional[dict]:
        """Get SSL certificate information."""
        try:
            loop = asyncio.get_event_loop()

            def get_cert():
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        if not cert:
                            # Get cert without validation
                            cert_bin = ssock.getpeercert(binary_form=True)
                            if cert_bin:
                                import ssl as ssl_module
                                cert = ssl_module._ssl._test_decode_cert(cert_bin)
                        return cert, ssock.version()

            cert, version = await loop.run_in_executor(None, get_cert)

            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                return {
                    "subject": subject.get("commonName", "Unknown"),
                    "issuer": issuer.get("commonName", "Unknown"),
                    "issuer_org": issuer.get("organizationName", "Unknown"),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "serial": cert.get("serialNumber", ""),
                    "version": version,
                    "san": [x[1] for x in cert.get("subjectAltName", [])],
                }
        except Exception as e:
            self.logger.debug(f"Certificate fetch error: {e}")

        return None

    async def _check_tls_versions(self, host: str, port: int) -> dict:
        """Check which TLS versions are supported."""
        versions = {
            "SSLv3": ssl.PROTOCOL_SSLv23,
            "TLSv1.0": ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None,
            "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None,
            "TLSv1.3": None,  # Checked separately
        }

        results = {}
        loop = asyncio.get_event_loop()

        for version_name, protocol in versions.items():
            if protocol is None and version_name != "TLSv1.3":
                continue

            def check_version(proto, vname):
                try:
                    if vname == "TLSv1.3":
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.minimum_version = ssl.TLSVersion.TLSv1_3
                        context.maximum_version = ssl.TLSVersion.TLSv1_3
                    else:
                        context = ssl.SSLContext(proto)

                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((host, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=host):
                            return True
                except Exception:
                    return False

            try:
                supported = await loop.run_in_executor(None, check_version, protocol, version_name)
                results[version_name] = supported
            except Exception:
                results[version_name] = False

        return results

    def _extract_host(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            return urlparse(value).netloc
        return value
