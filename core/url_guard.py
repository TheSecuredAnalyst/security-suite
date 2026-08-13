"""Outbound URL validation (SSRF guard).

Any module that fetches a URL supplied by an API caller must run it through
``validate_outbound_url`` first. Without this, a caller can point the server at
internal services (``http://169.254.169.254/`` for cloud metadata,
``http://127.0.0.1:6379/`` for Redis, ``file://`` for local files) and use the
suite as a proxy into networks it can reach but the caller cannot.

Operators who legitimately need to test RFC1918 targets can set
``SECSUITE_ALLOW_PRIVATE_TARGETS=true``, or pass ``allow_private=True`` at the
call site.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

from core.config import get_settings
from core.exceptions import InvalidTargetError
from core.logger import get_logger

logger = get_logger(__name__)

ALLOWED_SCHEMES = frozenset({"http", "https"})


class BlockedTargetError(InvalidTargetError):
    """Raised when a URL points somewhere we refuse to send a request."""

    def __init__(self, target: str, reason: str):
        self.reason = reason
        super().__init__(f"{target} ({reason})")


def _is_blocked_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if the address is anything other than a routable public host."""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _is_blocked_address(mapped)

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_host(host: str) -> list[str]:
    """Resolve a hostname to every address it maps to.

    A hostname can resolve to several records (A and AAAA, round-robin pools);
    all of them have to be safe, otherwise an attacker just retries until the
    resolver hands back the internal one.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise BlockedTargetError(host, f"DNS resolution failed: {exc}") from exc

    return sorted({info[4][0] for info in infos})


def validate_outbound_url(url: str, *, allow_private: bool | None = None) -> str:
    """Validate a user-supplied URL before it is used as a request target.

    Args:
        url: The candidate URL.
        allow_private: Permit private/loopback destinations. Defaults to the
            ``SECSUITE_ALLOW_PRIVATE_TARGETS`` setting.

    Returns:
        The normalized URL (fragment dropped, host lowercased) to request.

    Raises:
        BlockedTargetError: The URL is malformed, uses a non-HTTP scheme, or
            resolves to a non-public address.
    """
    if allow_private is None:
        allow_private = get_settings().allow_private_targets

    parts = urlsplit(url.strip())

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedTargetError(url, f"scheme '{parts.scheme}' is not http/https")

    if parts.username or parts.password:
        raise BlockedTargetError(url, "credentials in URL are not accepted")

    try:
        host = parts.hostname
        port = parts.port  # raises ValueError on a malformed port
    except ValueError as exc:
        raise BlockedTargetError(url, f"malformed host or port: {exc}") from exc

    if not host:
        raise BlockedTargetError(url, "no host component")

    if not allow_private:
        for address in resolve_host(host):
            ip = ipaddress.ip_address(address)
            if _is_blocked_address(ip):
                logger.warning(f"Blocked outbound request to {host} ({address})")
                raise BlockedTargetError(
                    url, f"resolves to non-public address {address}"
                )

    # Rebuild the URL from the validated components so that only the parts we
    # checked survive. Note this does not close the DNS-rebinding window: the
    # name is resolved again by the HTTP client. Public deployments should also
    # egress-filter the container/host.
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def safe_join(base_url: str, path: str) -> str:
    """Join a spec-supplied path onto a validated base URL, pinned to its origin.

    ``urljoin`` hands the whole URL over to the second argument when that
    argument is absolute or protocol-relative, so an OpenAPI spec containing
    ``"paths": {"http://169.254.169.254/latest/meta-data/": ...}`` would redirect
    a scan off the validated host. Only the path and query of `path` are used.

    Args:
        base_url: An origin already checked by validate_outbound_url().
        path: Endpoint path from a parsed specification.

    Returns:
        A URL on the same origin as `base_url`.
    """
    parts = urlsplit(path)
    if parts.scheme or parts.netloc:
        logger.warning(f"Ignoring absolute host in spec path: {path}")

    relative = urlunsplit(("", "", parts.path, parts.query, ""))
    if relative.startswith("//"):
        relative = "/" + relative.lstrip("/")

    return urljoin(base_url, relative)
