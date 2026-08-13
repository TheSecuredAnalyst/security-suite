"""Syslog exporter for traditional SIEM integration."""

import asyncio
import socket
import ssl
from enum import IntEnum

from modules.siem.base import SIEMEvent, SIEMExporter


class SyslogFacility(IntEnum):
    """Syslog facility codes."""
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(IntEnum):
    """Syslog severity codes."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


class SyslogExporter(SIEMExporter):
    """Export events via Syslog (UDP/TCP/TLS)."""

    SEVERITY_MAP = {
        "critical": SyslogSeverity.CRITICAL,
        "high": SyslogSeverity.ERROR,
        "medium": SyslogSeverity.WARNING,
        "low": SyslogSeverity.NOTICE,
        "info": SyslogSeverity.INFO,
    }

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",  # udp, tcp, tls
        facility: SyslogFacility = SyslogFacility.LOCAL0,
        format: str = "cef",  # cef, leef, rfc5424, rfc3164
        app_name: str = "security-suite",
        use_tls: bool = False,
        tls_verify: bool = True,
        timeout: float = 5.0,
    ):
        """Initialize Syslog exporter.

        Args:
            host: Syslog server hostname/IP
            port: Syslog server port
            protocol: Transport protocol (udp, tcp, tls)
            facility: Syslog facility
            format: Message format (cef, leef, rfc5424, rfc3164)
            app_name: Application name for syslog header
            use_tls: Use TLS for TCP connections
            tls_verify: Verify TLS certificates
            timeout: Connection timeout
        """
        super().__init__()
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.facility = facility
        self.format = format.lower()
        self.app_name = app_name
        self.use_tls = use_tls or protocol == "tls"
        self.tls_verify = tls_verify
        self.timeout = timeout

        self._socket: socket.socket | None = None

    def _get_priority(self, severity: str) -> int:
        """Calculate syslog priority (facility * 8 + severity)."""
        sev = self.SEVERITY_MAP.get(severity.lower(), SyslogSeverity.INFO)
        return (self.facility * 8) + sev

    def _format_message(self, event: SIEMEvent) -> str:
        """Format event as syslog message."""
        if self.format == "cef":
            return event.to_cef()
        elif self.format == "leef":
            return event.to_leef()
        elif self.format == "rfc5424":
            return self._format_rfc5424(event)
        else:  # rfc3164
            return self._format_rfc3164(event)

    def _format_rfc3164(self, event: SIEMEvent) -> str:
        """Format as RFC 3164 (BSD syslog)."""
        priority = self._get_priority(event.severity)
        timestamp = event.timestamp.strftime("%b %d %H:%M:%S")
        hostname = event.target or socket.gethostname()

        # Truncate hostname if needed
        if len(hostname) > 255:
            hostname = hostname[:255]

        return f"<{priority}>{timestamp} {hostname} {self.app_name}: {event.message}"

    def _format_rfc5424(self, event: SIEMEvent) -> str:
        """Format as RFC 5424 (modern syslog)."""
        priority = self._get_priority(event.severity)
        timestamp = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = event.target or socket.gethostname()
        msgid = event.event_type.value

        # Structured data
        sd = f'[security-suite@0 module="{event.module}" severity="{event.severity}"'
        if event.finding_title:
            sd += f' finding="{event.finding_title[:100]}"'
        sd += "]"

        return f"<{priority}>1 {timestamp} {hostname} {self.app_name} - {msgid} {sd} {event.message}"

    def _get_socket(self) -> socket.socket:
        """Get or create socket connection."""
        if self._socket is None:
            if self.protocol == "udp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.timeout)

                if self.use_tls:
                    context = ssl.create_default_context()
                    # create_default_context() still permits TLS 1.0/1.1 on
                    # older OpenSSL builds; syslog forwarding carries finding
                    # detail, so require TLS 1.2 or better.
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    if not self.tls_verify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    self._socket = context.wrap_socket(
                        self._socket, server_hostname=self.host
                    )

                self._socket.connect((self.host, self.port))

        return self._socket

    async def export(self, event: SIEMEvent) -> bool:
        """Export event via Syslog.

        Args:
            event: Event to export

        Returns:
            True if successful
        """
        message = self._format_message(event)

        # Ensure message ends with newline for TCP
        if self.protocol != "udp" and not message.endswith("\n"):
            message += "\n"

        message_bytes = message.encode("utf-8")

        try:
            # Run blocking socket operations in executor
            loop = asyncio.get_event_loop()

            if self.protocol == "udp":
                await loop.run_in_executor(
                    None,
                    lambda: self._send_udp(message_bytes)
                )
            else:
                await loop.run_in_executor(
                    None,
                    lambda: self._send_tcp(message_bytes)
                )

            self.logger.debug(f"Syslog message sent: {event.event_type}")
            return True

        except Exception as e:
            self.logger.error(f"Syslog export failed: {e}")
            self._socket = None  # Reset socket on error
            return False

    def _send_udp(self, message: bytes) -> None:
        """Send message via UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message, (self.host, self.port))
        finally:
            sock.close()

    def _send_tcp(self, message: bytes) -> None:
        """Send message via TCP/TLS."""
        sock = self._get_socket()
        sock.sendall(message)

    async def test_connection(self) -> bool:
        """Test connection to Syslog server.

        Returns:
            True if connection successful
        """
        try:
            if self.protocol == "udp":
                # UDP is connectionless, just verify we can create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.close()
                return True
            else:
                # Try to connect
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._get_socket)
                return True

        except Exception as e:
            self.logger.error(f"Syslog connection test failed: {e}")
            return False

    def close(self) -> None:
        """Close socket connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def get_config_info(self) -> dict:
        """Get exporter configuration info."""
        return {
            "type": "syslog",
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "format": self.format,
            "facility": self.facility.name,
        }
