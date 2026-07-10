"""Port scanner module using nmap."""

import asyncio
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET

from core.models import ScanResult, Severity, Target
from modules.osint.base import OSINTModule


class PortScanner(OSINTModule):
    """Port scanning using nmap or fallback to socket-based scanning."""

    name = "port_scan"
    description = "Scan for open ports and services using nmap"

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017
    ]

    TOP_1000_PORTS = "1-1000"

    # Scan type presets
    SCAN_PRESETS = {
        "quick": {"flags": ["-T4", "-F"], "description": "Fast scan of common ports"},
        "full": {"flags": ["-T4", "-p-"], "description": "Scan all 65535 ports"},
        "default": {"flags": ["-T4", "-p", "1-1000"], "description": "Top 1000 ports"},
        "aggressive": {"flags": ["-T4", "-A", "-sV", "-sC"], "description": "Aggressive scan with OS detection and scripts"},
        "intense": {"flags": ["-T4", "-p-", "-A"], "description": "Intense scan: all ports + aggressive options"},
        "light": {"flags": ["-T5", "-p", "1-1000"], "description": "Light, fast scan"},
        "comprehensive": {"flags": ["-T3", "-p-", "-sV", "-sC", "-O"], "description": "Comprehensive scan with OS detection"},
    }

    def __init__(
        self,
        ports: str | None = None,
        scan_type: str = "default",
        enable_os_detection: bool = False,
        enable_scripts: bool = False,
        udp_scan: bool = False,
        timing_template: int = 3,
        service_version: bool = True,
        ping_before_scan: bool = True,
    ):
        super().__init__()
        self.ports = ports
        self.scan_type = scan_type
        self.enable_os_detection = enable_os_detection
        self.enable_scripts = enable_scripts
        self.udp_scan = udp_scan
        self.timing_template = max(0, min(5, timing_template))  # Clamp between 0-5
        self.service_version = service_version
        self.ping_before_scan = ping_before_scan
        self.nmap_available = shutil.which("nmap") is not None

    async def run(self, target: Target) -> ScanResult:
        """Scan target for open ports."""
        result = self.create_result(target)

        if target.target_type not in ("domain", "ip", "url"):
            result.errors.append(f"Invalid target type: {target.target_type}")
            result.success = False
            result.complete()
            return result

        host = self._extract_host(target.value)
        self.logger.info(f"Starting port scan on {host}")

        if self.nmap_available:
            await self._nmap_scan(host, result)
        else:
            self.logger.warning("nmap not found, using fallback socket scanner")
            await self._socket_scan(host, result)

        result.complete()
        return result

    async def _nmap_scan(self, host: str, result: ScanResult) -> None:
        """Run nmap scan and parse results."""
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            output_file = f.name

        try:
            cmd = ["nmap", "-oX", output_file]

            # Build nmap command based on scan type and options
            if self.scan_type in self.SCAN_PRESETS:
                cmd.extend(self.SCAN_PRESETS[self.scan_type]["flags"])
            else:
                # Use custom port specification
                cmd.extend([f"-T{self.timing_template}", "-p", self.ports or self.TOP_1000_PORTS])

            # Add optional flags
            if self.service_version and "-sV" not in cmd:
                cmd.append("-sV")

            if self.enable_os_detection:
                cmd.append("-O")

            if self.enable_scripts and "-sC" not in cmd:
                cmd.append("-sC")

            if self.udp_scan:
                cmd.append("-sU")

            if not self.ping_before_scan:
                cmd.append("-Pn")

            cmd.append(host)

            self.logger.info(f"Running: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                result.errors.append(f"nmap failed: {error_msg}")
                result.success = False
                return

            self._parse_nmap_xml(output_file, result)

        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    def _parse_nmap_xml(self, xml_file: str, result: ScanResult) -> None:
        """Parse nmap XML output."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            open_ports = []
            services = []
            os_detection = {}

            for host in root.findall(".//host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                # Parse OS detection if available
                osmatch = host.find(".//osmatch")
                if osmatch is not None:
                    os_detection = {
                        "name": osmatch.get("name", "Unknown"),
                        "accuracy": osmatch.get("accuracy", "0"),
                    }

                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        protocol = port.get("protocol", "tcp")

                        service_elem = port.find("service")
                        service_info = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": "open",
                        }

                        if service_elem is not None:
                            service_info["service"] = service_elem.get("name", "unknown")
                            service_info["product"] = service_elem.get("product", "")
                            service_info["version"] = service_elem.get("version", "")
                            service_info["extrainfo"] = service_elem.get("extrainfo", "")

                        open_ports.append(int(port_id))
                        services.append(service_info)

            result.raw_data["open_ports"] = open_ports
            result.raw_data["services"] = services

            if os_detection:
                result.raw_data["os_detection"] = os_detection

            if open_ports:
                result.add_finding(
                    title="Open Ports Discovered",
                    description=f"Found {len(open_ports)} open port(s)",
                    severity=Severity.INFO,
                    data={"ports": open_ports, "services": services},
                )

                risky_ports = {
                    21: "FTP", 23: "Telnet", 445: "SMB",
                    3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
                }

                found_risky = [
                    {"port": p, "service": risky_ports[p]}
                    for p in open_ports if p in risky_ports
                ]

                if found_risky:
                    result.add_finding(
                        title="Potentially Risky Services Exposed",
                        description=f"Found {len(found_risky)} service(s) that may pose security risks",
                        severity=Severity.MEDIUM,
                        data={"services": found_risky},
                    )

            # Add OS detection finding if available
            if os_detection:
                result.add_finding(
                    title="Operating System Detected",
                    description=f"Detected OS: {os_detection['name']} (Accuracy: {os_detection['accuracy']}%)",
                    severity=Severity.INFO,
                    data=os_detection,
                )

        except ET.ParseError as e:
            result.errors.append(f"Failed to parse nmap output: {e}")

    async def _socket_scan(self, host: str, result: ScanResult) -> None:
        """Fallback socket-based port scanner."""
        open_ports = []
        ports_to_scan = self.COMMON_PORTS
        semaphore = asyncio.Semaphore(100)

        async def check_port(port: int) -> int | None:
            async with semaphore:
                try:
                    conn = asyncio.open_connection(host, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=2.0)
                    writer.close()
                    await writer.wait_closed()
                    return port
                except Exception:
                    return None

        self.logger.info(f"Scanning {len(ports_to_scan)} common ports...")
        tasks = [check_port(p) for p in ports_to_scan]
        results = await asyncio.gather(*tasks)

        open_ports = [p for p in results if p is not None]

        result.raw_data["open_ports"] = open_ports
        result.raw_data["scan_method"] = "socket"

        if open_ports:
            result.add_finding(
                title="Open Ports Discovered",
                description=f"Found {len(open_ports)} open port(s)",
                severity=Severity.INFO,
                data={"ports": sorted(open_ports)},
            )

    def _extract_host(self, value: str) -> str:
        if value.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            return urlparse(value).netloc
        return value
