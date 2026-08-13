"""Async nmap-based network scanner with scan profiles."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET

from core.logger import get_logger, scrub
from core.models import ScanResult, Severity, Target

logger = get_logger("vulnscan.scanner")

SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast scan of top 100 ports",
        "flags": ["-Pn", "-sV", "--top-ports", "100", "-T4"],
    },
    "normal": {
        "name": "Normal Scan",
        "description": "Balanced scan of top 1000 ports",
        "flags": ["-Pn", "-sV", "--top-ports", "1000", "-T3"],
    },
    "full": {
        "name": "Full Scan",
        "description": "All 65535 ports with OS detection",
        "flags": ["-Pn", "-sV", "-p", "1-65535", "-T3", "-O", "--osscan-guess"],
    },
    "stealth": {
        "name": "Stealth Scan",
        "description": "Slow, fragmented packets to avoid detection",
        "flags": ["-Pn", "-sV", "-p", "1-1000", "-T2", "-f"],
    },
    "lan": {
        "name": "LAN Scan",
        "description": "Aggressive timing for fast local network scans (no WAN)",
        "flags": ["-Pn", "-sV", "--top-ports", "1000", "-T4", "--min-rate", "500"],
    },
}

RISKY_PORTS: dict[int, str] = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 53: "DNS",
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB",
}


def expand_target(value: str) -> list[str]:
    """Expand CIDR, IP range, or comma-separated targets to a list of IP strings."""
    targets: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                targets.extend(str(ip) for ip in net.hosts())
            except ValueError:
                targets.append(part)
        elif "-" in part:
            # Handle 192.168.1.1-254 or 192.168.1.1-192.168.1.50
            try:
                left, right = part.rsplit("-", 1)
                if "." in right:
                    start = int(ipaddress.ip_address(left))
                    end = int(ipaddress.ip_address(right))
                    targets.extend(str(ipaddress.ip_address(i)) for i in range(start, end + 1))
                else:
                    base = ".".join(left.split(".")[:3])
                    start_last = int(left.split(".")[-1])
                    end_last = int(right)
                    targets.extend(
                        f"{base}.{i}" for i in range(start_last, end_last + 1)
                    )
            except (ValueError, IndexError):
                targets.append(part)
        else:
            targets.append(part)
    return targets


async def scan_host(
    ip: str,
    profile: str = "normal",
    custom_ports: list[int] | None = None,
) -> list[dict]:
    """
    Run nmap against a single host and return discovered services.
    Returns empty list if host is down or nmap fails.
    """
    if not shutil.which("nmap"):
        raise RuntimeError("nmap is not installed. Install with: sudo apt install nmap")

    profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES["normal"])
    flags = list(profile_cfg["flags"])

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_out = f.name

    try:
        cmd = ["nmap", "-oX", xml_out] + flags
        if custom_ports:
            # Remove any existing -p flag from profile and inject custom
            try:
                idx = cmd.index("-p")
                cmd.pop(idx)
                cmd.pop(idx)
            except ValueError:
                pass
            cmd += ["-p", ",".join(str(p) for p in custom_ports)]

        cmd.append(ip)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, _ = await proc.communicate()

        if proc.returncode != 0 or not os.path.exists(xml_out):
            return []

        return _parse_nmap_xml(xml_out, ip)
    finally:
        if os.path.exists(xml_out):
            os.unlink(xml_out)


def _parse_nmap_xml(xml_file: str, expected_ip: str) -> list[dict]:
    """Parse nmap XML output and return services list."""
    services = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall(".//host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            # Determine actual IP (may differ for hostnames)
            addr_elem = host.find("address[@addrtype='ipv4']")
            host_ip = addr_elem.get("addr", expected_ip) if addr_elem is not None else expected_ip

            # OS detection
            os_info: dict = {}
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                os_info = {
                    "name": osmatch.get("name", "Unknown"),
                    "accuracy": osmatch.get("accuracy", "0"),
                }

            for port_elem in host.findall(".//port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                svc = port_elem.find("service")

                service: dict = {
                    "target_ip": host_ip,
                    "port": port_id,
                    "protocol": protocol,
                    "name": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                    "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                }
                if os_info:
                    service["os_detection"] = os_info

                services.append(service)
    except ET.ParseError as e:
        logger.warning(f"Failed to parse nmap XML for {expected_ip}: {e}")

    return services


class NetworkScanner:
    """
    Async network vulnerability scanner.

    Scans one or more hosts (IP, CIDR, range, comma-separated)
    and returns a flat list of discovered services.
    """

    def __init__(
        self,
        profile: str = "normal",
        custom_ports: list[int] | None = None,
        max_parallel: int = 25,
    ):
        self.profile = profile
        self.custom_ports = custom_ports
        self.max_parallel = max_parallel
        self.logger = get_logger("vulnscan.scanner")

    async def scan(self, target_value: str) -> tuple[list[dict], list[str]]:
        """
        Scan target(s) and return (services, errors).

        Args:
            target_value: IP, CIDR, range, or comma-separated list

        Returns:
            Tuple of (discovered_services, error_messages)
        """
        ips = expand_target(target_value)
        if not ips:
            return [], [f"No valid IPs parsed from: {target_value}"]

        self.logger.info(f"Scanning {len(ips)} host(s) with profile '{scrub(self.profile)}'")

        semaphore = asyncio.Semaphore(self.max_parallel)
        errors: list[str] = []
        all_services: list[dict] = []
        lock = asyncio.Lock()

        async def scan_one(ip: str) -> None:
            async with semaphore:
                try:
                    services = await scan_host(ip, self.profile, self.custom_ports)
                    if services:
                        async with lock:
                            all_services.extend(services)
                except Exception as e:
                    async with lock:
                        errors.append(f"{ip}: {e}")

        await asyncio.gather(*[scan_one(ip) for ip in ips])
        return all_services, errors

    async def run(self, target: Target) -> ScanResult:
        """Security-suite compatible run() interface."""
        result = ScanResult(target=target, module="vulnscan.scanner")

        services, errors = await self.scan(target.value)
        for err in errors:
            result.errors.append(err)

        result.raw_data["services"] = services
        result.raw_data["profile"] = self.profile

        if not services:
            result.complete()
            return result

        risky = [
            {"port": s["port"], "service": RISKY_PORTS[s["port"]], "host": s["target_ip"]}
            for s in services if s["port"] in RISKY_PORTS
        ]

        result.add_finding(
            title="Open Services Discovered",
            description=f"Found {len(services)} open service(s) across all hosts",
            severity=Severity.INFO,
            data={"count": len(services), "services": services[:20]},
        )

        if risky:
            result.add_finding(
                title="High-Risk Services Exposed",
                description=f"{len(risky)} service(s) known to carry elevated risk",
                severity=Severity.HIGH,
                data={"services": risky},
            )

        result.complete()
        return result
