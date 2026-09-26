#!/usr/bin/env python3
"""Offline demo of the correlation engine — the "show, don't tell" artifact.

Runs the real engine over a scripted, realistic set of scan results (no network,
no live target) so anyone can reproduce the attack paths in one command:

    python examples/correlation_demo.py

It builds a provenance graph the same way ``secsuite correlate`` does, then
prints every correlation that fires with its evidence and the chain that led
there — e.g. ``demo.example.com -> 445/tcp smb -> CVE-2017-0144``.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from core.models import ScanResult, Severity, Target
from modules.correlation import CorrelationEngine, build_graph, load_rules
from modules.correlation.rules import _SEVERITY_RANK

console = Console()
TARGET = "demo.example.com"


def _scripted_results() -> list[ScanResult]:
    """A believable single-target run: recon + discovery + injection + a CVE."""
    services = [
        {"port": 445, "protocol": "tcp", "service": "smb", "product": "Samba", "version": "3.0.0"},
        {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18.0"},
    ]

    ports = ScanResult(target=Target.from_string(TARGET), module="osint.port_scan")
    ports.raw_data["services"] = services
    ports.add_finding("Open Ports Discovered", "2 open ports", data={"services": services})

    dns = ScanResult(target=Target.from_string(TARGET), module="osint.dns")
    dns.add_finding("A record", "resolved to 203.0.113.10")

    crawler = ScanResult(target=Target.from_string(TARGET), module="webscanner.crawler")
    crawler.add_finding("Endpoints discovered", "17 URLs, 3 with parameters")

    sqli = ScanResult(target=Target.from_string(TARGET), module="webscanner.sqli")
    sqli.add_finding(
        "SQL injection in `id` parameter",
        "Error-based SQLi confirmed on /item?id=",
        severity=Severity.HIGH,
        data={"url": f"http://{TARGET}/item?id=1"},
    )

    # What CVE enrichment would produce for the discovered Samba service.
    cve = ScanResult(target=Target.from_string(TARGET), module="vulnscan.cve_lookup")
    cve.add_finding(
        "CVE-2017-0144 (Samba 3.0.0)",
        "Remote code execution in SMBv1 (EternalBlue).",
        severity=Severity.CRITICAL,
        data={"cve_id": "CVE-2017-0144", "cvss_score": 9.3, "product": "Samba", "port": 445},
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    )

    return [ports, dns, crawler, sqli, cve]


def main() -> None:
    results = _scripted_results()
    findings = [f for r in results for f in r.findings]
    graph = build_graph(TARGET, results)

    engine = CorrelationEngine(load_rules())
    correlations = engine.evaluate(findings, graph)

    console.print()
    console.print(
        f"[bold]SecSuite correlation demo[/bold] — target [cyan]{TARGET}[/cyan]: "
        f"{len(findings)} findings across {len(results)} scans, "
        f"{len(engine.rules)} rules → [bold]{len(correlations)} correlations[/bold]\n"
    )

    sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "green"}
    for c in sorted(correlations, key=lambda x: _SEVERITY_RANK[x.severity], reverse=True):
        color = sev_color.get(c.severity.value, "white")
        body = c.description.strip()
        if c.attack_path:
            body += f"\n\n[bold]Path:[/bold] {c.attack_path}"
        elif c.anchor:
            body += f"\n\n[bold]Host:[/bold] {c.anchor}"
        body += f"\n[dim]Evidence: {', '.join(f.title for f in c.evidence)}[/dim]"
        if c.mitre:
            body += f"\n[dim]MITRE: {', '.join(c.mitre)}[/dim]"
        console.print(Panel(body, title=f"[{color}]{c.severity.value.upper()}[/{color}] {c.name}"))

    console.print(
        "\n[dim]Reproduce a live run with:[/dim] "
        f"[cyan]secsuite correlate {TARGET}[/cyan]  "
        "[dim](add --rules ./my-rules to load your own)[/dim]"
    )


if __name__ == "__main__":
    main()
