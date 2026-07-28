"""Main CLI entry point for Security Suite."""

import asyncio
import random

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.config import get_settings
from core.guardrails import guardrails
from core.logger import setup_logging
from core.models import Target
from core.wordlists import seclists_status

console = Console()

# ASCII Art Banners (Metasploit-style)
BANNERS = [
    r"""
[cyan]
   ____            ____        _ __
  / __/__ ___     / __/_ __(_) /____
 _\ \/ -_) __/   _\ \/ // / / __/ -_)
/___/\__/\__/   /___/\_,_/_/\__/\__/
[/cyan]
""",
    r"""
[cyan]
███████╗███████╗ ██████╗███████╗██╗   ██╗██╗████████╗███████╗
██╔════╝██╔════╝██╔════╝██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
███████╗█████╗  ██║     ███████╗██║   ██║██║   ██║   █████╗
╚════██║██╔══╝  ██║     ╚════██║██║   ██║██║   ██║   ██╔══╝
███████║███████╗╚██████╗███████║╚██████╔╝██║   ██║   ███████╗
╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
[/cyan]
""",
    r"""
[cyan]
  ██████ ▓█████  ▄████▄    ██████  █    ██  ██▓▄▄▄█████▓▓█████
▒██    ▒ ▓█   ▀ ▒██▀ ▀█  ▒██    ▒  ██  ▓██▒▓██▒▓  ██▒ ▓▒▓█   ▀
░ ▓██▄   ▒███   ▒▓█    ▄ ░ ▓██▄   ▓██  ▒██░▒██▒▒ ▓██░ ▒░▒███
  ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒  ▒   ██▒▓▓█  ░██░░██░░ ▓██▓ ░ ▒▓█  ▄
▒██████▒▒░▒████▒▒ ▓███▀ ░▒██████▒▒▒▒█████▓ ░██░  ▒██▒ ░ ░▒████▒
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░▓    ▒ ░░   ░░ ▒░ ░
░ ░▒  ░ ░ ░ ░  ░  ░  ▒   ░ ░▒  ░ ░░░▒░ ░ ░  ▒ ░    ░     ░ ░  ░
░  ░  ░     ░   ░        ░  ░  ░   ░░░ ░ ░  ▒ ░  ░         ░
      ░     ░  ░░ ░            ░     ░      ░              ░  ░
[/cyan]
""",
    r"""
[cyan]
 ▄████████    ▄████████  ▄████████    ▄████████ ███    █▄   ▄█      ███        ▄████████
███    ███   ███    ███ ███    ███   ███    ███ ███    ███ ███  ▀█████████▄   ███    ███
███    █▀    ███    █▀  ███    █▀    ███    █▀  ███    ███ ███▌    ▀███▀▀██   ███    █▀
███         ▄███▄▄▄     ███          ███        ███    ███ ███▌     ███   ▀  ▄███▄▄▄
▀███████████ ▀▀███▀▀▀     ▀███████████ ▀███████████ ███    ███ ███▌     ███     ▀▀███▀▀▀
         ███ ███    █▄           ███          ███ ███    ███ ███      ███       ███    █▄
   ▄█    ███ ███    ███    ▄█    ███    ▄█    ███ ███    ███ ███      ███       ███    ███
 ▄████████▀  ██████████  ▄████████▀   ▄████████▀  ████████▀  █▀      ▄████▀     ██████████
[/cyan]
""",
]

TIPS = [
    "Use [cyan]secsuite osint full <target>[/cyan] for comprehensive reconnaissance",
    "AI analysis works offline with [cyan]--provider ollama --model llama3[/cyan]",
    "Export findings to SIEM with [cyan]secsuite siem export[/cyan]",
    "Schedule recurring scans with [cyan]secsuite schedule create[/cyan]",
    "Generate HTML reports with [cyan]secsuite report html <target>[/cyan]",
    "API security testing: [cyan]secsuite api scan <openapi-spec>[/cyan]",
    "The dashboard provides real-time visualization at [cyan]localhost:8080[/cyan]",
    "Use [cyan]secsuite ai correlate <target>[/cyan] to find attack chains",
    "Ubuntu system hardening audit: [cyan]secsuite audit run[/cyan] → [cyan]secsuite audit remediate[/cyan]",
]


def print_banner():
    """Print the Metasploit-style banner."""
    banner = random.choice(BANNERS)
    console.print(banner)

    # Module stats
    stats = Text()
    stats.append("       =[ ", style="white")
    stats.append("SecSuite v0.2.0", style="bold cyan")
    stats.append(" - ", style="white")
    stats.append("by ", style="white")
    stats.append("TheSecuredAnalyst", style="bold red")
    stats.append(" ]=\n", style="white")

    stats.append("+ -- --=[ ", style="white")
    stats.append("11", style="bold green")
    stats.append(" OSINT modules", style="white")
    stats.append(" | ", style="dim")
    stats.append("6", style="bold green")
    stats.append(" Web scanners", style="white")
    stats.append(" | ", style="dim")
    stats.append("4", style="bold green")
    stats.append(" API security tools", style="white")
    stats.append(" ]=--\n", style="white")

    stats.append("+ -- --=[ ", style="white")
    stats.append("AI-powered analysis", style="bold magenta")
    stats.append(" with ", style="white")
    stats.append("Ollama/Anthropic/OpenAI", style="bold magenta")
    stats.append("       ]=--\n", style="white")

    stats.append("+ -- --=[ ", style="white")
    stats.append("SIEM integration", style="bold yellow")
    stats.append(" | ", style="dim")
    stats.append("Scheduled scans", style="bold yellow")
    stats.append(" | ", style="dim")
    stats.append("Web dashboard", style="bold yellow")
    stats.append("      ]=--\n", style="white")

    console.print(stats)

    # Random tip
    tip = random.choice(TIPS)
    console.print(f"\n[dim]💡 Tip: {tip}[/dim]\n")


def banner_callback(ctx: typer.Context):
    """Callback to print banner before commands."""
    # Only print banner for main help or when no command specified
    if ctx.invoked_subcommand is None:
        print_banner()


app = typer.Typer(
    name="secsuite",
    help="Open-source security tools suite",
    add_completion=False,
    callback=banner_callback,
    invoke_without_command=True,
)

# Sub-command groups
osint_app = typer.Typer(help="OSINT reconnaissance tools")
scan_app = typer.Typer(help="Web security scanning tools")
phish_app = typer.Typer(help="Phishing simulation tools")
exploit_app = typer.Typer(help="Exploit and vulnerability tools")
ai_app = typer.Typer(help="AI Security Copilot")
report_app = typer.Typer(help="Report generation")
apisec_app = typer.Typer(help="API security testing")
siem_app = typer.Typer(help="SIEM integration")
schedule_app = typer.Typer(help="Scheduled scans")
vuln_app = typer.Typer(help="Network vulnerability scanner (Al-VulnScan + Automated_VAPT)")
threat_app = typer.Typer(help="IP threat intelligence (VirusTotal · AbuseIPDB · Shodan · OTX · GreyNoise)")
password_app = typer.Typer(help="Password strength audit and generation")
audit_app = typer.Typer(help="Ubuntu 24.04 LTS security audit and LLM-driven remediation")

app.add_typer(osint_app, name="osint")
app.add_typer(scan_app, name="scan")
app.add_typer(phish_app, name="phish")
app.add_typer(exploit_app, name="exploit")
app.add_typer(ai_app, name="ai")
app.add_typer(report_app, name="report")
app.add_typer(apisec_app, name="api")
app.add_typer(siem_app, name="siem")
app.add_typer(schedule_app, name="schedule")
app.add_typer(vuln_app, name="vuln")
app.add_typer(threat_app, name="threat")
app.add_typer(password_app, name="password")
app.add_typer(audit_app, name="audit")


def run_async(coro):
    """Run async function in sync context."""
    return asyncio.get_event_loop().run_until_complete(coro)


def display_result(result):
    """Display scan result in a nice format."""
    if not result.success:
        console.print("[red]Scan failed with errors:[/red]")
        for error in result.errors:
            console.print(f"  - {error}")
        return

    # Show findings
    if result.findings:
        for finding in result.findings:
            severity_colors = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "green",
            }
            color = severity_colors.get(finding.severity.value, "white")

            panel = Panel(
                f"[{color}]{finding.description}[/{color}]",
                title=f"[{color}][{finding.severity.value.upper()}] {finding.title}[/{color}]",
                border_style=color,
            )
            console.print(panel)

            if finding.data:
                for key, value in finding.data.items():
                    if isinstance(value, list) and len(value) > 5:
                        console.print(f"  {key}: {value[:5]} ... ({len(value)} total)")
                    else:
                        console.print(f"  {key}: {value}")
            console.print()

    # Duration
    if result.duration_seconds:
        console.print(f"[dim]Completed in {result.duration_seconds:.2f}s[/dim]")


# ============== OSINT Commands ==============

@osint_app.command("dns")
def osint_dns(
    target: str = typer.Argument(..., help="Target domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Enumerate DNS records for a domain."""
    setup_logging(debug=verbose)
    from modules.osint import DNSEnumerator

    console.print(f"[bold]DNS Enumeration:[/bold] {target}")
    scanner = DNSEnumerator()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("whois")
def osint_whois(
    target: str = typer.Argument(..., help="Target domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Perform WHOIS lookup."""
    setup_logging(debug=verbose)
    from modules.osint import WhoisLookup

    console.print(f"[bold]WHOIS Lookup:[/bold] {target}")
    scanner = WhoisLookup()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("subdomains")
def osint_subdomains(
    target: str = typer.Argument(..., help="Target domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Discover subdomains."""
    setup_logging(debug=verbose)
    from modules.osint import SubdomainScanner

    console.print(f"[bold]Subdomain Enumeration:[/bold] {target}")
    scanner = SubdomainScanner()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("headers")
def osint_headers(
    target: str = typer.Argument(..., help="Target URL or domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Analyze HTTP security headers."""
    setup_logging(debug=verbose)
    from modules.osint import HeaderAnalyzer

    console.print(f"[bold]Header Analysis:[/bold] {target}")
    scanner = HeaderAnalyzer()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("ports")
def osint_ports(
    target: str = typer.Argument(..., help="Target IP or domain"),
    ports: str | None = typer.Option(None, "--ports", "-p", help="Ports to scan (e.g., '22,80,443' or '1-1000')"),
    scan_type: str = typer.Option("default", "--type", "-t", help="Scan type: quick, default, full"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Scan for open ports (uses nmap if available)."""
    setup_logging(debug=verbose)
    from modules.osint import PortScanner

    console.print(f"[bold]Port Scan:[/bold] {target}")
    scanner = PortScanner(ports=ports, scan_type=scan_type)
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("tech")
def osint_tech(
    target: str = typer.Argument(..., help="Target URL or domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Detect web technologies."""
    setup_logging(debug=verbose)
    from modules.osint import TechDetector

    console.print(f"[bold]Technology Detection:[/bold] {target}")
    scanner = TechDetector()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("emails")
def osint_emails(
    target: str = typer.Argument(..., help="Target domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Harvest email addresses."""
    setup_logging(debug=verbose)
    from modules.osint import EmailHarvester

    console.print(f"[bold]Email Harvesting:[/bold] {target}")
    scanner = EmailHarvester()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("vt")
def osint_virustotal(
    target: str = typer.Argument(..., help="Target domain, IP, or URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Check target against VirusTotal."""
    setup_logging(debug=verbose)
    from modules.osint import VirusTotalScanner

    console.print(f"[bold]VirusTotal Check:[/bold] {target}")
    scanner = VirusTotalScanner()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("shodan")
def osint_shodan(
    target: str = typer.Argument(..., help="Target IP or domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Query Shodan for host information."""
    setup_logging(debug=verbose)
    from modules.osint import ShodanScanner

    console.print(f"[bold]Shodan Lookup:[/bold] {target}")
    scanner = ShodanScanner()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@osint_app.command("full")
def osint_full(
    target: str = typer.Argument(..., help="Target domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run full OSINT reconnaissance."""
    setup_logging(debug=verbose)
    from modules.osint import (
        DNSEnumerator,
        EmailHarvester,
        HeaderAnalyzer,
        SubdomainScanner,
        TechDetector,
        WhoisLookup,
    )

    console.print(f"[bold]Full OSINT Recon:[/bold] {target}")
    console.print()

    t = Target.from_string(target)

    scanners = [
        ("DNS Enumeration", DNSEnumerator()),
        ("WHOIS Lookup", WhoisLookup()),
        ("Subdomain Discovery", SubdomainScanner()),
        ("Header Analysis", HeaderAnalyzer()),
        ("Technology Detection", TechDetector()),
        ("Email Harvesting", EmailHarvester()),
    ]

    for name, scanner in scanners:
        console.print(f"[cyan]Running {name}...[/cyan]")
        result = run_async(scanner.run(t))
        display_result(result)
        console.print()


# ============== Web Scanner Commands ==============

@scan_app.command("crawl")
def scan_crawl(
    target: str = typer.Argument(..., help="Target URL"),
    max_pages: int = typer.Option(100, "--max-pages", "-m"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Crawl website to discover pages and forms."""
    setup_logging(debug=verbose)
    from modules.webscanner import WebCrawler

    console.print(f"[bold]Web Crawl:[/bold] {target}")
    scanner = WebCrawler(max_pages=max_pages)
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@scan_app.command("xss")
def scan_xss(
    target: str = typer.Argument(..., help="Target URL with parameters"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Scan for XSS vulnerabilities."""
    setup_logging(debug=verbose)
    from modules.webscanner import XSSScanner

    console.print(f"[bold]XSS Scan:[/bold] {target}")
    scanner = XSSScanner()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@scan_app.command("sqli")
def scan_sqli(
    target: str = typer.Argument(..., help="Target URL with parameters"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Scan for SQL injection vulnerabilities."""
    setup_logging(debug=verbose)
    from modules.webscanner import SQLiScanner

    console.print(f"[bold]SQLi Scan:[/bold] {target}")
    scanner = SQLiScanner()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@scan_app.command("dirs")
def scan_dirs(
    target: str = typer.Argument(..., help="Target URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Bruteforce directories and files."""
    setup_logging(debug=verbose)
    from modules.webscanner import DirectoryBruteforcer

    console.print(f"[bold]Directory Bruteforce:[/bold] {target}")
    scanner = DirectoryBruteforcer()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@scan_app.command("ssl")
def scan_ssl(
    target: str = typer.Argument(..., help="Target domain"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Analyze SSL/TLS configuration."""
    setup_logging(debug=verbose)
    from modules.webscanner import SSLAnalyzer

    console.print(f"[bold]SSL/TLS Analysis:[/bold] {target}")
    scanner = SSLAnalyzer()
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


@scan_app.command("nuclei")
def scan_nuclei(
    target: str = typer.Argument(..., help="Target URL"),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Severity filter (comma-separated)"),
    tags: str | None = typer.Option(None, "--tags", "-t", help="Template tags (comma-separated)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run Nuclei vulnerability scanner."""
    setup_logging(debug=verbose)
    from modules.webscanner import NucleiScanner

    console.print(f"[bold]Nuclei Scan:[/bold] {target}")
    sev_list = severity.split(",") if severity else None
    tag_list = tags.split(",") if tags else None

    scanner = NucleiScanner(severity=sev_list, tags=tag_list)
    result = run_async(scanner.run(Target.from_string(target)))
    display_result(result)


# ============== Exploit Commands ==============

@exploit_app.command("search")
def exploit_search(
    query: str = typer.Argument(..., help="Search query (service, product, CVE)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Search for exploits using searchsploit."""
    setup_logging(debug=verbose)
    from modules.exploit import SearchSploit

    console.print(f"[bold]Exploit Search:[/bold] {query}")

    searcher = SearchSploit()

    if not searcher.searchsploit_available:
        console.print("[bold red]Error:[/bold red] searchsploit is not installed.")
        console.print("[dim]Install it with: apt install exploitdb[/dim]")
        raise typer.Exit(1)

    results = run_async(searcher.search(query))

    if results:
        table = Table(title="Exploits Found")
        table.add_column("ID", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Platform", style="green")

        for r in results[:20]:
            table.add_row(
                str(r.get("EDB-ID", "")),
                r.get("Title", "")[:60],
                r.get("Type", ""),
                r.get("Platform", ""),
            )

        console.print(table)
        console.print(f"[dim]Showing {min(20, len(results))} of {len(results)} results[/dim]")
    else:
        console.print("[yellow]No exploits found[/yellow]")


# ============== Phishing Commands ==============

@phish_app.command("templates")
def phish_templates():
    """List available phishing templates."""
    from modules.phishing import TemplateManager

    tm = TemplateManager()

    console.print("[bold]Email Templates:[/bold]")
    table = Table()
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Category", style="yellow")

    for t in tm.list_email_templates():
        table.add_row(t.id, t.name, t.category)

    console.print(table)
    console.print()

    console.print("[bold]Landing Page Templates:[/bold]")
    table = Table()
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Category", style="yellow")

    for t in tm.list_landing_templates():
        table.add_row(t.id, t.name, t.category)

    console.print(table)


@phish_app.command("server")
def phish_server(
    host: str = typer.Option("0.0.0.0", "--host", "-h"),
    port: int = typer.Option(8080, "--port", "-p"),
):
    """Start phishing server for landing pages."""
    from modules.phishing import PhishingServer

    console.print(f"[bold]Starting phishing server on {host}:{port}[/bold]")
    server = PhishingServer(host=host, port=port)

    async def run():
        await server.start()
        console.print("[green]Server running. Press Ctrl+C to stop.[/green]")
        while True:
            await asyncio.sleep(1)

    try:
        run_async(run())
    except KeyboardInterrupt:
        run_async(server.stop())
        console.print("[yellow]Server stopped[/yellow]")


# ============== AI Copilot Commands ==============

# Store scan results for AI analysis
_scan_results_cache: list = []


def _collect_scan_results(target: str, modules: list[str]) -> list:
    """Run scans and collect results for AI analysis."""
    from modules.osint import (
        DNSEnumerator,
        HeaderAnalyzer,
        PortScanner,
        SubdomainScanner,
        TechDetector,
        WhoisLookup,
    )
    from modules.webscanner import (
        DirectoryBruteforcer,
        SQLiScanner,
        SSLAnalyzer,
        WebCrawler,
        XSSScanner,
    )

    t = Target.from_string(target)
    results = []

    module_map = {
        "dns": DNSEnumerator(),
        "whois": WhoisLookup(),
        "subdomains": SubdomainScanner(),
        "headers": HeaderAnalyzer(),
        "tech": TechDetector(),
        "ports": PortScanner(),
        "crawler": WebCrawler(max_pages=50),
        "xss": XSSScanner(),
        "sqli": SQLiScanner(),
        "dirs": DirectoryBruteforcer(),
        "ssl": SSLAnalyzer(),
    }

    for mod_name in modules:
        if mod_name in module_map:
            console.print(f"[dim]Running {mod_name}...[/dim]")
            try:
                result = run_async(module_map[mod_name].run(t))
                results.append(result)
            except Exception as e:
                console.print(f"[red]Error in {mod_name}: {e}[/red]")

    return results


@ai_app.command("providers")
def ai_providers():
    """List available LLM providers."""
    from modules.ai.llm_client import list_supported_providers

    providers = list_supported_providers()

    console.print("[bold]Cloud Providers:[/bold]")
    for name, desc in providers["cloud_providers"].items():
        console.print(f"  • [cyan]{name}[/cyan]: {desc}")

    console.print()
    console.print("[bold]Local Providers (no API key needed):[/bold]")
    for name, desc in providers["local_providers"].items():
        console.print(f"  • [cyan]{name}[/cyan]: {desc}")

    console.print()
    console.print("[bold]Ollama Model Shortcuts:[/bold]")
    shortcuts = providers["ollama_model_shortcuts"]
    console.print(f"  {', '.join(shortcuts.keys())}")

    console.print()
    console.print("[bold]Usage Examples:[/bold]")
    console.print("  secsuite ai analyze example.com -p ollama -m qwen2.5")
    console.print("  secsuite ai analyze example.com -p ollama/llama3.2")
    console.print("  secsuite ai analyze example.com -p qwen")
    console.print("  secsuite ai analyze example.com -p mistral")
    console.print("  secsuite ai ask 'What is XSS?' -p ollama -m mistral")


@ai_app.command("analyze")
def ai_analyze(
    target: str = typer.Argument(..., help="Target to analyze"),
    provider: str = typer.Option("anthropic", "--provider", "-p", help="LLM provider (anthropic/openai/ollama/qwen/llama3/mistral)"),
    model: str | None = typer.Option(None, "--model", "-m", help="Model name"),
    base_url: str | None = typer.Option(None, "--base-url", "-b", help="Base URL for ollama or custom API"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan (fewer modules)"),
):
    """Run scans and get AI-powered analysis."""
    setup_logging()

    console.print(f"[bold]AI Security Analysis:[/bold] {target}")
    console.print()

    # Determine which modules to run
    if quick:
        modules = ["dns", "headers", "tech", "ssl"]
    else:
        modules = ["dns", "whois", "headers", "tech", "ports", "ssl", "dirs"]

    console.print("[cyan]Running security scans...[/cyan]")
    results = _collect_scan_results(target, modules)

    if not results:
        console.print("[red]No scan results collected[/red]")
        return

    console.print(f"[green]Collected {len(results)} scan results[/green]")
    console.print()

    # Run AI analysis
    console.print("[cyan]Running AI analysis...[/cyan]")
    try:
        from modules.ai import SecurityCopilot

        copilot = SecurityCopilot(provider=provider, model=model, base_url=base_url)
        copilot.load_scan_results(results)

        analysis = run_async(copilot.analyze())

        console.print()
        console.print(Panel(analysis, title="[bold magenta]AI Security Analysis[/bold magenta]", border_style="magenta"))

    except ValueError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        console.print("[dim]For cloud: Set SECSUITE_ANTHROPIC_API_KEY or SECSUITE_OPENAI_API_KEY[/dim]")
        console.print("[dim]For local: Use -p ollama -m <model> (requires Ollama running)[/dim]")
    except ImportError as e:
        console.print(f"[red]Missing package: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if "ollama" in provider.lower():
            console.print("[dim]Make sure Ollama is running: ollama serve[/dim]")


@ai_app.command("ask")
def ai_ask(
    question: str = typer.Argument(..., help="Question to ask about security"),
    target: str | None = typer.Option(None, "--target", "-t", help="Target to scan first"),
    provider: str = typer.Option("anthropic", "--provider", "-p", help="LLM provider (anthropic/openai/ollama/qwen/llama3/mistral)"),
    model: str | None = typer.Option(None, "--model", "-m", help="Model name"),
    base_url: str | None = typer.Option(None, "--base-url", "-b", help="Base URL for ollama or custom API"),
):
    """Ask the AI copilot a security question."""
    setup_logging()

    try:
        from modules.ai import SecurityCopilot

        copilot = SecurityCopilot(provider=provider, model=model, base_url=base_url)

        # If target provided, run quick scan first
        if target:
            console.print(f"[dim]Scanning {target}...[/dim]")
            results = _collect_scan_results(target, ["dns", "headers", "tech"])
            copilot.load_scan_results(results)

        console.print(f"[cyan]Question:[/cyan] {question}")
        console.print()

        response = run_async(copilot.ask(question))
        console.print(Panel(response, title="[bold magenta]AI Response[/bold magenta]", border_style="magenta"))

    except ValueError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if "ollama" in provider.lower():
            console.print("[dim]Make sure Ollama is running: ollama serve[/dim]")


@ai_app.command("executive")
def ai_executive(
    target: str = typer.Argument(..., help="Target to analyze"),
    provider: str = typer.Option("anthropic", "--provider", "-p", help="LLM provider"),
    model: str | None = typer.Option(None, "--model", "-m", help="Model name"),
    base_url: str | None = typer.Option(None, "--base-url", "-b", help="Base URL"),
):
    """Generate executive summary for leadership."""
    setup_logging()

    console.print(f"[bold]Executive Summary:[/bold] {target}")

    results = _collect_scan_results(target, ["dns", "headers", "tech", "ssl", "ports"])

    try:
        from modules.ai import SecurityCopilot

        copilot = SecurityCopilot(provider=provider, model=model, base_url=base_url)
        copilot.load_scan_results(results)

        summary = run_async(copilot.get_executive_summary())
        console.print()
        console.print(Panel(summary, title="[bold blue]Executive Summary[/bold blue]", border_style="blue"))

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if "ollama" in provider.lower():
            console.print("[dim]Make sure Ollama is running: ollama serve[/dim]")


@ai_app.command("correlate")
def ai_correlate(
    target: str = typer.Argument(..., help="Target to analyze"),
):
    """Correlate findings and identify attack chains."""
    setup_logging()

    console.print(f"[bold]Finding Correlation:[/bold] {target}")

    results = _collect_scan_results(target, ["dns", "headers", "tech", "ssl", "ports", "dirs"])

    from modules.ai import FindingCorrelator

    correlator = FindingCorrelator()
    report = correlator.correlate(results)

    # Display risk summary
    risk = report.risk_summary
    risk_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "MINIMAL": "green"}
    risk_color = risk_colors.get(risk.get("risk_level", ""), "white")

    console.print()
    console.print(Panel(
        f"[{risk_color}]Risk Score: {risk.get('overall_score', 0)}/100\n"
        f"Risk Level: {risk.get('risk_level', 'Unknown')}[/{risk_color}]\n\n"
        f"Total Findings: {report.total_findings}\n"
        f"Unique Findings: {report.unique_findings}\n"
        f"High Priority: {risk.get('high_priority_findings', 0)}\n"
        f"Attack Chains: {risk.get('attack_chains_identified', 0)}",
        title="[bold]Risk Summary[/bold]"
    ))

    # Display attack chains
    if report.attack_chains:
        console.print()
        console.print("[bold red]Attack Chains Identified:[/bold red]")
        for chain in report.attack_chains:
            console.print(f"  • [yellow]{chain.name}[/yellow] (Risk: {chain.risk_score:.1f}/10)")
            console.print(f"    {chain.description}")

    # Display recommendations
    if report.recommendations:
        console.print()
        console.print("[bold green]Recommendations:[/bold green]")
        for rec in report.recommendations:
            console.print(f"  • {rec}")


@ai_app.command("remediate")
def ai_remediate(
    target: str = typer.Argument(..., help="Target to scan and remediate (use 'localhost' for this machine)"),
    provider: str = typer.Option("ollama", "--provider", "-p", help="LLM provider (ollama/anthropic/openai)"),
    model: str | None = typer.Option(None, "--model", "-m", help="Model name (e.g. qwen2.5:7b)"),
    base_url: str | None = typer.Option(None, "--base-url", "-b", help="Ollama/custom API base URL"),
    severity: str = typer.Option("medium", "--severity", "-s", help="Minimum severity to remediate: critical/high/medium/low"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show commands without executing"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan (fewer modules)"),
    skip_scan: bool = typer.Option(False, "--skip-scan", help="Skip scan phase, use last cached results if available"),
):
    """
    Scan a target then use a local LLM to interactively remediate findings.

    Checks prerequisites for each finding before offering to execute.
    Supports: localhost hardening, web headers, SSL, firewall, services.

    Examples:
      secsuite ai remediate localhost -p ollama -m qwen2.5:7b
      secsuite ai remediate localhost --dry-run
      secsuite ai remediate https://example.com -s high
    """
    from core.models import Severity as SevEnum
    from modules.ai import RemediationCopilot

    setup_logging()

    SEV_MAP = {
        "critical": SevEnum.CRITICAL,
        "high":     SevEnum.HIGH,
        "medium":   SevEnum.MEDIUM,
        "low":      SevEnum.LOW,
    }
    min_sev = SEV_MAP.get(severity.lower(), SevEnum.MEDIUM)

    # ── Severity colour helper ────────────────────────────────────────────────
    SEV_STYLE = {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "blue",
        "info":     "dim",
    }

    # ── Scan phase ────────────────────────────────────────────────────────────
    console.print(f"\n[bold cyan]SecSuite AI Remediation[/bold cyan] — {target}")
    console.print(f"[dim]Provider: {provider}  Model: {model or 'auto'}  Min-severity: {severity}  Dry-run: {dry_run}[/dim]\n")

    if not skip_scan:
        if quick or target in ("localhost", "127.0.0.1"):
            modules = ["ports", "headers", "ssl"]
        else:
            modules = ["dns", "headers", "tech", "ssl", "ports", "dirs"]

        console.print("[cyan]Running security scan...[/cyan]")
        results = _collect_scan_results(target, modules)
        if not results:
            console.print("[red]No scan results — cannot proceed with remediation.[/red]")
            raise typer.Exit(1)
        total_findings = sum(len(r.findings) for r in results)
        console.print(f"[green]Scan complete — {total_findings} finding(s) across {len(results)} module(s).[/green]\n")
    else:
        console.print("[yellow]Skipping scan (--skip-scan). No findings loaded.[/yellow]")
        console.print("[dim]Tip: Run without --skip-scan to scan and remediate in one step.[/dim]")
        raise typer.Exit(0)

    # ── Build copilot ─────────────────────────────────────────────────────────
    copilot_kwargs: dict = {}
    if model:
        copilot_kwargs["model"] = model
    if base_url:
        copilot_kwargs["base_url"] = base_url

    try:
        copilot = RemediationCopilot(
            provider=provider,
            target=target,
            **copilot_kwargs,
        )
    except ValueError as exc:
        console.print(f"[red]LLM configuration error: {exc}[/red]")
        raise typer.Exit(1) from None

    # ── Generate plans ────────────────────────────────────────────────────────
    console.print("[cyan]Generating remediation plans via LLM...[/cyan]\n")
    try:
        triples = run_async(copilot.plans_for_results(results, min_severity=min_sev))
    except Exception as exc:
        console.print(f"[red]LLM error: {exc}[/red]")
        if "ollama" in provider.lower():
            console.print("[dim]Is Ollama running? Try: ollama serve[/dim]")
        raise typer.Exit(1) from None

    if not triples:
        console.print(f"[green]No findings at or above '{severity}' severity. Nothing to remediate.[/green]")
        raise typer.Exit(0)

    console.print(f"[bold]{len(triples)} finding(s) to remediate.[/bold]")
    console.print("[dim]Controls:  [y] apply  [n] skip  [e] edit  [s] follow-up  [q] quit[/dim]\n")

    applied = skipped = 0

    for idx, (finding, prereq, plan) in enumerate(triples, 1):
        sev_val  = finding.severity.value
        sev_style = SEV_STYLE.get(sev_val, "white")

        console.rule(f"[dim]Finding {idx}/{len(triples)}[/dim]")
        console.print(f"  [{sev_style}][{sev_val.upper()}][/{sev_style}] [bold]{finding.title}[/bold]")
        console.print(f"  [dim]{finding.description[:120]}[/dim]")
        console.print()

        # ── Show prerequisite results ─────────────────────────────────────────
        if prereq.checks:
            for chk in prereq.checks:
                icon  = "[green]✓[/green]" if chk.met else "[red]✗[/red]"
                label = chk.name
                console.print(f"    {icon}  {label}" + (f"  [dim]→ {chk.hint}[/dim]" if not chk.met else ""))

        if not prereq.can_autofix:
            console.print("\n  [yellow]Advisory only[/yellow] — target is not localhost; review commands manually.\n")

        if prereq.blocking:
            console.print(f"\n  [red]Blocked:[/red] {', '.join(prereq.blocking)}")
            console.print("  [dim]Resolve the above before this finding can be auto-fixed.[/dim]\n")

        # ── Show generated plan ───────────────────────────────────────────────
        console.print(f"  [cyan]Suggested commands ({model or 'auto'}):[/cyan]")
        for step in plan.steps:
            label_style = {"CHECK": "blue", "FIX": "green", "VERIFY": "cyan", "ADVISORY": "yellow", "INFO": "dim"}.get(step.label, "white")
            console.print(f"    [{label_style}][{step.label}][/{label_style}]  {step.command}")
        console.print()

        if plan.advisory_only:
            console.print("  [yellow]Advisory finding — no commands to execute automatically.[/yellow]\n")
            skipped += 1
            continue

        if prereq.blocking and not dry_run:
            console.print("  [dim]Skipping execution — prerequisites not met.[/dim]\n")
            skipped += 1
            continue

        # ── Interactive prompt ────────────────────────────────────────────────
        while True:
            choice = typer.prompt(
                "  Apply? [y/n/e/s/q]",
                default="n",
                show_default=False,
            ).strip().lower()

            if choice == "q":
                console.print(f"\n[yellow]Session ended.[/yellow]  Applied={applied}  Skipped={skipped}\n")
                raise typer.Exit(0)

            elif choice == "y":
                fix_cmds = [s.command for s in plan.steps if s.label in ("FIX", "VERIFY")]
                if not fix_cmds:
                    console.print("  [dim]No executable FIX steps in plan.[/dim]")
                    skipped += 1
                    break
                for cmd in fix_cmds:
                    if cmd.startswith("#"):
                        continue
                    # Defense-in-depth: AI-generated commands pass through the
                    # guardrails safety analyzer before they can touch a shell.
                    verdict = guardrails.validate_script(cmd)
                    if not verdict.safe:
                        console.print(f"  [dim]$ {cmd}[/dim]")
                        console.print(
                            "  [red]Blocked by safety guardrails:[/red] "
                            + "; ".join(verdict.violations)
                        )
                        continue
                    console.print(f"  [dim]$ {cmd}[/dim]")
                    for warning in verdict.warnings:
                        console.print(f"  [yellow]⚠ {warning}[/yellow]")
                    if not dry_run:
                        import subprocess as _sp
                        # Guardrail-validated above; interactive apply of a shell remediation step.
                        result = _sp.run(cmd, shell=True, text=True, capture_output=True)  # nosec B602
                        if result.stdout:
                            console.print(f"  {result.stdout.strip()}")
                        if result.returncode != 0:
                            console.print(f"  [red]Exit {result.returncode}:[/red] {result.stderr.strip()}")
                        else:
                            console.print("  [green]Done.[/green]")
                    else:
                        console.print(f"  [yellow][DRY RUN] Would execute: {cmd}[/yellow]")
                applied += 1
                break

            elif choice == "n":
                console.print("  [dim]Skipped.[/dim]")
                skipped += 1
                break

            elif choice == "e":
                new_cmd = typer.prompt("  Enter command", default="")
                if new_cmd:
                    console.print(f"  [dim]$ {new_cmd}[/dim]")
                    verdict = guardrails.validate_script(new_cmd)
                    if not verdict.safe:
                        console.print(
                            "  [red]Blocked by safety guardrails:[/red] "
                            + "; ".join(verdict.violations)
                        )
                        break
                    if not dry_run:
                        import subprocess as _sp
                        # Guardrail-validated above; interactive apply of an operator-entered command.
                        result = _sp.run(new_cmd, shell=True, text=True, capture_output=True)  # nosec B602
                        console.print(result.stdout or result.stderr or "Done.")
                    else:
                        console.print(f"  [yellow][DRY RUN] {new_cmd}[/yellow]")
                    applied += 1
                break

            elif choice == "s":
                follow_up = typer.prompt("  Follow-up question")
                console.print(f"  [dim]Asking {model or 'LLM'}...[/dim]")
                try:
                    from modules.ai import SecurityCopilot
                    cp = SecurityCopilot(provider=provider, model=model, base_url=base_url)
                    resp = run_async(cp.ask(
                        f"Ubuntu 24.04. Finding: {finding.title}. Question: {follow_up}"
                    ))
                    console.print(f"\n  [cyan]{resp}[/cyan]\n")
                except Exception as exc:
                    console.print(f"  [red]{exc}[/red]")
            else:
                console.print("  [dim]Use y / n / e / s / q[/dim]")

        console.print()

    # ── Summary ───────────────────────────────────────────────────────────────
    console.rule()
    console.print("\n  [bold]Remediation summary[/bold]")
    console.print(f"  [green]Applied : {applied}[/green]")
    console.print(f"  [yellow]Skipped : {skipped}[/yellow]")
    console.print(f"\n  [dim]Re-run audit to verify: secsuite ai remediate {target} --dry-run[/dim]\n")


# ============== Report Commands ==============

@report_app.command("html")
def report_html(
    target: str = typer.Argument(..., help="Target to scan and report"),
    output: str = typer.Option("security_report.html", "--output", "-o", help="Output file path"),
    title: str = typer.Option("Security Assessment Report", "--title", "-t"),
    with_ai: bool = typer.Option(False, "--ai", help="Include AI analysis"),
    provider: str = typer.Option("anthropic", "--provider", "-p"),
):
    """Generate HTML security report."""
    setup_logging()

    console.print(f"[bold]Generating Report:[/bold] {target}")

    results = _collect_scan_results(
        target,
        ["dns", "whois", "headers", "tech", "ssl", "ports", "dirs"]
    )

    from modules.ai import ReportGenerator, SecurityCopilot
    from modules.ai.reporter import ReportConfig

    ai_analysis = None
    if with_ai:
        try:
            console.print("[dim]Running AI analysis...[/dim]")
            copilot = SecurityCopilot(provider=provider)
            copilot.load_scan_results(results)
            ai_analysis = run_async(copilot.analyze())
        except Exception as e:
            console.print(f"[yellow]AI analysis skipped: {e}[/yellow]")

    config = ReportConfig(title=title)
    reporter = ReportGenerator()
    path = reporter.save_html(results, output, config, ai_analysis)

    console.print(f"[green]Report saved to: {path}[/green]")


@report_app.command("json")
def report_json(
    target: str = typer.Argument(..., help="Target to scan and report"),
    output: str = typer.Option("security_report.json", "--output", "-o"),
):
    """Generate JSON security report."""
    setup_logging()

    console.print(f"[bold]Generating JSON Report:[/bold] {target}")

    results = _collect_scan_results(
        target,
        ["dns", "whois", "headers", "tech", "ssl", "ports"]
    )

    from modules.ai import ReportGenerator

    reporter = ReportGenerator()
    path = reporter.save_json(results, output)

    console.print(f"[green]Report saved to: {path}[/green]")


@report_app.command("remediation")
def report_remediation(
    finding: str = typer.Argument(..., help="Finding title to get remediation for"),
):
    """Get remediation guidance for a specific finding."""
    from core.models import Finding, Severity
    from modules.ai import RemediationEngine

    engine = RemediationEngine()

    # Create a dummy finding to match
    dummy = Finding(
        title=finding,
        description=finding,
        severity=Severity.MEDIUM,
        source="user",
    )

    guide = engine.get_remediation(dummy)

    if guide:
        formatted = engine.format_remediation(guide)
        console.print(Panel(formatted, title=f"[bold]Remediation: {guide.title}[/bold]"))
    else:
        console.print(f"[yellow]No specific remediation guide found for: {finding}[/yellow]")
        console.print("[dim]Try keywords like: sql injection, xss, security header, ssl, exposed[/dim]")


# ============== API Security Commands ==============

@apisec_app.command("scan")
def api_scan(
    spec_url: str = typer.Argument(..., help="URL to OpenAPI/Swagger spec"),
    auth_token: str | None = typer.Option(None, "--token", "-t", help="Auth token"),
):
    """Scan API endpoints for vulnerabilities."""
    setup_logging()

    console.print(f"[bold]API Security Scan:[/bold] {spec_url}")

    async def run():
        from modules.apisec import APIEndpointTester, OpenAPIParser

        parser = OpenAPIParser()
        api = await parser.parse_url(spec_url)

        console.print(f"[green]Parsed {len(api.endpoints)} endpoints from {api.title}[/green]")

        tester = APIEndpointTester(auth_token=auth_token)
        result = await tester.test_api(api)

        display_result(result)

    run_async(run())


@apisec_app.command("fuzz")
def api_fuzz(
    spec_url: str = typer.Argument(..., help="URL to OpenAPI/Swagger spec"),
    max_requests: int = typer.Option(100, "--max", "-m", help="Maximum requests"),
    auth_token: str | None = typer.Option(None, "--token", "-t"),
):
    """Fuzz API endpoints for vulnerabilities."""
    setup_logging()

    console.print(f"[bold]API Fuzzing:[/bold] {spec_url}")

    async def run():
        from modules.apisec import APIFuzzer, OpenAPIParser

        parser = OpenAPIParser()
        api = await parser.parse_url(spec_url)

        fuzzer = APIFuzzer(max_requests=max_requests, auth_token=auth_token)
        result = await fuzzer.fuzz_api(api)

        display_result(result)
        console.print(f"[dim]Sent {result.data.get('requests_sent', 0)} requests[/dim]")

    run_async(run())


@apisec_app.command("auth-test")
def api_auth_test(
    spec_url: str = typer.Argument(..., help="URL to OpenAPI/Swagger spec"),
):
    """Test API authentication security."""
    setup_logging()

    console.print(f"[bold]API Auth Testing:[/bold] {spec_url}")

    async def run():
        from modules.apisec import APIAuthTester, OpenAPIParser

        parser = OpenAPIParser()
        api = await parser.parse_url(spec_url)

        tester = APIAuthTester()
        result = await tester.test_api_auth(api)

        display_result(result)

    run_async(run())


# ============== SIEM Commands ==============

@siem_app.command("test")
def siem_test(
    provider: str = typer.Argument(..., help="SIEM provider (splunk/elasticsearch/syslog/webhook)"),
    url: str = typer.Option(..., "--url", "-u", help="SIEM endpoint URL"),
    token: str | None = typer.Option(None, "--token", "-t", help="Auth token"),
):
    """Test SIEM connection."""
    setup_logging()

    console.print(f"[bold]Testing SIEM Connection:[/bold] {provider}")

    async def run():
        from modules.siem import ElasticsearchExporter, SplunkExporter, WebhookExporter

        if provider == "splunk":
            exporter = SplunkExporter(hec_url=url, hec_token=token or "")
        elif provider == "elasticsearch":
            exporter = ElasticsearchExporter(hosts=[url])
        elif provider == "webhook":
            exporter = WebhookExporter(url=url)
        else:
            console.print(f"[red]Unknown provider: {provider}[/red]")
            return

        if await exporter.test_connection():
            console.print("[green]✓ Connection successful[/green]")
        else:
            console.print("[red]✗ Connection failed[/red]")

    run_async(run())


@siem_app.command("export")
def siem_export(
    target: str = typer.Argument(..., help="Target to scan and export"),
    provider: str = typer.Option("webhook", "--provider", "-p"),
    url: str = typer.Option(..., "--url", "-u", help="SIEM endpoint URL"),
    token: str | None = typer.Option(None, "--token", "-t"),
):
    """Run scan and export results to SIEM."""
    setup_logging()

    console.print(f"[bold]Scan and Export:[/bold] {target} -> {provider}")

    results = _collect_scan_results(target, ["dns", "headers", "tech", "ssl"])

    async def run():
        from modules.siem import ElasticsearchExporter, SplunkExporter, WebhookExporter

        if provider == "splunk":
            exporter = SplunkExporter(hec_url=url, hec_token=token or "")
        elif provider == "elasticsearch":
            exporter = ElasticsearchExporter(hosts=[url])
        else:
            exporter = WebhookExporter(url=url, format="slack" if "slack" in url else "json")

        for result in results:
            success, failed = await exporter.export_scan_result(result)
            console.print(f"[green]Exported {success} events[/green]")

    run_async(run())


# ============== Schedule Commands ==============

@schedule_app.command("create")
def schedule_create(
    name: str = typer.Argument(..., help="Schedule name"),
    target: str = typer.Option(..., "--target", "-t", help="Target to scan"),
    frequency: str = typer.Option("daily", "--frequency", "-f", help="Frequency (hourly/daily/weekly/monthly)"),
    modules: str = typer.Option("dns,headers,tech", "--modules", "-m", help="Comma-separated modules"),
):
    """Create a scheduled scan."""
    from modules.scheduler import ScanScheduler, ScheduleFrequency, ScheduleStorage

    scheduler = ScanScheduler()
    storage = ScheduleStorage()
    storage.attach_to_scheduler(scheduler)

    schedule = scheduler.create_schedule(
        name=name,
        target=target,
        modules=modules.split(","),
        frequency=ScheduleFrequency(frequency),
    )

    storage.sync_from_scheduler(scheduler)

    console.print(f"[green]Created schedule:[/green] {schedule.id}")
    console.print(f"  Name: {schedule.name}")
    console.print(f"  Target: {schedule.target}")
    console.print(f"  Frequency: {schedule.frequency.value}")
    console.print(f"  Next run: {schedule.next_run}")


@schedule_app.command("list")
def schedule_list():
    """List all scheduled scans."""
    from modules.scheduler import ScanScheduler, ScheduleStorage

    scheduler = ScanScheduler()
    storage = ScheduleStorage()
    storage.attach_to_scheduler(scheduler)

    schedules = scheduler.list_schedules()

    if not schedules:
        console.print("[yellow]No schedules found[/yellow]")
        return

    table = Table(title="Scheduled Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Target")
    table.add_column("Frequency")
    table.add_column("Next Run")
    table.add_column("Status")

    for s in schedules:
        table.add_row(
            s.id,
            s.name,
            s.target,
            s.frequency.value,
            str(s.next_run)[:19] if s.next_run else "N/A",
            "[green]Enabled[/green]" if s.enabled else "[red]Disabled[/red]",
        )

    console.print(table)


@schedule_app.command("delete")
def schedule_delete(
    schedule_id: str = typer.Argument(..., help="Schedule ID to delete"),
):
    """Delete a scheduled scan."""
    from modules.scheduler import ScanScheduler, ScheduleStorage

    scheduler = ScanScheduler()
    storage = ScheduleStorage()
    storage.attach_to_scheduler(scheduler)

    if scheduler.delete_schedule(schedule_id):
        storage.sync_from_scheduler(scheduler)
        console.print(f"[green]Deleted schedule: {schedule_id}[/green]")
    else:
        console.print(f"[red]Schedule not found: {schedule_id}[/red]")


@schedule_app.command("run")
def schedule_run(
    schedule_id: str = typer.Argument(..., help="Schedule ID to run now"),
):
    """Run a scheduled scan immediately."""
    from modules.scheduler import ScanScheduler, ScheduleStorage

    scheduler = ScanScheduler()
    storage = ScheduleStorage()
    storage.attach_to_scheduler(scheduler)

    # Set up scan callback
    async def scan_callback(target: str, modules: list[str]):
        return _collect_scan_results(target, modules)

    scheduler.set_scan_callback(scan_callback)

    async def run():
        job = await scheduler.run_now(schedule_id)
        if job:
            console.print(f"[green]Scan completed:[/green] {job.findings_count} findings")
        else:
            console.print(f"[red]Schedule not found: {schedule_id}[/red]")

    run_async(run())


@schedule_app.command("start")
def schedule_start():
    """Start the scheduler daemon."""
    from modules.scheduler import ScanScheduler, ScheduleStorage

    console.print("[bold]Starting Scheduler Daemon[/bold]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    scheduler = ScanScheduler()
    storage = ScheduleStorage()
    storage.attach_to_scheduler(scheduler)

    async def scan_callback(target: str, modules: list[str]):
        console.print(f"[dim]Running scan: {target}[/dim]")
        return _collect_scan_results(target, modules)

    scheduler.set_scan_callback(scan_callback)

    async def run():
        await scheduler.start()
        try:
            while True:
                await asyncio.sleep(60)
                storage.sync_from_scheduler(scheduler)
        except asyncio.CancelledError:
            await scheduler.stop()

    try:
        run_async(run())
    except KeyboardInterrupt:
        console.print("[yellow]Scheduler stopped[/yellow]")


# ============== Ubuntu Audit Commands ==============

@audit_app.command("run")
def audit_run():
    """Run the Ubuntu 24.04 LTS security audit.

    Checks: CVE patch status, kernel hardening, network exposure, filesystem
    security, user/auth config, service hardening, and secsuite network scans.

    Outputs an HTML report and JSON findings to ~/.secsuite/audit_reports/

    Note: Linux (Ubuntu 24.04) only.

    Examples:

      secsuite audit run
    """
    import subprocess
    script = _audit_script("ubuntu_audit.sh")
    if script is None:
        raise typer.Exit(1)
    try:
        subprocess.run(["bash", script], check=False)
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted.[/yellow]")


@audit_app.command("remediate")
def audit_remediate(
    model: str = typer.Option("qwen2.5:7b", "--model", "-m", help="Ollama model to use"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show commands without executing"),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Filter severity (CRITICAL/HIGH/MEDIUM/LOW)"),
    findings: str | None = typer.Option(None, "--findings", "-f", help="Path to findings JSON (default: latest)"),
):
    """LLM-driven remediation for audit findings.

    Reads the latest audit findings, asks a local Ollama model to generate a
    fix command for each finding, and prompts you to apply, skip, or edit it.

    Run 'secsuite audit run' first to generate findings.

    Note: Linux only. Requires Ollama running locally (ollama serve).

    Examples:

      secsuite audit remediate

      secsuite audit remediate --dry-run

      secsuite audit remediate --severity CRITICAL --model llama3.2
    """
    import subprocess
    script = _audit_script("ubuntu_remediate.sh")
    if script is None:
        raise typer.Exit(1)
    args = ["bash", script, "--model", model]
    if dry_run:
        args.append("--dry-run")
    if severity:
        args.extend(["--severity", severity])
    if findings:
        args.extend(["--findings", findings])
    try:
        subprocess.run(args, check=False)
    except KeyboardInterrupt:
        console.print("\n[yellow]Remediation session ended.[/yellow]")


def _audit_script(name: str) -> str | None:
    """Return the absolute path to a script in the repo's scripts/ directory."""
    import os
    scripts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
    path = os.path.join(scripts_dir, name)
    if not os.path.exists(path):
        console.print(f"[red]{name} not found at {path}[/red]")
        return None
    return path


# ============== REST API Server Command ==============

@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-H", help="Host to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes (dev mode)"),
    api_key: str | None = typer.Option(None, "--api-key", "-k", help="Require X-API-Key header (leave blank to allow all)"),
):
    """Start the REST API server.

    After starting, open http://localhost:8000/docs to explore the API interactively.

    Set --api-key to protect the server with a key that callers must send
    in the X-API-Key header.

    Examples:

      secsuite serve

      secsuite serve --port 9000 --api-key mysecretkey
    """
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn is not installed.[/red]")
        console.print("[dim]Run: pip install 'security-suite[dashboard]'[/dim]")
        raise typer.Exit(1) from None

    import os
    if api_key:
        os.environ["SECSUITE_API_KEY"] = api_key
        console.print("[yellow]API key protection enabled.[/yellow]")
        console.print(f"[dim]Send header: X-API-Key: {api_key}[/dim]")

    console.print(f"[bold]Starting Security Suite API[/bold] on http://{host}:{port}")
    console.print(f"[dim]Interactive docs: http://{'localhost' if host == '0.0.0.0' else host}:{port}/docs[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    uvicorn.run(
        "api.server:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


# ============== Dashboard Command ==============

@app.command()
def dashboard(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind"),
):
    """Start the web dashboard."""
    console.print(f"[bold]Starting Dashboard[/bold] on http://{host}:{port}")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    try:
        from dashboard import DashboardApp
        app = DashboardApp(host=host, port=port)
        run_async(app.run())
    except ImportError as e:
        console.print(f"[red]Missing dependencies: {e}[/red]")
        console.print("[dim]Run: pip install fastapi uvicorn[/dim]")
    except KeyboardInterrupt:
        console.print("[yellow]Dashboard stopped[/yellow]")


# ============== Main Commands ==============

@app.command()
def version():
    """Show version information."""
    print_banner()
    console.print("[bold cyan]SecSuite[/bold cyan] - Open-source Security Tools Suite")
    console.print("[dim]Reconnaissance • Web Security • API Testing • AI Analysis[/dim]")
    console.print()
    console.print("Created by [bold red]TheSecuredAnalyst[/bold red]")
    console.print("https://github.com/TheSecuredAnalyst/security-suite")


@app.command()
def config():
    """Show current configuration."""
    settings = get_settings()

    table = Table(title="Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Data Directory", str(settings.data_dir))
    table.add_row("Debug Mode", str(settings.debug))
    table.add_row("Request Timeout", f"{settings.request_timeout}s")
    table.add_row("Max Concurrent", str(settings.max_concurrent_requests))
    table.add_row("Shodan API Key", "✓ Set" if settings.shodan_api_key else "✗ Not set")
    table.add_row("VirusTotal API Key", "✓ Set" if settings.virustotal_api_key else "✗ Not set")
    table.add_row("Anthropic API Key", "✓ Set" if settings.anthropic_api_key else "✗ Not set")
    table.add_row("OpenAI API Key", "✓ Set" if settings.openai_api_key else "✗ Not set")

    console.print(table)
    console.print()
    console.print("[dim]Set API keys via environment variables:[/dim]")
    console.print("[dim]  SECSUITE_ANTHROPIC_API_KEY, SECSUITE_OPENAI_API_KEY[/dim]")
    console.print("[dim]  SECSUITE_SHODAN_API_KEY, SECSUITE_VIRUSTOTAL_API_KEY[/dim]")


@app.command("wordlists")
def wordlists():
    """Show SecLists integration status and active wordlist sources."""
    status = seclists_status()

    if status["available"]:
        console.print(Panel(
            f"[green]SecLists detected[/green]\n{status['root']}",
            title="Wordlist Source",
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[yellow]SecLists not detected[/yellow]\nUsing built-in fallback wordlists",
            title="Wordlist Source",
            border_style="yellow",
        ))

    table = Table(title="Wordlist Integrations")
    table.add_column("Key", style="cyan")
    table.add_column("Module", style="magenta")
    table.add_column("Source", style="white")
    table.add_column("Entries", justify="right", style="green")
    table.add_column("Resolved File", style="dim")

    for entry in status["entries"]:
        source_style = "[green]SecLists[/green]" if entry["source"] == "seclists" else "[yellow]Fallback[/yellow]"
        table.add_row(
            entry["key"],
            entry["module"],
            source_style,
            str(entry["count"] or 0),
            entry["path"] or "-",
        )

    console.print(table)


# ============================================================
# VULN — Network Vulnerability Scanner
# secsuite vuln scan <target>   → quick scan, no audit trail
# secsuite vuln vapt <target>   → full VAPT with ROE + DOCX
# secsuite vuln list            → scan history
# ============================================================

@vuln_app.command("scan")
def vuln_scan(
    target: str = typer.Argument(..., help="IP, CIDR (192.168.1.0/24), range, or comma-separated IPs"),
    profile: str = typer.Option("normal", "--profile", "-p", help="quick | normal | full | stealth"),
    ports: str | None = typer.Option(None, "--ports", help="Custom ports: 22,80,443"),
    output_dir: str = typer.Option("reports", "--output", "-o", help="Output directory"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI analysis"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Scan a network target for open services and CVEs."""
    setup_logging(debug=verbose)
    import os
    from datetime import datetime

    from modules.vulnscan import CVELookup, ExploitSearch, NetworkScanner, RiskScorer, VulnReporter

    custom_ports = [int(p) for p in ports.split(",") if p.strip().isdigit()] if ports else None
    scanner = NetworkScanner(profile=profile, custom_ports=custom_ports)

    console.print(f"\n[bold cyan]Network Vulnerability Scan[/bold cyan] — {target}")
    console.print(f"[dim]Profile: {profile}[/dim]\n")

    services, errors = run_async(scanner.scan(target))
    for err in errors:
        console.print(f"[yellow]⚠  {err}[/yellow]")

    if not services:
        console.print("[yellow]No open services found.[/yellow]")
        return

    console.print(f"[green]Found {len(services)} open service(s)[/green]\n")

    cve_lookup = CVELookup()
    exploit_search = ExploitSearch()
    risk_scorer = RiskScorer()
    results = []
    total_cves = 0

    for svc in services:
        ip = svc["target_ip"]
        port = svc["port"]
        product = svc.get("product", "")
        version = svc.get("version", "")
        service_name = svc.get("name", "")

        console.print(f"[cyan]{ip}:{port}[/cyan] — {product} {version}".strip())

        cves = run_async(cve_lookup.lookup(product, version, service_name))
        total_cves += len(cves)
        risk_score, risk_level = risk_scorer.score(cves)
        color = risk_scorer.color(risk_level)

        if cves:
            console.print(f"  CVEs: [bold]{len(cves)}[/bold] | Risk: [{color}]{risk_level} ({risk_score}/100)[/{color}]")
            for cve in cves[:3]:
                console.print(f"  [dim]{cve['id']} (CVSS {cve['cvss_score']}) — {cve['description'][:80]}...[/dim]")
        else:
            console.print("  [dim]No CVEs found[/dim]")

        exploits = run_async(exploit_search.search(product, version, [c["id"] for c in cves]))
        if exploits:
            console.print(exploit_search.format_for_display(exploits))

        results.append({
            **svc,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "cve_details": cves,
            "exploits": exploits,
            "ai_analysis": "",
            "timestamp": datetime.now().isoformat(),
        })
        console.print()

    report_data = {
        "scan_date": datetime.now().isoformat(),
        "total_targets": len({s["target_ip"] for s in services}),
        "total_services": len(services),
        "total_cves": total_cves,
        "results": results,
    }

    os.makedirs(output_dir, exist_ok=True)
    reporter = VulnReporter(report_data)
    reporter.export_json(os.path.join(output_dir, "vuln_report.json"))
    reporter.export_markdown(os.path.join(output_dir, "vuln_report.md"))
    reporter.export_html(os.path.join(output_dir, "vuln_report.html"))

    console.print("\n[bold green]Scan complete.[/bold green]")
    console.print(f"  Services: {len(services)} | CVEs: {total_cves}")
    console.print(f"  Reports saved to: [underline]{output_dir}/[/underline]")


@vuln_app.command("vapt")
def vuln_vapt(
    target: str = typer.Argument(..., help="IP, CIDR, range, or comma-separated IPs"),
    profile: str = typer.Option("normal", "--profile", "-p",
                               help="quick | normal | lan | full | stealth"),
    ports: str | None = typer.Option(None, "--ports"),
    operator: str = typer.Option(..., "--operator", help="Operator name (required for audit trail)"),
    ticket: str = typer.Option(..., "--ticket", help="Change/approval ticket ID"),
    engagement: str | None = typer.Option(None, "--engagement", help="Engagement ID"),
    notes: str | None = typer.Option(None, "--notes"),
    allowed_cidrs: str | None = typer.Option(None, "--allowed", help="Allowed CIDRs (comma-separated)"),
    forbidden_cidrs: str | None = typer.Option(None, "--forbidden", help="Forbidden CIDRs (comma-separated)"),
    org_name: str = typer.Option("Organization", "--org"),
    group_name: str = typer.Option("Security Team", "--group"),
    unit_name: str = typer.Option("Internal VAPT", "--unit"),
    output_dir: str = typer.Option("reports", "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Full VAPT workflow with ROE validation, audit trail, and DOCX evidence report.

    Example:
      secsuite vuln vapt 192.168.1.0/24 --operator "John" --ticket "CHG-001"
    """
    setup_logging(debug=verbose)
    import os
    from datetime import datetime

    from modules.vulnscan import (
        CVELookup,
        ExploitSearch,
        NetworkScanner,
        RiskScorer,
        RulesOfEngagement,
        VulnReporter,
    )
    from modules.vulnscan.scanner import expand_target

    # ROE validation
    roe = RulesOfEngagement(
        allowed_cidrs=allowed_cidrs.split(",") if allowed_cidrs else None,
        forbidden_cidrs=forbidden_cidrs.split(",") if forbidden_cidrs else None,
    )

    if roe.is_configured:
        warnings, _ = roe.evaluate(expand_target(target))
        if warnings:
            console.print("\n[bold yellow]ROE Warnings:[/bold yellow]")
            for w in warnings:
                console.print(f"  [yellow]{w}[/yellow]")
            if not typer.confirm("\nProceed despite ROE warnings?"):
                raise typer.Abort()

    console.print(f"\n[bold cyan]Automated VAPT[/bold cyan] — {target}")
    console.print(f"[dim]Operator: {operator} | Ticket: {ticket} | Profile: {profile}[/dim]\n")

    custom_ports = [int(p) for p in ports.split(",") if p.strip().isdigit()] if ports else None
    scanner = NetworkScanner(profile=profile, custom_ports=custom_ports)
    services, errors = run_async(scanner.scan(target))

    for err in errors:
        console.print(f"[yellow]⚠  {err}[/yellow]")

    if not services:
        console.print("[yellow]No open services found.[/yellow]")
        return

    cve_lookup = CVELookup()
    exploit_search = ExploitSearch()
    risk_scorer = RiskScorer()
    results = []
    total_cves = 0

    for svc in services:
        product = svc.get("product", "")
        version = svc.get("version", "")
        cves = run_async(cve_lookup.lookup(product, version, svc.get("name", "")))
        total_cves += len(cves)
        risk_score, risk_level = risk_scorer.score(cves)
        exploits = run_async(exploit_search.search(product, version, [c["id"] for c in cves]))
        color = risk_scorer.color(risk_level)

        console.print(
            f"[cyan]{svc['target_ip']}:{svc['port']}[/cyan] {product} {version} — "
            f"[{color}]{risk_level}[/{color}] ({len(cves)} CVEs)"
        )

        results.append({
            **svc,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "cve_details": cves,
            "exploits": exploits,
            "ai_analysis": "",
            "timestamp": datetime.now().isoformat(),
        })

    report_data = {
        "scan_date": datetime.now().isoformat(),
        "total_targets": len({s["target_ip"] for s in services}),
        "total_services": len(services),
        "total_cves": total_cves,
        "scan_metadata": {
            "operator": operator,
            "ticket": ticket,
            "engagement": engagement or "",
            "notes": notes or "",
            "profile": profile,
        },
        "results": results,
    }

    os.makedirs(output_dir, exist_ok=True)
    reporter = VulnReporter(report_data)
    reporter.export_json(os.path.join(output_dir, "vapt_report.json"))
    reporter.export_markdown(os.path.join(output_dir, "vapt_report.md"))
    reporter.export_html(os.path.join(output_dir, "vapt_report.html"))

    try:
        docx_path = reporter.export_docx(
            os.path.join(output_dir, "vapt_report.docx"),
            org_name=org_name,
            group_name=group_name,
            unit_name=unit_name,
        )
        console.print(f"  DOCX: [underline]{docx_path}[/underline]")
    except ImportError:
        console.print("[yellow]  DOCX skipped — install python-docx: pip install python-docx[/yellow]")

    console.print("\n[bold green]VAPT complete.[/bold green]")
    console.print(f"  Operator: {operator} | Ticket: {ticket}")
    console.print(f"  Services: {len(services)} | CVEs: {total_cves}")
    console.print(f"  Reports saved to: [underline]{output_dir}/[/underline]")


# ============================================================
# THREAT — IP Threat Intelligence
# secsuite threat ip <ip>
# secsuite threat ip --file ips.txt
# ============================================================

@threat_app.command("ip")
def threat_ip(
    ip: str | None = typer.Argument(None, help="Single IP address to check"),
    file: str | None = typer.Option(None, "--file", "-f", help="File with one IP per line"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save results (JSON or CSV based on --format)"),
    fmt: str = typer.Option("table", "--format", help="Output format: table | json | csv"),
    threshold: int = typer.Option(1, "--threshold", help="Min malicious VT vendors to flag"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    delay: float = typer.Option(15.0, "--delay", help="Seconds between VT calls"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Multi-source IP threat intelligence.

    Checks IPs against: VirusTotal, ThreatFox, AbuseIPDB, Shodan, OTX, GreyNoise.

    Requires: VT_API_KEY env var (others optional).

    Examples:
      secsuite threat ip 8.8.8.8
      secsuite threat ip --file ips.txt --format csv --output results.csv
    """
    setup_logging(debug=verbose)
    from pathlib import Path

    from modules.threat_intel import IPThreatScanner

    # Collect IPs
    ips: list[str] = []
    if file:
        try:
            ips = [ln.strip() for ln in Path(file).read_text().splitlines() if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1) from None
    elif ip:
        ips = [ip]
    else:
        console.print("[red]Provide an IP argument or --file[/red]")
        raise typer.Exit(1)

    scanner = IPThreatScanner(threshold=threshold, delay=delay)
    sources = " · ".join(scanner.active_sources)
    console.print(f"\n[bold cyan]IP Threat Intelligence[/bold cyan]  [dim]{sources}[/dim]")
    console.print(f"Scanning {len(ips)} IP(s)...\n")

    results = run_async(scanner.scan_many(ips))

    if not results:
        console.print("[yellow]No results returned. Check VT_API_KEY.[/yellow]")
        return

    results = scanner.sorted_by_threat(results)

    if fmt == "table":
        from rich.table import Table as RichTable
        tbl = RichTable(title="Threat Intelligence Results", show_lines=True)
        tbl.add_column("IP", style="cyan")
        tbl.add_column("Status", justify="center")
        tbl.add_column("Mal", justify="right")
        tbl.add_column("Sus", justify="right")
        tbl.add_column("Country")
        tbl.add_column("AS Owner")
        tbl.add_column("Rep", justify="right")

        colors = {"malicious": "bold red", "suspicious": "bold yellow", "clean": "bold green"}
        for r in results:
            lvl = r.get("threat_level", "clean")
            c = colors.get(lvl, "white")
            tbl.add_row(
                r["ip"], f"[{c}]{lvl.upper()}[/{c}]",
                str(r["malicious_count"]), str(r["suspicious_count"]),
                r["country"], r["as_owner"], str(r["reputation"]),
            )
        console.print(tbl)

    if output:
        if fmt == "csv":
            scanner.to_csv(results, output)
            console.print(f"\n[green]CSV saved: {output}[/green]")
        else:
            scanner.to_json(results, output)
            console.print(f"\n[green]JSON saved: {output}[/green]")
    elif fmt == "json":
        import json as _json
        console.print(_json.dumps(results, indent=2))


# ============================================================
# PASSWORD — Audit and Generate
# secsuite password audit <password>
# secsuite password generate
# secsuite password batch --file passwords.txt
# ============================================================

@password_app.command("audit")
def password_audit(
    password: str = typer.Argument(..., help="Password to audit"),
    policy: str = typer.Option("enterprise", "--policy", "-p", help="home | enterprise"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Audit a single password for strength and policy compliance."""
    setup_logging(debug=verbose)
    from modules.password import PasswordAuditor
    from modules.password.auditor import PolicyMode

    mode = PolicyMode.HOME if policy == "home" else PolicyMode.ENTERPRISE
    auditor = PasswordAuditor(policy=mode)
    result = auditor.audit(password)

    color_map = {"STRONG": "green", "LOW": "blue", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
    color = color_map.get(result.risk_label, "white")

    console.print(f"\n[bold]Password Audit[/bold]  (policy: {policy})")
    console.print(f"  Length:  {result.length}")
    console.print(f"  Entropy: {result.entropy:.1f} bits")
    console.print(f"  Score:   {result.score}/100")
    console.print(f"  Risk:    [{color}]{result.risk_label}[/{color}]")

    char_flags = []
    if result.has_upper:
        char_flags.append("UPPER")
    if result.has_lower:
        char_flags.append("lower")
    if result.has_digit:
        char_flags.append("123")
    if result.has_special:
        char_flags.append("!@#")
    console.print(f"  Chars:   {' '.join(char_flags) or 'none'}")

    if result.is_common:
        console.print("  [bold red]⚠  Matches a common password list[/bold red]")
    if result.patterns_found:
        console.print(f"  Patterns: {', '.join(result.patterns_found)}")

    console.print("\n[bold]Recommendations:[/bold]")
    for rec in result.recommendations:
        icon = "✓" if "meets" in rec.lower() else "→"
        color2 = "green" if "meets" in rec.lower() else "yellow"
        console.print(f"  [{color2}]{icon} {rec}[/{color2}]")


@password_app.command("generate")
def password_generate(
    length: int = typer.Option(20, "--length", "-l"),
    count: int = typer.Option(1, "--count", "-n", help="Number of passwords to generate"),
    passphrase: bool = typer.Option(False, "--passphrase", help="Generate passphrase instead"),
    words: int = typer.Option(5, "--words", help="Words in passphrase"),
    no_special: bool = typer.Option(False, "--no-special"),
    no_digits: bool = typer.Option(False, "--no-digits"),
    no_ambiguous: bool = typer.Option(False, "--no-ambiguous", help="Exclude lookalike chars (O,0,I,l,1)"),
):
    """Generate secure random passwords or passphrases."""
    from modules.password import PasswordGenerator

    console.print()
    if passphrase:
        for _ in range(count):
            p = PasswordGenerator.generate_passphrase(word_count=words)
            console.print(f"  [green]{p}[/green]")
    else:
        for _ in range(count):
            p = PasswordGenerator.generate(
                length=length,
                use_special=not no_special,
                use_digits=not no_digits,
                exclude_ambiguous=no_ambiguous,
            )
            console.print(f"  [green]{p}[/green]")
    console.print()


@password_app.command("batch")
def password_batch(
    file: str = typer.Argument(..., help="File with one password per line"),
    policy: str = typer.Option("enterprise", "--policy", "-p"),
    output: str | None = typer.Option(None, "--output", "-o", help="Export path (JSON or CSV)"),
    fmt: str = typer.Option("json", "--format", help="json | csv"),
):
    """Batch-audit passwords from a file. Exports metrics only (no plaintext)."""
    from modules.password import PasswordAuditor
    from modules.password.auditor import PolicyMode

    mode = PolicyMode.HOME if policy == "home" else PolicyMode.ENTERPRISE
    auditor = PasswordAuditor(policy=mode)
    results = auditor.audit_file(file)

    if not results:
        console.print("[yellow]No passwords audited.[/yellow]")
        return

    risk_counts: dict[str, int] = {}
    for r in results:
        risk_counts[r.risk_label] = risk_counts.get(r.risk_label, 0) + 1

    console.print(f"\n[bold]Batch Audit[/bold] — {len(results)} password(s)")
    color_map = {"STRONG": "green", "LOW": "blue", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
    for label, cnt in sorted(risk_counts.items()):
        c = color_map.get(label, "white")
        console.print(f"  [{c}]{label}[/{c}]: {cnt}")

    if output:
        if fmt == "csv":
            auditor.export_csv(results, output)
        else:
            auditor.export_json(results, output)
        console.print(f"\n[green]Results saved: {output}[/green]")


if __name__ == "__main__":
    app()
