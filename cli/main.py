"""Main CLI entry point for Security Suite."""

import asyncio
import random
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from core.config import get_settings
from core.logger import setup_logging
from core.models import Target

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
]


def print_banner():
    """Print the Metasploit-style banner."""
    banner = random.choice(BANNERS)
    console.print(banner)

    # Module stats
    stats = Text()
    stats.append("       =[ ", style="white")
    stats.append("SecSuite v0.1.0", style="bold cyan")
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

app.add_typer(osint_app, name="osint")
app.add_typer(scan_app, name="scan")
app.add_typer(phish_app, name="phish")
app.add_typer(exploit_app, name="exploit")
app.add_typer(ai_app, name="ai")
app.add_typer(report_app, name="report")
app.add_typer(apisec_app, name="api")
app.add_typer(siem_app, name="siem")
app.add_typer(schedule_app, name="schedule")


def run_async(coro):
    """Run async function in sync context."""
    return asyncio.get_event_loop().run_until_complete(coro)


def display_result(result):
    """Display scan result in a nice format."""
    if not result.success:
        console.print(f"[red]Scan failed with errors:[/red]")
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
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Ports to scan (e.g., '22,80,443' or '1-1000')"),
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
        DNSEnumerator, WhoisLookup, SubdomainScanner,
        HeaderAnalyzer, TechDetector, EmailHarvester
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
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Severity filter (comma-separated)"),
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="Template tags (comma-separated)"),
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
        DNSEnumerator, WhoisLookup, SubdomainScanner,
        HeaderAnalyzer, TechDetector, PortScanner
    )
    from modules.webscanner import (
        WebCrawler, XSSScanner, SQLiScanner, DirectoryBruteforcer, SSLAnalyzer
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
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name"),
    base_url: Optional[str] = typer.Option(None, "--base-url", "-b", help="Base URL for ollama or custom API"),
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
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target to scan first"),
    provider: str = typer.Option("anthropic", "--provider", "-p", help="LLM provider (anthropic/openai/ollama/qwen/llama3/mistral)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name"),
    base_url: Optional[str] = typer.Option(None, "--base-url", "-b", help="Base URL for ollama or custom API"),
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
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name"),
    base_url: Optional[str] = typer.Option(None, "--base-url", "-b", help="Base URL"),
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
    from modules.ai import RemediationEngine
    from core.models import Finding, Severity

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
    auth_token: Optional[str] = typer.Option(None, "--token", "-t", help="Auth token"),
):
    """Scan API endpoints for vulnerabilities."""
    setup_logging()

    console.print(f"[bold]API Security Scan:[/bold] {spec_url}")

    async def run():
        from modules.apisec import OpenAPIParser, APIEndpointTester

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
    auth_token: Optional[str] = typer.Option(None, "--token", "-t"),
):
    """Fuzz API endpoints for vulnerabilities."""
    setup_logging()

    console.print(f"[bold]API Fuzzing:[/bold] {spec_url}")

    async def run():
        from modules.apisec import OpenAPIParser, APIFuzzer

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
        from modules.apisec import OpenAPIParser, APIAuthTester

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
    token: Optional[str] = typer.Option(None, "--token", "-t", help="Auth token"),
):
    """Test SIEM connection."""
    setup_logging()

    console.print(f"[bold]Testing SIEM Connection:[/bold] {provider}")

    async def run():
        from modules.siem import SplunkExporter, ElasticsearchExporter, WebhookExporter

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
    token: Optional[str] = typer.Option(None, "--token", "-t"),
):
    """Run scan and export results to SIEM."""
    setup_logging()

    console.print(f"[bold]Scan and Export:[/bold] {target} -> {provider}")

    results = _collect_scan_results(target, ["dns", "headers", "tech", "ssl"])

    async def run():
        from modules.siem import SplunkExporter, ElasticsearchExporter, WebhookExporter

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
    console.print("https://github.com/53cur3dL34rn/security-suite")


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


if __name__ == "__main__":
    app()
