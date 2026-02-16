# Security Suite

[![CI](https://github.com/53cur3dL34rn/security-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/53cur3dL34rn/security-suite/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A comprehensive open-source security tools suite for OSINT reconnaissance, web security testing, API security assessment, and compliance checking with AI-powered analysis.

```
   ____            ____        _ __
  / __/__ ___     / __/_ __(_) /____
 _\ \/ -_) __/   _\ \/ // / / __/ -_)
/___/\__/\__/   /___/\_,_/_/\__/\__/

       =[ SecSuite v0.1.0 ]=
+ -- --=[ 11 OSINT modules | 6 Web scanners | 4 API security tools ]=--
+ -- --=[ AI-powered analysis with Ollama/Anthropic/OpenAI       ]=--
+ -- --=[ SIEM integration | Scheduled scans | Web dashboard      ]=--
```

---

## Highlights

| Module | Capabilities | Tools |
|--------|-------------|-------|
| **OSINT** | DNS, WHOIS, subdomains, ports, tech detection, headers, emails | nmap, Shodan, VirusTotal |
| **Web Scanner** | XSS, SQLi, directory bruteforce, SSL/TLS analysis, crawling | Nuclei |
| **API Security** | OpenAPI parsing, auth bypass, JWT testing, BOLA/IDOR, fuzzing | - |
| **AI Analysis** | Finding correlation, remediation, executive summaries | Ollama, Anthropic, OpenAI |
| **SIEM** | Splunk, Elasticsearch, Syslog, webhooks (Slack/Discord/PagerDuty) | CEF/LEEF formats |
| **Scheduler** | Cron-based recurring scans with persistent history | - |
| **Dashboard** | Real-time monitoring, findings visualization, scan history | FastAPI |
| **Compliance** | OWASP Top 10, CIS Controls assessment | - |
| **Exploit** | Exploit search and CVE lookup | SearchSploit, Exploit-DB |
| **Phishing** | Security awareness campaigns and simulation | - |

---

## Demo

### DNS Enumeration
```
$ secsuite osint dns example.com

DNS Enumeration: example.com
╭──────────────────────── [INFO] IPv4 Addresses Found ─────────────────────────╮
│ Domain resolves to 2 IPv4 address(es)                                        │
╰──────────────────────────────────────────────────────────────────────────────╯
  addresses: ['104.18.27.120', '104.18.26.120']

╭───────────────────────── [INFO] Mail Servers Found ──────────────────────────╮
│ Found 1 mail server(s)                                                       │
╰──────────────────────────────────────────────────────────────────────────────╯
  servers: ['0 .']

╭────────────────────────── [INFO] SPF Record Found ───────────────────────────╮
│ Domain has SPF email authentication configured                               │
╰──────────────────────────────────────────────────────────────────────────────╯
  spf: ['"v=spf1 -all"']

╭─────────────────────── [INFO] Nameservers Identified ────────────────────────╮
│ Found 2 nameserver(s)                                                        │
╰──────────────────────────────────────────────────────────────────────────────╯
  nameservers: ['hera.ns.cloudflare.com.', 'elliott.ns.cloudflare.com.']

Completed in 0.68s
```

### SSL/TLS Analysis
```
$ secsuite scan ssl example.com

SSL/TLS Analysis: example.com
╭─────────────────────── [INFO] TLS Versions Supported ────────────────────────╮
│ Supported: SSLv3, TLSv1.2, TLSv1.3                                          │
╰──────────────────────────────────────────────────────────────────────────────╯
  SSLv3: True   TLSv1.0: False   TLSv1.1: False   TLSv1.2: True   TLSv1.3: True

╭──────────────────────────── [HIGH] SSLv3 Enabled ────────────────────────────╮
│ SSLv3 is enabled - vulnerable to POODLE attack                               │
╰──────────────────────────────────────────────────────────────────────────────╯

Completed in 0.78s
```

### Configuration
```
$ secsuite config

                  Configuration
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Setting            ┃ Value                    ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Data Directory     │ ~/.secsuite              │
│ Debug Mode         │ False                    │
│ Request Timeout    │ 30s                      │
│ Max Concurrent     │ 10                       │
│ Shodan API Key     │ ✗ Not set                │
│ VirusTotal API Key │ ✗ Not set                │
│ Anthropic API Key  │ ✗ Not set                │
│ OpenAI API Key     │ ✗ Not set                │
└────────────────────┴──────────────────────────┘
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                           │
├──────────────────────────┬──────────────────────────────────────┤
│   CLI (Typer)            │  REST API (FastAPI)                  │
│   secsuite <command>     │  /api/v1/scans, /api/v1/results     │
└──────────────────────────┴──────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Core Infrastructure                           │
│  Target Model ─ Config ─ Logging ─ Caching ─ Error Handling    │
│  HTTP Client ─ Exporters (JSON/CSV/HTML/Markdown)              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Scanning Modules                              │
│                                                                 │
│  ┌─────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────────┐ │
│  │  OSINT  │ │Web Scanner│ │API Security│ │   AI Analysis   │ │
│  │11 tools │ │ 6 tools   │ │  4 tools   │ │ 3 providers     │ │
│  └─────────┘ └───────────┘ └───────────┘ └──────────────────┘ │
│  ┌─────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────────┐ │
│  │  SIEM   │ │ Scheduler │ │Compliance │ │Exploit / Phishing│ │
│  │ 4 backends│ │ cron-based│ │OWASP/CIS │ │ search / sim    │ │
│  └─────────┘ └───────────┘ └───────────┘ └──────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Output & Integration                          │
│  JSON/CSV/HTML Reports ─ SIEM Export ─ Webhook Notifications   │
│  Web Dashboard ─ Scheduled Automation                           │
└─────────────────────────────────────────────────────────────────┘
```

> For detailed architecture documentation, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Installation

```bash
# Clone the repository
git clone https://github.com/53cur3dL34rn/security-suite.git
cd security-suite

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install base package
pip install -e .

# Install with all optional dependencies
pip install -e ".[all]"

# Or install specific extras
pip install -e ".[dev]"       # Development tools
pip install -e ".[ai]"        # AI providers (OpenAI, Anthropic)
pip install -e ".[dashboard]" # Web dashboard (FastAPI, uvicorn)
```

## Configuration

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

All settings use the `SECSUITE_` prefix. API keys are optional — core features work without them.

| Variable | Service | Required |
|----------|---------|----------|
| `SECSUITE_SHODAN_API_KEY` | Shodan host intelligence | No |
| `SECSUITE_VIRUSTOTAL_API_KEY` | VirusTotal malware analysis | No |
| `SECSUITE_HUNTER_API_KEY` | Hunter.io email discovery | No |
| `SECSUITE_ANTHROPIC_API_KEY` | Claude AI analysis | No |
| `SECSUITE_OPENAI_API_KEY` | GPT AI analysis | No |

> For local AI analysis with no API keys, use [Ollama](#local-llm-setup-ollama).

---

## Usage

### OSINT Reconnaissance

```bash
secsuite osint dns example.com          # DNS enumeration
secsuite osint whois example.com        # WHOIS lookup
secsuite osint subdomains example.com   # Subdomain discovery
secsuite osint headers https://example.com  # HTTP header analysis
secsuite osint ports 192.168.1.1        # Port scanning (requires nmap)
secsuite osint tech https://example.com # Technology detection
secsuite osint emails example.com       # Email harvesting
secsuite osint vt example.com           # VirusTotal lookup
secsuite osint shodan 8.8.8.8           # Shodan lookup
secsuite osint full example.com         # Full OSINT scan (all modules)
```

### Web Security Scanning

```bash
secsuite scan crawl https://example.com                    # Web crawling
secsuite scan xss "https://example.com/search?q=test"      # XSS detection
secsuite scan sqli "https://example.com/product?id=1"      # SQL injection
secsuite scan dirs https://example.com                     # Directory bruteforce
secsuite scan ssl example.com                              # SSL/TLS analysis
secsuite scan nuclei https://example.com                   # Nuclei scanning
```

### API Security Testing

```bash
secsuite api scan https://api.example.com/openapi.json     # Scan from OpenAPI spec
secsuite api scan spec.yaml --auth-header "Authorization: Bearer token"
secsuite api fuzz https://api.example.com/openapi.json     # Fuzz endpoints
secsuite api auth-test https://api.example.com --auth-header "Authorization: Bearer token"
```

### AI-Powered Analysis

```bash
secsuite ai analyze results.json                           # Analyze with default provider
secsuite ai analyze results.json --provider anthropic      # Use Claude
secsuite ai analyze results.json --provider ollama --model llama3  # Use local LLM
secsuite ai remediate results.json --output remediation.md # Remediation report
```

### SIEM Integration

```bash
secsuite siem test splunk                                  # Test connection
secsuite siem export results.json --backend splunk         # Export to Splunk
secsuite siem export results.json --backend elasticsearch --index security-findings
```

### Scheduled Scans

```bash
secsuite schedule create "Daily Web Scan" example.com --frequency daily --modules dns,headers,ssl
secsuite schedule list                                     # List schedules
secsuite schedule run <schedule-id>                        # Run immediately
secsuite schedule start                                    # Start scheduler daemon
```

### Dashboard & Reports

```bash
secsuite dashboard --port 8080                             # Start web dashboard
secsuite report generate results.json --format html --output report.html
secsuite osint dns example.com --output json               # JSON output
secsuite osint full example.com --output-file report.json  # Save to file
```

### Exploit Search & Phishing Simulation

```bash
secsuite exploit search "apache 2.4"                       # Search exploits
secsuite exploit search "CVE-2021-44228"                   # Search by CVE
secsuite phish templates                                   # List email templates
secsuite phish server --port 8080                          # Start phishing server
```

---

## Local LLM Setup (Ollama)

Run AI analysis locally with no cloud API keys:

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3
ollama pull qwen2.5
ollama pull mistral

# Use with secsuite
secsuite ai analyze results.json --provider ollama --model llama3
```

## External Dependencies

Some features require external tools:

| Tool | Feature | Installation |
|------|---------|--------------|
| nmap | Port scanning | `apt install nmap` |
| nuclei | Vulnerability scanning | [nuclei releases](https://github.com/projectdiscovery/nuclei) |
| searchsploit | Exploit search | `apt install exploitdb` |

---

## Project Structure

```
security-suite/
├── cli/                 # CLI commands (Typer)
├── core/                # Shared models, config, logging, caching
├── api/                 # REST API (FastAPI)
│   └── routers/         # API route handlers
├── modules/
│   ├── osint/           # OSINT tools (11 modules)
│   ├── webscanner/      # Web security scanners (6 modules)
│   ├── apisec/          # API security testing (4 modules)
│   ├── ai/              # AI analysis (3 providers)
│   ├── siem/            # SIEM integration (4 backends)
│   ├── scheduler/       # Scheduled scans
│   ├── compliance/      # OWASP/CIS compliance
│   ├── exploit/         # Exploit search
│   └── phishing/        # Phishing simulation
├── dashboard/           # Web UI (FastAPI)
├── tests/               # Test suite
├── .env.example         # Environment template
├── pyproject.toml       # Package configuration
├── ARCHITECTURE.md      # System architecture docs
├── USAGE.md             # Detailed usage examples
└── QUICK_START.md       # Getting started guide
```

## Development

```bash
pip install -e ".[dev]"          # Install dev dependencies
pytest                           # Run tests
pytest --cov=core --cov=modules  # Run with coverage
ruff check .                     # Lint code
mypy core modules                # Type checking
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, data flow, module architecture |
| [USAGE.md](USAGE.md) | Detailed CLI usage with examples |
| [QUICK_START.md](QUICK_START.md) | Getting started guide with demos |
| [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) | Implementation details and decisions |

---

## Disclaimer

This tool is intended for **authorized security testing** and **educational purposes only**.

- Always obtain proper written authorization before testing systems you do not own
- Phishing simulations should only be conducted as part of approved security awareness programs
- The developers are not responsible for misuse of this software
- Comply with all applicable laws and regulations in your jurisdiction

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

AGPL-3.0 - See [LICENSE](LICENSE) file for details.
