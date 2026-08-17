# Quick Start — Security Suite

This guide gets you from zero to running your first scan in under 10 minutes.

---

## Step 1 — Install

Run the setup script for your operating system. It handles everything automatically.

**Linux / macOS**
```bash
git clone https://github.com/TheSecuredAnalyst/security-suite.git
cd security-suite
bash setup.sh
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/TheSecuredAnalyst/security-suite.git
cd security-suite
powershell -ExecutionPolicy Bypass -File setup.ps1
```

The script will:
- Install Python 3.11 if you don't have it
- Install Git if you don't have it
- Create a virtual environment (an isolated Python sandbox for this project)
- Install all dependencies
- Install Ollama (so you can use AI features without an API key)
- Download a small AI model (~2 GB)
- Create your `.env` configuration file

---

## Step 2 — Activate the environment

Every time you open a new terminal, you need to activate the virtual environment first.

**Linux / macOS**
```bash
cd security-suite
source venv/bin/activate
```

**Windows PowerShell**
```powershell
cd security-suite
.\venv\Scripts\Activate.ps1
```

You'll know it's active when you see `(venv)` at the start of your terminal prompt.

---

## Step 3 — Confirm it works

```bash
secsuite --help
```

You should see a list of commands. If you get a "command not found" error, make sure
you completed Step 2.

---

## Your First 5 Minutes

Try these in order to see what the tool can do.

### 1. Look up a domain

```bash
secsuite osint dns example.com
```

This checks DNS records — what IP addresses the domain points to, its mail servers,
name servers, and SPF/DMARC email security settings.

Expected output:
```
DNS Enumeration: example.com

╭──────────────────── [INFO] IPv4 Addresses Found ─────────────────────╮
│ Domain resolves to 2 IPv4 address(es)                                │
╰───────────────────────────────────────────────────────────────────────╯
  addresses: ['104.18.27.120', '104.18.26.120']

╭──────────────────── [INFO] Mail Servers Found ───────────────────────╮
│ Found 1 mail server(s)                                               │
╰───────────────────────────────────────────────────────────────────────╯

Completed in 0.68s
```

### 2. Check a website's security headers

```bash
secsuite osint headers https://example.com
```

This checks whether the website sets the security headers that browsers expect
(things that prevent clickjacking, content sniffing attacks, etc.).

### 3. Check SSL/TLS

```bash
secsuite scan ssl example.com
```

This checks whether the SSL certificate is valid, which versions of TLS are
enabled, and whether any known weak protocols (like SSLv3 or TLS 1.0) are on.

### 4. Ask the AI a security question

```bash
secsuite ai ask "What is SQL injection and how do I prevent it?" --provider ollama --model llama3.2
```

This uses the local AI model that was installed in Step 1 — no internet connection
or API key needed.

### 5. Start the interactive web interface

```bash
secsuite serve
```

Then open your browser and go to: **http://localhost:8000/docs**

You'll see an interactive page that lists every API endpoint. You can click on any
endpoint, fill in the inputs, and click "Execute" to run it — no code needed.

---

## Common Command Patterns

```bash
# Always specify a target (domain, IP, or URL)
secsuite osint dns <target>
secsuite scan ssl <target>
secsuite ai analyze <target> --provider ollama --model llama3.2

# Add --verbose to see more detail
secsuite osint dns example.com --verbose

# Save a report to a file
secsuite report html example.com -o my_report.html
secsuite report json example.com -o my_report.json
```

---

## What the REST API is for

The `secsuite serve` command starts a web server that lets you:

- Trigger scans from any programming language or tool (curl, Postman, Python, etc.)
- Retrieve results in JSON format for use in other systems
- Use the interactive `/docs` page to explore and run any scan without writing code

Think of it as a way to use Security Suite as a building block in your own projects,
or just as a more visual way to run scans.

---

## Troubleshooting

Something not working? See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for fixes to
the most common problems, including Windows-specific issues.

---

## Next Steps

| Goal | Command |
|------|---------|
| Full OSINT scan | `secsuite osint full example.com` |
| Scan a web app for XSS | `secsuite scan xss "https://example.com/search?q=test"` |
| Test your API | `secsuite api scan http://localhost:8000/openapi.json` |
| Port scan | `secsuite osint ports 192.168.1.1` |
| See all available commands | `secsuite --help` |
| See help for a specific command | `secsuite osint --help` |
| Full documentation | [USAGE.md](USAGE.md) |
