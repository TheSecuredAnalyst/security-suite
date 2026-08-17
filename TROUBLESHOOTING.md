# Troubleshooting — Security Suite

This page covers the most common problems people run into, with step-by-step fixes.
Windows issues are covered in detail because they come up most often.

---

## Table of Contents

1. [Windows Issues](#windows-issues)
2. [Python / Installation Issues](#python--installation-issues)
3. [Virtual Environment Issues](#virtual-environment-issues)
4. [Ollama / AI Issues](#ollama--ai-issues)
5. [REST API / Docs Page Issues](#rest-api--docs-page-issues)
6. [Scan / Tool Issues](#scan--tool-issues)
7. [How to Get More Help](#how-to-get-more-help)

---

## Windows Issues

### "running scripts is disabled on this system"

**What you see:**
```
.\venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system.
```

**What it means:**  
Windows blocks PowerShell scripts by default as a security measure.

**Fix:**  
Run this once in PowerShell (you only need to do this once per machine):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then try activating the venv again:
```powershell
.\venv\Scripts\Activate.ps1
```

---

### Python installed but `python` command not found

**What you see:**
```
python : The term 'python' is not recognized
```

**What it means:**  
Python was installed but wasn't added to the system PATH (or the PATH hasn't refreshed yet).

**Fix — Option 1 (easiest):** Close PowerShell completely and open a new one. PATH updates don't apply to already-open windows.

**Fix — Option 2:** Find where Python was installed and use the full path:
```powershell
# Try the py launcher (usually works on Windows)
py --version

# If that works, use py instead of python everywhere
py -m venv venv
```

**Fix — Option 3:** Add Python to PATH manually:
1. Search Windows for "Edit the system environment variables"
2. Click "Environment Variables"
3. Under "User variables", find "Path" and click Edit
4. Click New and add: `C:\Users\YourName\AppData\Local\Programs\Python\Python311`
5. Also add: `C:\Users\YourName\AppData\Local\Programs\Python\Python311\Scripts`
6. Click OK, close PowerShell, open a new one

**Fix — Option 4:** Reinstall Python and tick the box:
When running the Python installer, check **"Add Python to PATH"** before clicking Install.

---

### `secsuite` command not found after installation

**What you see:**
```
secsuite : The term 'secsuite' is not recognized
```

**What it means:**  
The virtual environment is not activated, or the package wasn't installed correctly.

**Fix — Step 1:** Activate the environment:
```powershell
.\venv\Scripts\Activate.ps1
```
You should see `(venv)` in your prompt. Then try `secsuite` again.

**Fix — Step 2:** If it still doesn't work, reinstall:
```powershell
pip install -e ".[all]"
```

---

### Windows Defender blocks nmap or scan tools

**What you see:**  
Windows Defender SmartScreen blocks `nmap` from running, or an antivirus alert appears.

**What it means:**  
Security scanning tools are sometimes flagged by antivirus software because they do
things that look suspicious (scanning ports, sending crafted packets).

**Fix:**
1. Add an exclusion for the `security-suite` folder in Windows Security:
   - Open Windows Security → Virus & threat protection → Manage settings
   - Under "Exclusions", click "Add or remove exclusions"
   - Add the folder: your `security-suite` directory
2. Or use the CLI on Windows Subsystem for Linux (WSL) to avoid these conflicts entirely.

---

### Ollama installed but AI commands fail

**What you see:**
```
Connection refused: localhost:11434
```

**What it means:**  
Ollama is installed but the server isn't running.

**Fix:**  
On Windows, Ollama runs as a background app in the system tray (bottom-right corner).
Look for the Ollama icon (a llama face). If it's not there:
1. Open the Start Menu and search for "Ollama"
2. Launch it — it starts in the system tray
3. Wait 5–10 seconds, then retry your secsuite command

If Ollama isn't installed:
```powershell
winget install Ollama.Ollama
```
Or download it from: https://ollama.com/download/windows

---

### `winget` not available

**What you see:**
```
winget : The term 'winget' is not recognized
```

**What it means:**  
`winget` (Windows Package Manager) isn't installed. It ships with Windows 10 (version 2004+)
and Windows 11, but may be missing on older systems or fresh installs.

**Fix:**  
Install "App Installer" from the Microsoft Store:
1. Open the Microsoft Store (search for it in the Start Menu)
2. Search for "App Installer"
3. Install it
4. Close and reopen PowerShell
5. Re-run the setup script

Alternatively, install the required tools manually:
- Python: https://www.python.org/downloads/
- Git: https://git-scm.com/download/win
- Ollama: https://ollama.com/download/windows

---

### Git not recognised / clone fails

**What you see:**
```
git : The term 'git' is not recognized
```

**Fix:**
```powershell
winget install Git.Git
```
Then close PowerShell and open a new one.

Or download from: https://git-scm.com/download/win  
During install, choose "Git from the command line and also from 3rd-party software".

---

## Python / Installation Issues

### `pip install` fails with "Microsoft Visual C++ required"

**What you see:**
```
error: Microsoft Visual C++ 14.0 or greater is required.
```

**Fix:**  
Install the Microsoft C++ Build Tools:
1. Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Run the installer, select "C++ build tools", install
3. Retry: `pip install -e ".[all]"`

On Linux, install build tools instead:
```bash
# Ubuntu/Debian
sudo apt install build-essential python3-dev

# Fedora/RHEL
sudo dnf groupinstall "Development Tools" && sudo dnf install python3-devel
```

---

### `pip install` fails with SSL errors

**What you see:**
```
SSL: CERTIFICATE_VERIFY_FAILED
```

**Fix:**
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -e ".[all]"
```

This usually happens on corporate networks with SSL inspection. Let your IT team know
if the above doesn't work.

---

### Wrong Python version is used

**What you see after activating venv:**
```
Python 3.8.10   ← too old, needs 3.10+
```

**Fix:** Create the venv using a specific Python version:
```bash
# Linux — use the versioned command directly
python3.11 -m venv venv
source venv/bin/activate

# Windows — use the py launcher
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
```

---

## Virtual Environment Issues

### "No module named secsuite" or "No module named core"

**What it means:**  
The virtual environment isn't activated, or the package isn't installed in it.

**Fix:**
```bash
# Activate first
source venv/bin/activate          # Linux/macOS
.\venv\Scripts\Activate.ps1       # Windows

# Then install
pip install -e ".[all]"

# Verify
secsuite --help
```

---

### Need to start fresh (venv is broken)

```bash
# Delete and recreate
rm -rf venv                        # Linux/macOS
Remove-Item -Recurse -Force venv   # Windows PowerShell

python3 -m venv venv               # Linux/macOS
py -3.11 -m venv venv              # Windows

source venv/bin/activate           # Linux/macOS
.\venv\Scripts\Activate.ps1        # Windows

pip install -e ".[all]"
```

---

## Ollama / AI Issues

### "ollama: command not found" on Linux

**Fix:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

---

### Ollama installed but `ollama serve` fails

**What you see:**
```
Error: listen tcp 127.0.0.1:11434: bind: address already in use
```

**What it means:**  
Ollama is already running. You don't need to start it again.

**Fix:** Just use it — the server is already up:
```bash
ollama list          # check what models you have
ollama pull llama3.2 # pull a model if needed
```

---

### Model pull is very slow or stalls

Models are large files (1–8 GB). This is normal on the first download. 
If it stalls completely:
```bash
# Cancel with Ctrl+C, then try again
ollama pull llama3.2
```
Ollama resumes interrupted downloads.

---

### "model not found" when running AI commands

**What you see:**
```
Error: model 'llama3' not found
```

**What it means:**  
The model name changed or was never downloaded.

**Fix:**
```bash
ollama list          # see what you have
ollama pull llama3.2 # download it (note: llama3.2, not llama3)
```

Then use the exact name you see in `ollama list`:
```bash
secsuite ai ask "..." --provider ollama --model llama3.2
```

---

### AI response is very slow

This is normal if your machine has no dedicated GPU — the model runs on your CPU.
Use a smaller/faster model:
```bash
ollama pull llama3.2        # 3B params — fast on most machines
ollama pull qwen2.5:3b      # also small and fast
```

Avoid 7B+ models unless you have a GPU or at least 16 GB RAM.

---

## REST API / Docs Page Issues

### Blank page at `http://localhost:8000/docs`

**What it means:**  
The Swagger UI interface (which draws the docs page) loads its CSS and JavaScript
from the internet (`unpkg.com`). If that site is blocked on your network, the page
appears blank.

**How to check:**  
Open your browser's developer tools (press F12), go to the Console tab.
If you see errors like `Failed to load resource` for `unpkg.com`, it's a network issue.

**Fix — Option 1 (easiest):** Use mobile data or a different network temporarily
to load the docs page once. After that, the browser usually caches the assets.

**Fix — Option 2:** Use the raw API directly with curl or Postman instead of the browser docs.
The API itself works fine — only the visual docs page needs the external assets:
```bash
# Health check
curl http://localhost:8000/health

# List modules
curl http://localhost:8000/api/v1/modules

# The full API spec is always available here
curl http://localhost:8000/openapi.json
```

Import `http://localhost:8000/openapi.json` into Postman to get the same interactive
experience as the docs page, without needing internet access.

---

### "Port 8000 is already in use"

**What you see:**
```
ERROR: [Errno 98] Address already in use
```

**Fix:**
```bash
# Use a different port
secsuite serve --port 9000

# Or find and kill what's using 8000
# Linux/macOS:
lsof -i :8000
kill -9 <PID>

# Windows PowerShell:
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

---

### "uvicorn not installed" when running `secsuite serve`

**Fix:**
```bash
pip install -e ".[dashboard]"
# or
pip install uvicorn fastapi
```

---

### API returns 401 Unauthorized

**What it means:**  
The server was started with `--api-key` and you're not sending the key in requests.

**Fix — in curl:**
```bash
curl -H "X-API-Key: your-key-here" http://localhost:8000/api/v1/scans
```

**Fix — in the browser docs:**  
Click the "Authorize" button (padlock icon) at the top of the docs page and enter your key.

---

## Scan / Tool Issues

### "nmap not found" / port scanning fails

**Fix:**
```bash
# Ubuntu/Debian
sudo apt install nmap

# Fedora/RHEL
sudo dnf install nmap

# macOS
brew install nmap

# Windows
winget install Insecure.Nmap
```
Then close and reopen your terminal.

---

### Permission denied on port scans

Some nmap scan types need root/administrator privileges.

**Linux fix:**
```bash
sudo secsuite osint ports 192.168.1.1
```

**Windows fix:**  
Run PowerShell as Administrator (right-click → "Run as administrator"), then run your command.

---

### Scan hangs or takes a very long time

Some targets are slow to respond. Add a timeout:
```bash
secsuite osint ports 192.168.1.1 --type quick
```

Or try a specific port range instead of a full scan:
```bash
secsuite osint ports 192.168.1.1 --ports 22,80,443,8080,3306
```

---

### API security scan returns "Failed to parse spec"

**What you see:**
```
Failed to parse spec: ...
```

**Common causes and fixes:**

1. **Wrong URL** — the URL should point to the raw JSON/YAML file, not an HTML page.
   - Wrong: `https://example.com/docs` (this is an HTML page)
   - Right: `https://example.com/openapi.json` (this is the spec file)

2. **App not running** — if you're testing a local app, make sure it's started first.
   ```bash
   # Start your app in one terminal
   python myapp.py
   # Then test in another terminal
   secsuite api scan http://localhost:5000/openapi.json
   ```

3. **Auth required to access the spec** — some apps protect the spec endpoint:
   ```bash
   secsuite api scan http://localhost:5000/openapi.json --token your-bearer-token
   ```

4. **Not sure where the spec is?** Let Security Suite search:
   ```bash
   curl -X POST http://localhost:8000/api/v1/apisec/discover \
     -H "Content-Type: application/json" \
     -d '{"base_url": "http://localhost:5000"}'
   ```

---

## How to Get More Help

**Check what version you're running:**
```bash
secsuite version
python --version
pip show security-suite
```

**Turn on verbose/debug output:**
```bash
secsuite osint dns example.com --verbose
```

**Report a bug:**  
Open an issue at https://github.com/TheSecuredAnalyst/security-suite/issues  
Include:
- Your operating system and version
- The exact command you ran
- The full error message (copy-paste, not a screenshot)
- Output of `python --version` and `secsuite version`
