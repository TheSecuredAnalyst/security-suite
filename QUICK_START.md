# Quick Start Guide - New Features

## 📚 Documentation Files

Read these in order to understand what was added:

1. **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Overview of all new features
2. **[ARCHITECTURE.md](ARCHITECTURE.md)** - Deep dive into system design
3. **[README.md](README.md)** - Original project documentation
4. **[USAGE.md](USAGE.md)** - Command-line usage examples

---

## 🚀 Quick Demos

### Demo 1: REST API

Start the API:
```bash
source venv/bin/activate
python -c "
from api.server import create_app
import uvicorn
uvicorn.run(create_app(), host='0.0.0.0', port=8000)
"
```

In another terminal, test endpoints:
```bash
# Health check
curl http://localhost:8000/health

# List available modules
curl http://localhost:8000/api/v1/modules

# Create a scan (with dry-run)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "modules": ["dns"], "dry_run": true}'

# Get scan details (use scan ID from response)
curl http://localhost:8000/api/v1/scans/{SCAN_ID}
```

### Demo 2: Caching

```bash
python3 -c "
from core.cache import get_cache
from core.models import Target, ScanResult

cache = get_cache()

# Check cache stats
print('Cache Stats:', cache.get_stats())

# View cache location
import os
cache_dir = cache.cache_dir
print(f'Cache Directory: {cache_dir}')
print(f'Cache Files: {list(cache_dir.glob(\"*.json\"))[:5]}')
"
```

### Demo 3: Export Formats

```bash
python3 -c "
from core.models import Target, ScanResult, Finding, Severity
from core.exporters import export_result
from pathlib import Path

# Create sample result
target = Target.from_string('example.com')
result = ScanResult(target=target, module='test')

finding = Finding(
    title='Test Finding',
    description='A sample security finding',
    severity=Severity.HIGH,
    source='demo',
)
result.findings.append(finding)

# Export to different formats
print('JSON:', export_result(result, 'json')[:100] + '...')
print('CSV:', export_result(result, 'csv')[:100] + '...')
print('HTML:', export_result(result, 'html')[:100] + '...')

# Save to files
export_result(result, 'html', Path('/tmp/report.html'))
print('HTML report saved to /tmp/report.html')
"
```

### Demo 4: Error Handling

```bash
python3 -c "
from core.tools import ToolManager
from core.exceptions import ToolNotFoundError

# Check if nmap is available
try:
    ToolManager.check_tool('nmap')
    print('✓ nmap is available')
except ToolNotFoundError as e:
    print(f'✗ {e}')

# Check non-existent tool with fallback
available = ToolManager.check_tool('nonexistent_tool', raise_error=False)
print(f'Nonexistent tool available: {available}')
"
```

---

## 📊 Running Tests

Run all tests with coverage:
```bash
source venv/bin/activate
pytest --cov=core --cov=modules tests/ -v
```

Run specific test file:
```bash
pytest tests/test_cache.py -v
```

View HTML coverage report:
```bash
pytest --cov=core tests/
open htmlcov/index.html
```

---

## 📁 File Structure Overview

### New Directories
```
api/                           # NEW REST API implementation
├── __init__.py
├── server.py                  # FastAPI app factory
├── models.py                  # Pydantic models
└── routers/                   # API endpoint handlers
    ├── __init__.py
    ├── health.py
    ├── scans.py
    ├── results.py
    └── modules.py

core/                          # Core infrastructure (expanded)
├── cache.py                   # NEW Caching system
├── exceptions.py              # NEW Exception classes
├── exporters.py               # NEW Export functionality
├── tools.py                   # NEW Tool management
├── (existing files)
└── ...

tests/                         # Test suite (expanded)
├── test_cache.py              # NEW Cache tests
├── test_exporters.py          # NEW Export tests
├── test_error_handling.py      # NEW Error handling tests
├── (existing files)
└── ...
```

### New Documentation
```
IMPLEMENTATION_SUMMARY.md      # NEW Feature overview
ARCHITECTURE.md                # NEW System design
QUICK_START.md                 # THIS FILE
```

---

## 🔧 Configuration

### Cache Configuration

Set cache TTL via environment:
```bash
export SECSUITE_DEBUG=true
# Cache directory: ~/.secsuite/cache/
# Default TTL: 24 hours
```

### API Configuration

Change API host/port:
```python
uvicorn.run(app, host="127.0.0.1", port=8080)
```

---

## 💡 Usage Examples

### Example 1: Use API Programmatically

```python
import httpx
import asyncio

async def create_and_monitor_scan():
    async with httpx.AsyncClient() as client:
        # Create scan
        response = await client.post(
            "http://localhost:8000/api/v1/scans",
            json={"target": "example.com", "modules": ["dns", "whois"]}
        )
        scan = response.json()
        scan_id = scan["id"]
        
        # Monitor progress
        for _ in range(5):
            response = await client.get(f"http://localhost:8000/api/v1/scans/{scan_id}")
            status = response.json()["status"]
            print(f"Status: {status}")
            await asyncio.sleep(2)

asyncio.run(create_and_monitor_scan())
```

### Example 2: Export Scan Results

```python
from core.exporters import export_result
from core.models import Target, ScanResult
from pathlib import Path

# Assuming you have a scan_result...
result = ScanResult(target=Target.from_string("example.com"), module="osint")

# Export to all formats
for fmt in ["json", "csv", "html", "markdown"]:
    file_path = Path(f"report.{fmt if fmt != 'markdown' else 'md'}")
    export_result(result, fmt, file_path)
    print(f"✓ Exported to {file_path}")
```

### Example 3: Check External Tools

```python
from core.tools import ToolManager
from core.exceptions import ToolNotFoundError

required_tools = ["nmap", "whois", "dig"]

for tool in required_tools:
    try:
        if ToolManager.check_tool(tool):
            print(f"✓ {tool} is available")
    except ToolNotFoundError:
        print(f"✗ {tool} is NOT available - install it to use this module")
```

---

## 🐛 Troubleshooting

### Issue: API won't start
```
Check if port 8000 is in use:
lsof -i :8000
Kill process: kill -9 <PID>
Or use different port: uvicorn app --port 8001
```

### Issue: Cache not working
```
Check cache directory:
ls ~/.secsuite/cache/

Clear cache:
rm -rf ~/.secsuite/cache/*
```

### Issue: Tests failing
```
Ensure venv is activated:
source venv/bin/activate

Run with verbose output:
pytest -vv tests/test_cache.py

Check Python version:
python --version  # Should be 3.10+
```

---

## 📝 Commit History

```
b3d596d - docs: Add implementation summary
a601320 - fix: Fix test fixtures and exporters
adf9826 - feat: Implement major recommendations
aac7be7 - Initial commit: SecSuite v0.1.0
```

---

## 🎯 Next Steps

1. **Try the REST API** - Start the server and explore endpoints
2. **Review Architecture** - Read ARCHITECTURE.md for system design
3. **Run Tests** - Verify everything works with pytest
4. **Extend Features** - Add authentication, database integration
5. **Deploy** - Follow production checklist in ARCHITECTURE.md

---

## 📞 Feature Reference

| Feature | File | Status |
|---------|------|--------|
| REST API | `api/` | ✅ Complete |
| Error Handling | `core/exceptions.py`, `core/tools.py` | ✅ Complete |
| Caching | `core/cache.py` | ✅ Complete |
| Export Formats | `core/exporters.py` | ✅ Complete |
| Tests | `tests/` | ✅ Complete |
| Architecture Docs | `ARCHITECTURE.md` | ✅ Complete |
| Dry-Run Mode | - | ⏳ Not Started |
| Database Integration | - | ⏳ Not Started |
| API Authentication | - | ⏳ Not Started |

---

**Last Updated**: February 9, 2026  
**Version**: 0.2.0 (with recommended enhancements)
