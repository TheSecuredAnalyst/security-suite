"""Wordlist loading utilities with optional SecLists integration.

Architecture
------------
* ``resolve_seclists_path()``  – finds the SecLists root on disk (auto-detect or
  explicit path / env-var).
* ``load_wordlist()``          – loads a list of entries from a SecLists file,
  falls back to a built-in list when SecLists is not available.
* ``CATALOG``                  – central registry that maps a short key to every
  SecLists file each Security Suite module can use.
* ``seclists_status()``        – returns the resolved state of every catalog entry
  (used by the ``secsuite wordlists`` CLI command).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from core.config import get_settings

# ---------------------------------------------------------------------------
# SecLists root discovery
# ---------------------------------------------------------------------------

SECLISTS_CANDIDATE_DIRS: tuple[str, ...] = (
    "SecLists-master",
    "SecLists",
    "seclists",
)


def resolve_seclists_path(seclists_path: str | Path | None = None) -> Path | None:
    """Return the SecLists root directory if it can be found, else ``None``.

    Priority:
    1. Explicit *seclists_path* argument.
    2. ``SECSUITE_SECLISTS_PATH`` env-var / settings value.
    3. Auto-detect: walk up from the project root and look for candidate
       directory names (``SecLists-master``, ``SecLists``, ``seclists``).
    """
    candidates: list[Path] = []

    if seclists_path:
        candidates.append(Path(seclists_path).expanduser())

    settings_path = get_settings().seclists_path
    if settings_path:
        candidates.append(Path(settings_path).expanduser())

    project_root = Path(__file__).resolve().parents[1]
    for ancestor in (project_root, *project_root.parents):
        for directory_name in SECLISTS_CANDIDATE_DIRS:
            candidates.append(ancestor / directory_name)

    seen: set[Path] = set()
    for candidate in candidates:
        resolved_candidate = candidate.resolve(strict=False)
        if resolved_candidate in seen:
            continue
        seen.add(resolved_candidate)
        if resolved_candidate.is_dir():
            return resolved_candidate

    return None


# ---------------------------------------------------------------------------
# Core loading primitives
# ---------------------------------------------------------------------------

def load_wordlist(
    relative_paths: str | Path | Sequence[str | Path],
    fallback: Iterable[str] | None = None,
    seclists_path: str | Path | None = None,
    max_entries: int | None = None,
) -> list[str]:
    """Load a wordlist from SecLists with fallback to built-in entries.

    Args:
        relative_paths: One or more SecLists-relative paths tried in order
                        (first file that exists and is non-empty wins).
        fallback:       Built-in entries returned when no SecLists file found.
        seclists_path:  Override the SecLists root for this call only.
        max_entries:    Cap the returned list length (useful for large files).

    Returns:
        A deduplicated list of non-empty, non-comment lines.
    """
    paths = _normalize_relative_paths(relative_paths)
    resolved_root = resolve_seclists_path(seclists_path)

    if resolved_root:
        for relative_path in paths:
            candidate = resolved_root / relative_path
            if candidate.is_file():
                entries = _read_wordlist_file(candidate)
                if entries:
                    return entries[:max_entries] if max_entries else entries

    fallback_entries = list(fallback or [])
    return (fallback_entries[:max_entries] if max_entries else fallback_entries).copy()


def _normalize_relative_paths(
    relative_paths: str | Path | Sequence[str | Path],
) -> list[Path]:
    if isinstance(relative_paths, (str, Path)):
        return [Path(relative_paths)]
    return [Path(p) for p in relative_paths]


def _read_wordlist_file(path: Path) -> list[str]:
    """Read a wordlist file, stripping comments and blank lines, deduplicating."""
    seen: set[str] = set()
    entries: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        cleaned = line.strip()
        if cleaned and not cleaned.startswith("#") and cleaned not in seen:
            seen.add(cleaned)
            entries.append(cleaned)
    return entries


# ---------------------------------------------------------------------------
# Central catalog
# ---------------------------------------------------------------------------

@dataclass
class WordlistEntry:
    """Metadata for one registered SecLists wordlist integration."""
    key: str
    description: str
    module: str                        # Security Suite module that uses it
    seclists_paths: list[str]          # Tried in order; first hit wins
    fallback_count: int = 0            # len() of the built-in fallback
    # Populated at runtime by seclists_status():
    resolved_path: str | None = field(default=None, compare=False)
    active_count: int | None = field(default=None, compare=False)
    source: str = field(default="fallback", compare=False)  # "seclists" | "fallback"


# Map of key → WordlistEntry.  Modules reference keys declared here.
CATALOG: dict[str, WordlistEntry] = {
    # ---- Web Content Discovery -----------------------------------------------
    "web_directories": WordlistEntry(
        key="web_directories",
        description="Web directory & file bruteforce",
        module="modules.webscanner.dir_bruteforce",
        seclists_paths=[
            "Discovery/Web-Content/common.txt",
            "Discovery/Web-Content/common_directories.txt",
        ],
        fallback_count=50,
    ),
    # ---- DNS / Subdomain Discovery -------------------------------------------
    "dns_subdomains": WordlistEntry(
        key="dns_subdomains",
        description="DNS subdomain enumeration",
        module="modules.osint.subdomain",
        seclists_paths=[
            "Discovery/DNS/subdomains-top1million-5000.txt",
            "Discovery/DNS/subdomains-top1million-20000.txt",
        ],
        fallback_count=55,
    ),
    # ---- XSS Payloads --------------------------------------------------------
    "xss_payloads": WordlistEntry(
        key="xss_payloads",
        description="XSS injection payloads",
        module="modules.webscanner.xss_scanner",
        seclists_paths=[
            "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
            "Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
            "Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
        ],
        fallback_count=10,
    ),
    # ---- SQLi Payloads -------------------------------------------------------
    "sqli_payloads": WordlistEntry(
        key="sqli_payloads",
        description="SQL injection payloads",
        module="modules.webscanner.sqli_scanner",
        seclists_paths=[
            "Fuzzing/Databases/SQLi/quick-SQLi.txt",
            "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        ],
        fallback_count=15,
    ),
    # ---- JWT Secrets ---------------------------------------------------------
    "jwt_secrets": WordlistEntry(
        key="jwt_secrets",
        description="Common / leaked JWT signing secrets",
        module="modules.apisec.auth_tester",
        seclists_paths=[
            "Passwords/scraped-JWT-secrets.txt",
        ],
        fallback_count=8,
    ),
    # ---- Default Credentials -------------------------------------------------
    "default_credentials": WordlistEntry(
        key="default_credentials",
        description="Default username:password pairs",
        module="modules.apisec.auth_tester",
        seclists_paths=[
            "Passwords/Default-Credentials/default-passwords.txt",
        ],
        fallback_count=10,
    ),
    # ---- General Fuzzing Strings ---------------------------------------------
    "fuzz_strings": WordlistEntry(
        key="fuzz_strings",
        description="General-purpose fuzzing strings (naughty strings + injections)",
        module="modules.apisec.fuzzer",
        seclists_paths=[
            "Fuzzing/big-list-of-naughty-strings.txt",
            "Fuzzing/FuzzingStrings-SkullSecurity.org.txt",
        ],
        fallback_count=25,
    ),
    # ---- LFI Payloads --------------------------------------------------------
    "lfi_payloads": WordlistEntry(
        key="lfi_payloads",
        description="Local file inclusion path traversal payloads",
        module="modules.apisec.endpoint_tester",
        seclists_paths=[
            "Fuzzing/LFI/LFI-Jhaddix.txt",
            "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        ],
        fallback_count=4,
    ),
    # ---- Command Injection Payloads ------------------------------------------
    "cmdi_payloads": WordlistEntry(
        key="cmdi_payloads",
        description="Command injection payloads",
        module="modules.apisec.endpoint_tester",
        seclists_paths=[
            "Fuzzing/command-injection-commix.txt",
            "Fuzzing/UnixAttacks.fuzzdb.txt",
        ],
        fallback_count=4,
    ),
    # ---- API Endpoints -------------------------------------------------------
    "api_endpoints": WordlistEntry(
        key="api_endpoints",
        description="Common REST API endpoint paths",
        module="modules.webscanner.dir_bruteforce",
        seclists_paths=[
            "Discovery/Web-Content/common-api-endpoints-mazen160.txt",
            "Discovery/Web-Content/api/objects.txt",
        ],
        fallback_count=5,
    ),
    # ---- Usernames -----------------------------------------------------------
    "usernames": WordlistEntry(
        key="usernames",
        description="Common usernames for brute-force / harvesting",
        module="modules.osint.email_harvester",
        seclists_paths=[
            "Usernames/top-usernames-shortlist.txt",
            "Usernames/cirt-default-usernames.txt",
        ],
        fallback_count=10,
    ),
}


def seclists_status(seclists_path: str | Path | None = None) -> dict:
    """Return resolved status for all catalog entries.

    Returns a dict with:
    - ``root``: resolved SecLists root path (str) or None
    - ``available``: bool
    - ``entries``: list of resolved WordlistEntry dicts
    """
    root = resolve_seclists_path(seclists_path)
    resolved_entries: list[dict] = []

    for entry in CATALOG.values():
        found_path: str | None = None
        count: int | None = None
        source = "fallback"

        if root:
            for rel in entry.seclists_paths:
                candidate = root / rel
                if candidate.is_file():
                    lines = _read_wordlist_file(candidate)
                    if lines:
                        found_path = str(candidate)
                        count = len(lines)
                        source = "seclists"
                        break

        if found_path is None:
            count = entry.fallback_count

        resolved_entries.append({
            "key": entry.key,
            "description": entry.description,
            "module": entry.module,
            "source": source,
            "path": found_path,
            "count": count,
        })

    return {
        "root": str(root) if root else None,
        "available": root is not None,
        "entries": resolved_entries,
    }
