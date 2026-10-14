"""Walk a source tree, yielding the files worth scanning.

Dependencies, build output and minified bundles are skipped: they are either
covered by the dependency check or are generated from source that is scanned.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "out", "coverage", ".next", ".nuxt",
    "vendor", "venv", ".venv", "__pycache__", ".cache", ".turbo", ".svelte-kit",
    "bower_components", "tmp", ".idea", ".vscode", "htmlcov", ".pytest_cache", ".mypy_cache",
    ".ruff_cache",
}

CODE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm",
            ".php", ".py"}
TEXT_EXT = CODE_EXT | {".json", ".env", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
                       ".sh", ".txt", ".md", ".xml", ".properties"}

MAX_BYTES = 1_000_000
GENERATED_PARTS = re.compile(r"(^|/)storage/framework/|(^|/)bootstrap/cache/|(^|/)public/build/")
_TEST_PART = re.compile(
    r"(^|/)(tests?|__tests__|e2e|spec|fixtures?|mocks?|benchmarks?|dev|tools|scripts|examples?)(/|$)")
_TEST_NAME = re.compile(r"\.(test|spec)\.[a-z]+$|^test_.*\.py$|_test\.py$|(^|[-_.])mock[-_.]")


def is_test_path(rel: str) -> bool:
    """Tests, dev servers, mocks and build tooling are not shipped to users, so
    their findings matter less and are hidden by default."""
    rel = rel.replace(os.sep, "/")
    return bool(_TEST_PART.search(rel) or _TEST_NAME.search(rel.rsplit("/", 1)[-1]))


def looks_generated(text: str) -> bool:
    """Minified or bundled output: few, very long lines."""
    if not text:
        return False
    lines = text.count("\n") + 1
    return len(text) / lines > 300


def iter_files(root: Path, exts: set[str] = TEXT_EXT,
               skip_tests: bool = False) -> Iterator[tuple[Path, str]]:
    """Yield (path, text) for scannable files under ``root``."""
    root = root.resolve()
    base = root if root.is_dir() else root.parent
    if root.is_file():
        candidates: Iterator[Path] = iter([root])
    else:
        candidates = _walk(root)
    for path in candidates:
        name = path.name
        if path.suffix.lower() not in exts and not name.startswith(".env"):
            continue
        rel = str(path.relative_to(base)).replace(os.sep, "/")
        if GENERATED_PARTS.search(rel):
            continue  # framework caches and compiled views: generated from scanned source
        if skip_tests and is_test_path(rel):
            continue
        if name.endswith((".min.js", ".min.css", ".map")) or name in {"package-lock.json",
                                                                    "composer.lock", "yarn.lock"}:
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "\x00" in text[:2048]:
            continue
        yield path, text


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            yield Path(dirpath) / f


def find_named(root: Path, names: set[str]) -> Iterator[Path]:
    """Find manifest/lock files by exact name, skipping dependency folders."""
    root = root.resolve()
    if root.is_file():
        if root.name in names:
            yield root
        return
    for p in _walk(root):
        if p.name in names:
            yield p
