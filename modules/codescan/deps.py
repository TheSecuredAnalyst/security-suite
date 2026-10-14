"""Check locked dependencies against the OSV vulnerability database.

Reads npm (package-lock.json), Composer (composer.lock) and pinned pip
(requirements*.txt) files. Only package names and versions are sent to
api.osv.dev; no source code leaves the machine.

Development-only packages are reported one level lower: they run on the
developer's machine and in the build, not in what users receive.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .common import CodeFinding, downgrade
from .walker import find_named

OSV = "https://api.osv.dev/v1"
BATCH = 1000
LOCKFILES = {"package-lock.json", "composer.lock", "requirements.txt", "requirements-dev.txt",
             "requirements-prod.txt"}


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    dev: bool
    lockfile: str


def parse_package_lock(data: dict[str, Any], rel: str) -> list[Package]:
    out: list[Package] = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # lockfile v2/v3
        for key, meta in pkgs.items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict):
                continue
            if meta.get("link") or not meta.get("version"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            out.append(Package("npm", name, meta["version"], bool(meta.get("dev")), rel))
        return out

    def walk(deps: dict[str, Any]) -> None:  # lockfile v1
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append(Package("npm", name, meta["version"], bool(meta.get("dev")), rel))
                walk(meta.get("dependencies", {}))

    walk(data.get("dependencies", {}))
    return out


def parse_composer_lock(data: dict[str, Any], rel: str) -> list[Package]:
    out = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(section) or []:
            if p.get("name") and p.get("version"):
                out.append(Package("Packagist", p["name"], p["version"].lstrip("v"), dev, rel))
    return out


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!\-]+)")


def parse_requirements(text: str, rel: str) -> list[Package]:
    dev = "dev" in Path(rel).name
    return [Package("PyPI", m.group(1), m.group(2), dev, rel)
            for line in text.splitlines() if (m := _REQ.match(line))]


def collect(root: Path) -> list[Package]:
    root = root.resolve()
    base = root if root.is_dir() else root.parent
    pkgs: list[Package] = []
    for path in find_named(root, LOCKFILES):
        rel = str(path.relative_to(base))
        try:
            text = path.read_text(encoding="utf-8")
            if path.name == "package-lock.json":
                pkgs += parse_package_lock(json.loads(text), rel)
            elif path.name == "composer.lock":
                pkgs += parse_composer_lock(json.loads(text), rel)
            else:
                pkgs += parse_requirements(text, rel)
        except (OSError, ValueError):
            continue
    return pkgs


def osv_severity(vuln: dict[str, Any]) -> str:
    sev = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
    return {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium",
            "low": "low"}.get(sev, "medium")


def fixed_versions(vuln: dict[str, Any], ecosystem: str, name: str) -> list[str]:
    fixed = []
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("ecosystem") != ecosystem or p.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(fixed))


def query_osv(pkgs: list[Package], client: httpx.Client) -> dict[tuple[str, str, str], list[str]]:
    """(ecosystem, name, version) -> vulnerability ids."""
    unique = sorted({(p.ecosystem, p.name, p.version) for p in pkgs})
    hits: dict[tuple[str, str, str], list[str]] = {}
    for i in range(0, len(unique), BATCH):
        chunk = unique[i:i + BATCH]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        r = client.post(f"{OSV}/querybatch", json=body)
        r.raise_for_status()
        for key, res in zip(chunk, r.json().get("results", []), strict=False):
            ids = [v["id"] for v in res.get("vulns") or []]
            if ids:
                hits[key] = ids
    return hits


def scan(root: Path, client: httpx.Client | None = None) -> tuple[list[CodeFinding], dict[str, Any]]:
    pkgs = collect(root)
    stats: dict[str, Any] = {"packages": len(pkgs),
                             "lockfiles": len({p.lockfile for p in pkgs}),
                             "unique": len({(p.ecosystem, p.name, p.version) for p in pkgs})}
    if not pkgs:
        return [], stats
    own = client is None
    client = client or httpx.Client(timeout=60, transport=httpx.HTTPTransport(retries=3))
    try:
        hits = query_osv(pkgs, client)
        details: dict[str, dict[str, Any]] = {}
        for vid in sorted({v for ids in hits.values() for v in ids}):
            r = client.get(f"{OSV}/vulns/{vid}")
            if r.status_code == 200:
                details[vid] = r.json()
    finally:
        if own:
            client.close()

    findings: list[CodeFinding] = []
    for p in pkgs:
        for vid in hits.get((p.ecosystem, p.name, p.version), []):
            v = details.get(vid, {"id": vid})
            aliases = [a for a in v.get("aliases") or [] if a.startswith("CVE-")]
            fixed = fixed_versions(v, p.ecosystem, p.name)
            sev = osv_severity(v)
            summary = v.get("summary") or (v.get("details") or "")[:160] or vid
            findings.append(CodeFinding(
                check="deps", rule_id=vid, title=f"{p.name}@{p.version}: {summary}",
                severity=downgrade(sev) if p.dev else sev, file=p.lockfile,
                message=(f"{p.ecosystem} package {p.name} {p.version} is affected by {vid}"
                         + (f" ({', '.join(aliases)})" if aliases else "") + ". "
                         + (f"Fixed in {', '.join(fixed)}. " if fixed else "No fixed version listed. ")
                         + ("Development-only dependency: not shipped to users." if p.dev else "")),
                confidence="high",
                references=[f"https://osv.dev/vulnerability/{vid}"],
                data={"package": p.name, "version": p.version, "ecosystem": p.ecosystem,
                      "dev": p.dev, "fixed": fixed, "cve": aliases[0] if aliases else None,
                      "osv_severity": sev},
            ))
    stats["vulnerable_packages"] = len({(f.data["package"], f.data["version"]) for f in findings})
    return findings, stats
