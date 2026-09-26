# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Community-extensible correlation engine (`modules/correlation/`).** Turns
  co-occurring findings into single, higher-signal correlations via **declarative
  YAML rules** (`rules/correlation/`) instead of hardcoded Python — so detections
  can be contributed and reviewed the way Nuclei templates are. Rules are either
  *flat* (predicates matched anywhere in a run) or *host-scoped*, which groups
  findings by the anchor entity they trace back to in the entity graph and emits
  the full provenance chain (`10.0.0.5 → 445/tcp → CVE-2017-0144`). Ships with a
  starter pack of five rules (three migrated from the previously hardcoded attack
  patterns, plus two provenance-aware ones) and a contributor guide.
- **Entity-graph builder (`modules/correlation/graph_builder.py`)** that turns a
  run's scan results into a provenance graph (`target → host → service/url/
  vulnerability`), so **`secsuite correlate` now activates host-scoped rules
  live** — findings trace to a shared host anchor and correlations carry the
  chain that led to them. Rules can anchor on multiple host types
  (`[ip_address, hostname, domain]`).
- **CVE enrichment in `correlate` (`modules/correlation/enrich.py`).** Looks up
  CVEs for the services the port scan discovered and nests each under its service
  in the graph (`host → 445/tcp → CVE-2017-0144`), so vulnerability-based rules
  like `critical-vuln-on-exposed-host` fire in the CLI path too. Toggle with
  `--cves/--no-cves`.
- **`secsuite correlate <target>`** to run the rules over a scan, and
  **`secsuite rules list` / `secsuite rules validate`** to inspect and validate
  the rule library (including contributed rules).

## [0.3.0] - 2026-09-26

A security + capability release: five real security fixes hardening the scan
inputs and forwarding paths, a large test-coverage jump, and the first piece of
entity-aware analysis — a provenance graph that records how each finding was
reached.

### Added

- **Entity provenance graph (`core/entities.py`).** Every discovered thing is now
  an `Entity` linked to the entity it came from, collected in an `EntityGraph`
  (`10.0.0.5 → 445/tcp → CVE-2017-0144`), so a report can show *how we got here*
  instead of a flat finding list. Identity is `(type, value)` with automatic
  dedup, cycle-safe `ancestry()`, and sticky in-scope resolution. Prerequisite
  for correlation rules and a module registry. (#12)

### Security

- **Blocked SSRF via OpenAPI spec URLs and spec-supplied servers** in apisec —
  spec locations and the `servers` they declare are now validated before any
  request is made. (#5 path)
- **Required TLS 1.2+ for syslog/SIEM forwarding**, so events are no longer sent
  over downgradeable transport.
- **Validated phishing campaign and tracking ids** before they are used, closing
  an injection path through attacker-influenced identifiers.
- **Scrubbed untrusted values before logging** to prevent log injection, and
  repaired `CacheEntry.__hash__`.
- **Cleared the CodeQL alerts** raised across the new code.

### Testing

- Coverage for the exploit/remediation execution paths, the RedBlue
  orchestrator autonomous loop, CVE enrichment, the SSL/XSS/SQLi web scanners,
  and persistence, scoring, ROE, ATT&CK, password and OpenAPI parsing.

### Maintenance

- Pointed all repository URLs at `TheSecuredAnalyst`. (#8)
- Bumped CI actions: `checkout` 4→7, `setup-python` 5→7, `upload-artifact` 4→7,
  `codeql-action` 3→4.37.3. (Dependabot #2, #3, #7, #10)

## [0.2.0] - 2026-07-10

A hardening release focused on trustworthiness: two real security fixes, a green
CI pipeline, supply-chain scanning, and a large jump in test coverage.

### Security

- **Fixed a guardrail bypass in AI-driven remediation.** The interactive
  `secsuite audit remediate` command executed AI-generated (and operator-entered)
  shell commands via `subprocess` **without** passing them through the guardrails
  safety analyzer — the same destructive-command class (`rm -rf`, `dd`, fork
  bombs, …) that `core/guardrails.py` is designed to block. Every command now
  passes through `guardrails.validate_script()` first; hard violations are
  blocked and soft warnings are surfaced before execution.
- **Fixed the REST API key gate returning `500` instead of `401`.** The
  `X-API-Key` check raised `HTTPException` inside a `BaseHTTPMiddleware`, which
  FastAPI's exception handlers do not process, so an unauthenticated request
  surfaced as an uncaught 500 (leaking a stack trace) rather than a clean 401.
  Access was still denied, but the response is now a proper `401`. The key
  comparison also uses `secrets.compare_digest` to prevent timing attacks.

### Added

- **Supply-chain security tooling:** a `SECURITY.md` disclosure policy,
  Dependabot (pip + GitHub Actions), a CodeQL workflow, and a Security workflow
  running `pip-audit` (dependency CVEs) and `bandit` SAST (gates on
  high-severity/high-confidence findings).
- **54 new tests** covering previously-untested, high-value logic:
  - `core/guardrails.py` 0% → 95.8% (ROE scope, forbidden modules, live-exploit
    opt-in, rate limiting, session expiry, AI-script safety, audit trail).
  - `modules/password/generator.py` 0% → 100%.
  - `modules/compliance/checker.py` 0% → 98.8%.
  - `modules/siem/base.py` 0% → 94.8% (CEF/LEEF formatting, batch export).
  - `api/server.py` 0% → 90.9% (routing and the API-key gate).
- Overall test coverage rose from **10.8% to 19.3%**; the suite grew from 64 to
  132 tests.

### Fixed

- Exception chaining (`raise ... from`) at 13 sites so tracebacks are no longer
  silently swallowed.
- Removed dead code, including phishing-tracker event counts that were computed
  but never used.
- Replaced deprecated `datetime.utcnow()` with timezone-aware
  `datetime.now(timezone.utc)` (removes 50+ deprecation warnings).

### Changed

- **CI lint is green:** resolved 984 `ruff` findings; `ruff check` now passes.
- **`mypy` runs again:** added the missing `modules/__init__.py` package marker
  that previously aborted type-checking.
- Tooling: `ruff` defers line length to the formatter; added `[tool.ruff.format]`
  and `[tool.bandit]` configuration; added `bandit` and `pip-audit` to the `dev`
  extra.

## [0.1.0] - 2026-02

- Initial release: OSINT, web scanning, API security testing, exploit search,
  compliance checks, phishing simulation, SIEM integration, REST API, and
  AI-powered analysis.

[0.2.0]: https://github.com/TheSecuredAnalyst/security-suite/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TheSecuredAnalyst/security-suite/releases/tag/v0.1.0
