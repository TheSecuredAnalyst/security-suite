# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
