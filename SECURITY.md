# Security Policy

Security Suite is an offensive/defensive security toolkit. Because it can send
traffic to and execute actions against remote systems, we take both the safety
of the tool itself and the safety of its users seriously.

## Supported versions

The project is pre-1.0 and moves quickly. Security fixes are applied to the
`main` branch and included in the next tagged release. Please test against
`main` before reporting.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| tagged releases | latest only |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/TheSecuredAnalyst/security-suite/security/advisories/new)
(the **Security → Advisories → Report a vulnerability** button on the repo).
This keeps the details confidential until a fix is available.

When reporting, please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal proof of concept is ideal).
- Affected module(s), commit hash, and Python version.
- Any suggested remediation.

We aim to acknowledge reports within **72 hours** and to ship a fix or
mitigation plan within **30 days**, depending on severity and complexity.

## Scope

In scope:

- Bypasses of the guardrails layer (`core/guardrails.py`) — e.g. executing an
  exploit or remediation outside an authorized engagement session or Rules of
  Engagement scope.
- Command injection, path traversal, SSRF, or unsafe deserialization within
  Security Suite itself.
- Leakage of credentials, API keys, or scan results to unintended destinations.
- Weaknesses in the AI-generated-script safety analyzer that allow a banned
  destructive command through.

Out of scope:

- Vulnerabilities in third-party targets you scan with the tool.
- Findings that require an attacker to already control the operator's machine.
- Missing hardening on optional integrations you have explicitly configured
  (e.g. an unauthenticated Splunk HEC you pointed the tool at).

## Responsible use

This tool is intended for authorized security testing only. Using it against
systems you do not own or have explicit written permission to test may be
illegal. The maintainers accept no liability for misuse. See `LICENSE` for the
full terms.
