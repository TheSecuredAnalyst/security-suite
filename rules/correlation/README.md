# Correlation rules

A correlation rule turns **co-occurring findings into a single, higher-signal
result** — the difference between "we found an open service" + "we found a
critical CVE" and "there is a critical CVE on an internet-exposed host, here is
the path to it."

Rules live here as YAML so they can be contributed and reviewed the way Nuclei
templates are — no Python required. One rule per file, named after its `id`.

## Anatomy

```yaml
id: critical-vuln-on-exposed-host        # unique, kebab-case; also the filename
name: Critical vulnerability on an internet-exposed host
description: >-
  Human-readable explanation of what the pattern means and why it matters.
severity: critical                        # critical | high | medium | low | info
mitre: [TA0001]                           # optional MITRE ATT&CK tactic/technique ids
references:                               # optional
  - https://example.com/writeup
match:
  same_host: true                         # see "Scope" below (default: false)
  anchor: ip_address                      # entity type findings are grouped under
  anchor_in_scope: true                   # only consider in-scope anchors (default: true)
  all_of:                                 # EVERY predicate must be satisfied
    - entity_type: service
    - entity_type: vulnerability
      min_severity: high
```

## Predicates (`all_of`)

Each predicate is a set of conditions; **all set fields must hold** for a finding
to satisfy it. A rule fires only when **every** predicate is satisfied.

| Field           | Meaning                                                            |
|-----------------|-------------------------------------------------------------------|
| `sources`       | List of `fnmatch` globs against `finding.source`; matches if ANY does (e.g. `["webscanner.*", "osint.port_scan"]`). |
| `title_matches` | Case-insensitive regex searched against the finding title.        |
| `min_severity`  | Finding severity must be at least this (`info`<`low`<`medium`<`high`<`critical`). |
| `entity_type`   | The entity the finding is *about* (via provenance) must be this type. |

## Scope: flat vs. host-scoped

- **flat** (`same_host: false`, the default) — predicates may be satisfied by
  *any* findings in the run. Good for "these kinds of findings appeared together
  somewhere against the target."
- **host-scoped** (`same_host: true`) — predicates must be satisfied by findings
  that trace back to the **same anchor entity** in the entity graph. The result
  carries that anchor and the full provenance chain
  (`10.0.0.5 → 445/tcp → CVE-2017-0144`). The `secsuite correlate` path builds
  this graph from the scan results automatically; host-scoped rules stay dormant
  only where no graph is supplied.

## Contributing a rule

1. Add `your-rule-id.yaml` here.
2. Validate it: `secsuite rules validate rules/correlation`
3. See it listed: `secsuite rules list`
4. Add a test in `tests/test_correlation.py` if it encodes non-obvious logic.

Open a PR — new detections are the most valuable contribution to this project.
