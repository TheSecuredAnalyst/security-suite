"""Community-extensible, provenance-aware correlation.

Correlation rules live in YAML (see ``rules/correlation/``), not in Python, so
that detections can be contributed and reviewed the way Nuclei templates are.
The engine evaluates them over a run's findings and its entity graph.
"""

from .engine import CorrelationEngine
from .graph_builder import build_graph
from .rules import (
    Correlation,
    CorrelationRule,
    FindingPredicate,
    MatchSpec,
    bundled_rules_dir,
    load_rule_file,
    load_rules,
)

__all__ = [
    "CorrelationEngine",
    "Correlation",
    "CorrelationRule",
    "FindingPredicate",
    "MatchSpec",
    "build_graph",
    "bundled_rules_dir",
    "load_rule_file",
    "load_rules",
]
