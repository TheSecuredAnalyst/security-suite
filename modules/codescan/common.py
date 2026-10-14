"""The record every code check produces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def downgrade(severity: str, steps: int = 1) -> str:
    i = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES) - 1
    return SEVERITIES[min(i + steps, len(SEVERITIES) - 1)]


@dataclass
class CodeFinding:
    check: str                 # secrets | deps | sast
    rule_id: str
    title: str
    severity: str
    file: str                  # relative to the scan root
    line: int = 0
    message: str = ""
    snippet: str = ""          # never contains a full secret
    cwe: str | None = None
    confidence: str = "medium"  # high | medium | low
    references: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file
