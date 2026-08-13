"""Shared data models for Security Suite."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Target(BaseModel):
    """Represents a scan target."""

    value: str = Field(..., description="Target value (domain, IP, URL, email, etc.)")
    target_type: str = Field(..., description="Type of target: domain, ip, url, email, username")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_string(cls, value: str) -> "Target":
        """Auto-detect target type from string."""
        value = value.strip()

        # URL detection
        if value.startswith(("http://", "https://")):
            return cls(value=value, target_type="url")

        # Email detection
        if "@" in value and "." in value.split("@")[-1]:
            return cls(value=value, target_type="email")

        # IP detection (simple check)
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return cls(value=value, target_type="ip")

        # Default to domain
        return cls(value=value, target_type="domain")


class Finding(BaseModel):
    """A single security finding or piece of intelligence."""

    title: str
    description: str
    severity: Severity = Severity.INFO
    source: str = Field(..., description="Module/tool that produced this finding")
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    references: list[str] = Field(default_factory=list)
    entity_id: str | None = Field(
        default=None,
        description="Entity this finding is about; resolves to a provenance chain "
                    "via core.entities.EntityGraph",
    )


class ScanResult(BaseModel):
    """Results from a scan or reconnaissance operation."""

    target: Target
    module: str = Field(..., description="Module that performed the scan")
    success: bool = True
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity = Severity.INFO,
        data: dict[str, Any] | None = None,
        references: list[str] | None = None,
        entity_id: str | None = None,
    ) -> Finding:
        """Add a finding to the result."""
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            source=self.module,
            data=data or {},
            references=references or [],
            entity_id=entity_id,
        )
        self.findings.append(finding)
        return finding

    def complete(self) -> None:
        """Mark the scan as complete."""
        self.completed_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float | None:
        """Get scan duration in seconds."""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
