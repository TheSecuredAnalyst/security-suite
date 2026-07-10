"""Pydantic models for API requests/responses."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SeverityEnum(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingResponse(BaseModel):
    """Response model for a finding."""
    id: str
    title: str
    description: str
    severity: SeverityEnum
    module: str
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ScanRequest(BaseModel):
    """Request model for creating a scan."""
    target: str = Field(..., description="Target to scan (domain, IP, URL, email)")
    modules: list[str] = Field(
        default=["osint"],
        description="Modules to run"
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Module-specific options"
    )
    dry_run: bool = Field(
        default=False,
        description="Perform dry-run without executing"
    )


class ScanResponse(BaseModel):
    """Response model for a scan."""
    id: str
    target: str
    modules: list[str]
    status: str = Field(..., description="pending, running, completed, failed")
    findings_count: int = 0
    findings: list[FindingResponse] = Field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class ScanListResponse(BaseModel):
    """Response model for listing scans."""
    total: int
    page: int
    page_size: int
    scans: list[ScanResponse]


class ModuleInfo(BaseModel):
    """Information about a module."""
    name: str
    category: str
    description: str
    options: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class ModulesResponse(BaseModel):
    """Response model for listing modules."""
    osint: list[ModuleInfo]
    webscanner: list[ModuleInfo]
    apisec: list[ModuleInfo]
    compliance: list[ModuleInfo]
    total: int


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str = "healthy"
    version: str
    timestamp: datetime
