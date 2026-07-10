"""Base SIEM exporter interface."""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum

from core.logger import get_logger
from core.models import Finding, ScanResult


class EventType(str, Enum):
    """SIEM event types."""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    FINDING_DETECTED = "finding_detected"
    ALERT = "alert"
    ERROR = "error"


@dataclass
class SIEMEvent:
    """Standardized SIEM event."""
    event_type: EventType
    timestamp: datetime
    source: str = "security-suite"
    severity: str = "info"
    message: str = ""
    target: str = ""
    module: str = ""
    finding_title: str | None = None
    finding_description: str | None = None
    risk_score: float | None = None
    raw_data: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        return data

    def to_cef(self) -> str:
        """Convert to CEF (Common Event Format)."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        severity_map = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }
        cef_severity = severity_map.get(self.severity.lower(), 1)

        extension = f"msg={self.message} src={self.target} cs1={self.module}"
        if self.finding_title:
            extension += f" cs2={self.finding_title}"

        return (
            f"CEF:0|SecuritySuite|SecSuite|1.0|{self.event_type.value}|"
            f"{self.message[:50]}|{cef_severity}|{extension}"
        )

    def to_leef(self) -> str:
        """Convert to LEEF (Log Event Extended Format)."""
        # LEEF:Version|Vendor|Product|Version|EventID|
        return (
            f"LEEF:1.0|SecuritySuite|SecSuite|1.0|{self.event_type.value}|"
            f"msg={self.message}\tsrc={self.target}\tmodule={self.module}\t"
            f"severity={self.severity}"
        )

    @classmethod
    def from_finding(cls, finding: Finding, target: str = "") -> "SIEMEvent":
        """Create event from a Finding."""
        return cls(
            event_type=EventType.FINDING_DETECTED,
            timestamp=datetime.now(),
            severity=finding.severity.value,
            message=finding.title,
            target=target,
            module=finding.source,
            finding_title=finding.title,
            finding_description=finding.description,
            raw_data=finding.data,
            tags=finding.references[:5] if finding.references else [],
        )

    @classmethod
    def from_scan_result(cls, result: ScanResult) -> list["SIEMEvent"]:
        """Create events from a ScanResult."""
        events = []

        # Scan completed event
        events.append(cls(
            event_type=EventType.SCAN_COMPLETED,
            timestamp=datetime.now(),
            message=f"Scan completed: {result.module}",
            target=result.target.value,
            module=result.module,
            raw_data={
                "success": result.success,
                "findings_count": len(result.findings),
                "duration": result.duration_seconds,
            },
        ))

        # Individual finding events
        for finding in result.findings:
            events.append(cls.from_finding(finding, result.target.value))

        return events


class SIEMExporter(ABC):
    """Abstract base class for SIEM exporters."""

    def __init__(self):
        self.logger = get_logger(f"siem.{self.__class__.__name__.lower()}")

    @abstractmethod
    async def export(self, event: SIEMEvent) -> bool:
        """Export a single event.

        Args:
            event: Event to export

        Returns:
            True if successful
        """
        pass

    async def export_batch(self, events: list[SIEMEvent]) -> tuple[int, int]:
        """Export multiple events.

        Args:
            events: Events to export

        Returns:
            Tuple of (successful, failed) counts
        """
        success = 0
        failed = 0

        for event in events:
            try:
                if await self.export(event):
                    success += 1
                else:
                    failed += 1
            except Exception as e:
                self.logger.error(f"Export failed: {e}")
                failed += 1

        return success, failed

    async def export_scan_result(self, result: ScanResult) -> tuple[int, int]:
        """Export a scan result as events.

        Args:
            result: Scan result to export

        Returns:
            Tuple of (successful, failed) counts
        """
        events = SIEMEvent.from_scan_result(result)
        return await self.export_batch(events)

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connection to SIEM.

        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    def get_config_info(self) -> dict:
        """Get exporter configuration info (without secrets)."""
        pass
