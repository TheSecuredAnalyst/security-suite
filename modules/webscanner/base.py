"""Base class for web scanner modules."""

from abc import ABC, abstractmethod

from core.logger import get_logger
from core.models import ScanResult, Target


class WebScannerModule(ABC):
    """Abstract base class for web scanner modules."""

    name: str = "base"
    description: str = "Base web scanner module"

    def __init__(self):
        self.logger = get_logger(f"webscanner.{self.name}")

    @abstractmethod
    async def run(self, target: Target) -> ScanResult:
        """Execute the scanner against a target."""
        pass

    def create_result(self, target: Target) -> ScanResult:
        """Create a new ScanResult for this module."""
        return ScanResult(target=target, module=f"webscanner.{self.name}")
