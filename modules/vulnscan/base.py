"""Base class for vulnscan modules."""

from abc import ABC, abstractmethod

from core.logger import get_logger
from core.models import ScanResult, Target


class VulnScanModule(ABC):
    """Abstract base for vulnerability scanning modules."""

    name: str = "vulnscan"
    description: str = "Base vulnerability scan module"

    def __init__(self):
        self.logger = get_logger(f"vulnscan.{self.name}")

    @abstractmethod
    async def run(self, target: Target) -> ScanResult:
        """Execute the scan against a target.

        Args:
            target: Target with target_type 'ip', 'network' (CIDR), or 'domain'

        Returns:
            ScanResult containing findings and raw scan data
        """

    def create_result(self, target: Target) -> ScanResult:
        return ScanResult(target=target, module=f"vulnscan.{self.name}")
