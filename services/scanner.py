from typing import Protocol, runtime_checkable

from services.scan_models import ScanResult


@runtime_checkable
class HostDiscoveryScanner(Protocol):
    def discover_hosts(self, network_cidr: str) -> ScanResult:
        """Return normalized host observations for a validated network."""