from typing import Protocol, runtime_checkable

from services.scan_models import ScanResult
from services.service_models import ServiceDiscoveryResult


@runtime_checkable
class HostDiscoveryScanner(Protocol):
    def discover_hosts(self, network_cidr: str) -> ScanResult:
        """Return normalized host observations for a validated network."""


@runtime_checkable
class ServiceDiscoveryScanner(Protocol):
    def discover_services(self, ip_address: str) -> ServiceDiscoveryResult:
        """Return normalized port and service observations for a device."""