from datetime import datetime

from services.scan_models import HostDiscoveryResult, ScanResult
from services.scanner import HostDiscoveryScanner


class FakeScanner:
    def discover_hosts(self, network_cidr: str) -> ScanResult:
        discovered_at = datetime(2026, 10, 11, 12, 0, 0)
        return ScanResult(
            target_network=network_cidr,
            scanner="fake",
            started_at=discovered_at,
            completed_at=discovered_at,
            hosts=(
                HostDiscoveryResult(
                    ip_address="192.168.1.1",
                    hostname="router",
                    discovered_at=discovered_at,
                    source="fake",
                ),
            ),
        )


def test_fake_scanner_satisfies_host_discovery_contract():
    scanner = FakeScanner()

    assert isinstance(scanner, HostDiscoveryScanner)
    result = scanner.discover_hosts("192.168.1.0/24")

    assert result.scanner == "fake"
    assert result.hosts[0].ip_address == "192.168.1.1"