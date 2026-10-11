from datetime import datetime

import pytest

from services.host_discovery import HostDiscoveryError, discover_hosts
from services.scan_models import HostDiscoveryResult, ScanResult
from services.target_policy import TargetPolicyError


DISCOVERED_AT = datetime(2026, 10, 11, 12, 0, 0)


class FakeScanner:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result
        self.error = error

    def discover_hosts(self, network_cidr: str) -> ScanResult:
        self.calls.append(network_cidr)

        if self.error is not None:
            raise self.error

        return self.result


def make_result(network_cidr="192.168.1.0/24", hosts=()):
    return ScanResult(
        target_network=network_cidr,
        scanner="fake",
        started_at=DISCOVERED_AT,
        completed_at=DISCOVERED_AT,
        hosts=hosts,
    )


def authorized_network(cidr="192.168.1.0/24"):
    return {
        "cidr": cidr,
        "authorized": True,
        "enabled": True,
    }


def test_authorized_enabled_network_is_discovered_with_normalized_cidr():
    scanner = FakeScanner(make_result())

    result = discover_hosts(
        authorized_network("192.168.1.9/24"),
        scanner,
    )

    assert scanner.calls == ["192.168.1.0/24"]
    assert result.target_network == "192.168.1.0/24"


@pytest.mark.parametrize(
    "network",
    [
        {"cidr": "192.168.1.0/24", "authorized": False, "enabled": True},
        {"cidr": "192.168.1.0/24", "authorized": True, "enabled": False},
    ],
)
def test_unauthorized_or_disabled_network_is_rejected(network):
    scanner = FakeScanner(make_result())

    with pytest.raises(HostDiscoveryError):
        discover_hosts(network, scanner)

    assert scanner.calls == []


def test_unsafe_network_is_rejected_before_scanner_call():
    scanner = FakeScanner(make_result())

    with pytest.raises(TargetPolicyError):
        discover_hosts(
            {
                "cidr": "8.8.8.0/24",
                "authorized": True,
                "enabled": True,
            },
            scanner,
        )

    assert scanner.calls == []


def test_hosts_remain_normalized_and_missing_evidence_is_allowed():
    host = HostDiscoveryResult(
        ip_address="192.168.1.30",
        discovered_at=DISCOVERED_AT,
        source="fake",
    )
    scanner = FakeScanner(make_result(hosts=(host,)))

    result = discover_hosts(authorized_network(), scanner)

    assert result.hosts == (host,)
    assert result.hosts[0].mac_address is None
    assert result.hosts[0].hostname is None


def test_empty_discovery_result_is_returned():
    scanner = FakeScanner(make_result(hosts=()))

    result = discover_hosts(authorized_network(), scanner)

    assert result.hosts == ()


def test_scanner_failure_is_surfaced_without_persistence():
    scanner = FakeScanner(error=RuntimeError("mock scanner failure"))

    with pytest.raises(RuntimeError, match="mock scanner failure"):
        discover_hosts(authorized_network(), scanner)

    assert scanner.calls == ["192.168.1.0/24"]


def test_scanner_result_for_wrong_target_is_rejected():
    scanner = FakeScanner(make_result("192.168.2.0/24"))

    with pytest.raises(HostDiscoveryError):
        discover_hosts(authorized_network(), scanner)