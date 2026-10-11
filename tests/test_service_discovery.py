from datetime import datetime

import pytest

from services.scan_models import ScanModelError
from services.scanner import ServiceDiscoveryScanner
from services.service_discovery import ServiceDiscoveryError, discover_services
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
)


OBSERVED_AT = datetime(2026, 10, 11, 12, 0, 0)


def make_result(target_ip="192.168.1.20"):
    return ServiceDiscoveryResult(
        target_ip=target_ip,
        scanner="mocked-scanner",
        started_at=OBSERVED_AT,
        completed_at=OBSERVED_AT,
        ports=(
            PortObservation(
                ip_address=target_ip,
                port=22,
                transport="tcp",
                state="open",
                observed_at=OBSERVED_AT,
                source="mocked-scanner",
            ),
        ),
    )


class FakeServiceScanner:
    def __init__(self, result=None, error=None):
        self.result = result or make_result()
        self.error = error
        self.calls = []

    def discover_services(self, ip_address):
        self.calls.append(ip_address)
        if self.error is not None:
            raise self.error
        return self.result


def network():
    return {
        "id": 1,
        "cidr": "192.168.1.0/24",
        "authorized": True,
        "enabled": True,
    }


def device():
    return {
        "id": 10,
        "network_id": 1,
        "last_ip_address": "192.168.1.20",
    }


def test_fake_scanner_satisfies_service_contract():
    scanner = FakeServiceScanner()

    assert isinstance(scanner, ServiceDiscoveryScanner)
    assert scanner.discover_services("192.168.1.20").target_ip == "192.168.1.20"


def test_authorized_device_target_is_discovered():
    scanner = FakeServiceScanner()

    result = discover_services(network(), device(), scanner)

    assert scanner.calls == ["192.168.1.20"]
    assert result.target_ip == "192.168.1.20"


@pytest.mark.parametrize(
    "invalid_network",
    [
        {**network(), "authorized": False},
        {**network(), "enabled": False},
        {**network(), "id": 2},
    ],
)
def test_unsafe_or_unrelated_target_is_rejected(invalid_network):
    scanner = FakeServiceScanner()

    with pytest.raises(ServiceDiscoveryError):
        discover_services(invalid_network, device(), scanner)

    assert scanner.calls == []


def test_public_or_out_of_network_device_is_rejected():
    scanner = FakeServiceScanner()

    with pytest.raises(ServiceDiscoveryError):
        discover_services(
            network(),
            {**device(), "last_ip_address": "8.8.8.8"},
            scanner,
        )

    assert scanner.calls == []


def test_result_target_mismatch_is_rejected():
    scanner = FakeServiceScanner(make_result("192.168.1.21"))

    with pytest.raises(ServiceDiscoveryError):
        discover_services(network(), device(), scanner)


def test_scanner_failure_is_propagated():
    scanner = FakeServiceScanner(error=RuntimeError("scanner failed"))

    with pytest.raises(RuntimeError, match="scanner failed"):
        discover_services(network(), device(), scanner)