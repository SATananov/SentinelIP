from datetime import datetime

import pytest

from services.scan_models import (
    HostDiscoveryResult,
    ScanModelError,
    ScanResult,
    normalize_mac,
)


DISCOVERED_AT = datetime(2026, 10, 11, 12, 0, 0)


def test_host_model_normalizes_valid_ipv4_and_optional_text():
    host = HostDiscoveryResult(
        ip_address="192.168.1.20",
        hostname=" workstation ",
        vendor=" Example Vendor ",
        discovered_at=DISCOVERED_AT,
        source="mock",
    )

    assert host.ip_address == "192.168.1.20"
    assert host.hostname == "workstation"
    assert host.vendor == "Example Vendor"
    assert host.discovered_at == DISCOVERED_AT
    assert host.source == "mock"


def test_host_model_rejects_invalid_ipv4():
    with pytest.raises(ScanModelError):
        HostDiscoveryResult(
            ip_address="192.168.001.010",
            discovered_at=DISCOVERED_AT,
            source="mock",
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("  AA:BB:CC:DD:EE:FF  ", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_mac_normalization(value, expected):
    assert normalize_mac(value) == expected


def test_missing_mac_hostname_and_vendor_are_allowed():
    host = HostDiscoveryResult(
        ip_address="192.168.1.30",
        discovered_at=DISCOVERED_AT,
        source="mock",
    )

    assert host.mac_address is None
    assert host.hostname is None
    assert host.vendor is None


def test_invalid_mac_is_rejected():
    for mac_address in ("not-a-mac", 123):
        with pytest.raises(ScanModelError):
            HostDiscoveryResult(
                ip_address="192.168.1.20",
                mac_address=mac_address,
                discovered_at=DISCOVERED_AT,
                source="mock",
            )


def test_host_model_requires_up_status_and_timestamp():
    with pytest.raises(ScanModelError):
        HostDiscoveryResult(
            ip_address="192.168.1.20",
            status="down",
            discovered_at=DISCOVERED_AT,
            source="mock",
        )

    with pytest.raises(ScanModelError):
        HostDiscoveryResult(
            ip_address="192.168.1.20",
            source="mock",
        )


def test_scan_result_retains_hosts_and_metadata():
    host = HostDiscoveryResult(
        ip_address="192.168.1.1",
        hostname="router",
        discovered_at=DISCOVERED_AT,
        source="mock",
    )
    result = ScanResult(
        target_network="192.168.1.0/24",
        scanner="mock",
        started_at=DISCOVERED_AT,
        completed_at=DISCOVERED_AT,
        hosts=[host],
        warnings=["example warning"],
    )

    assert result.target_network == "192.168.1.0/24"
    assert result.scanner == "mock"
    assert result.hosts == (host,)
    assert result.warnings == ("example warning",)