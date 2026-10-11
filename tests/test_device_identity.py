from datetime import datetime

import pytest

from services.device_inventory import (
    DeviceInventoryError,
    resolve_device_identity,
)
from services.scan_models import HostDiscoveryResult


OBSERVED_AT = datetime(2026, 10, 11, 12, 0, 0)


def host(ip, mac=None, hostname=None):
    return HostDiscoveryResult(
        ip_address=ip,
        mac_address=mac,
        hostname=hostname,
        discovered_at=OBSERVED_AT,
        source="mock",
    )


def test_mac_identity_is_network_scoped_and_high_confidence():
    identity = resolve_device_identity(
        3,
        host("192.168.1.20", "aa:bb:cc:dd:ee:ff"),
    )

    assert identity.stable_key == "network:3:mac:aa:bb:cc:dd:ee:ff"
    assert identity.confidence == "HIGH"


def test_provisional_hostname_identity_is_medium_confidence():
    identity = resolve_device_identity(
        3,
        host("192.168.1.20", hostname="Workstation"),
    )

    assert identity.stable_key == "network:3:ip:192.168.1.20:hostname:workstation"
    assert identity.confidence == "MEDIUM"


def test_provisional_ip_identity_is_low_confidence():
    identity = resolve_device_identity(3, host("192.168.1.20"))

    assert identity.stable_key == "network:3:ip:192.168.1.20"
    assert identity.confidence == "LOW"


def test_network_scope_prevents_cross_network_merges():
    first = resolve_device_identity(
        1,
        host("192.168.1.20", "aa:bb:cc:dd:ee:ff"),
    )
    second = resolve_device_identity(
        2,
        host("192.168.1.20", "aa:bb:cc:dd:ee:ff"),
    )

    assert first.stable_key != second.stable_key


def test_invalid_network_id_is_rejected():
    with pytest.raises(DeviceInventoryError):
        resolve_device_identity("1", host("192.168.1.20"))