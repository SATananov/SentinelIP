from datetime import datetime

import pytest

from services.scan_models import ScanModelError
from services.service_models import (
    PortObservation,
    ServiceDiscoveryResult,
    ServiceObservation,
)


OBSERVED_AT = datetime(2026, 10, 11, 12, 0, 0)


def make_port(port=22):
    return PortObservation(
        ip_address="192.168.1.20",
        port=port,
        transport="TCP",
        state="OPEN",
        observed_at=OBSERVED_AT,
        source="mocked-scanner",
    )


def test_port_observation_normalizes_valid_tcp_fact():
    port = make_port()

    assert port.ip_address == "192.168.1.20"
    assert port.port == 22
    assert port.transport == "tcp"
    assert port.state == "open"


@pytest.mark.parametrize("port", [0, 65536, "22", True])
def test_port_range_and_type_are_validated(port):
    with pytest.raises(ScanModelError):
        make_port(port)


def test_port_rejects_unsupported_transport_and_state():
    with pytest.raises(ScanModelError):
        PortObservation(
            ip_address="192.168.1.20",
            port=22,
            transport="udp",
            state="open",
            observed_at=OBSERVED_AT,
            source="mock",
        )

    with pytest.raises(ScanModelError):
        PortObservation(
            ip_address="192.168.1.20",
            port=22,
            transport="tcp",
            state="closed",
            observed_at=OBSERVED_AT,
            source="mock",
        )


def test_service_observation_preserves_explicit_evidence():
    service = ServiceObservation(
        ip_address="192.168.1.20",
        port=22,
        transport="TCP",
        service_name=" ssh ",
        product=" OpenSSH ",
        version=" 9.6p1 ",
        extra_info=" protocol 2 ",
        confidence="high",
        observed_at=OBSERVED_AT,
        source="mocked-scanner",
    )

    assert service.service_name == "ssh"
    assert service.product == "OpenSSH"
    assert service.version == "9.6p1"
    assert service.extra_info == "protocol 2"
    assert service.confidence == "HIGH"


def test_service_evidence_is_optional_but_confidence_is_required():
    service = ServiceObservation(
        ip_address="192.168.1.20",
        port=443,
        transport="tcp",
        service_name=None,
        product=None,
        version=None,
        extra_info=None,
        confidence="LOW",
        observed_at=OBSERVED_AT,
        source="mocked-scanner",
    )

    assert service.service_name is None
    assert service.product is None
    assert service.version is None

    with pytest.raises(ScanModelError):
        ServiceObservation(
            ip_address="192.168.1.20",
            port=443,
            transport="tcp",
            service_name="https",
            product=None,
            version=None,
            extra_info=None,
            confidence="UNKNOWN",
            observed_at=OBSERVED_AT,
            source="mocked-scanner",
        )


def test_service_discovery_result_keeps_port_and_service_facts_separate():
    result = ServiceDiscoveryResult(
        target_ip="192.168.1.20",
        scanner="mocked-scanner",
        started_at=OBSERVED_AT,
        completed_at=OBSERVED_AT,
        ports=(make_port(),),
        services=(
            ServiceObservation(
                ip_address="192.168.1.20",
                port=22,
                transport="tcp",
                service_name="ssh",
                product="OpenSSH",
                version="9.6p1",
                extra_info=None,
                confidence="HIGH",
                observed_at=OBSERVED_AT,
                source="mocked-scanner",
            ),
        ),
    )

    assert len(result.ports) == 1
    assert len(result.services) == 1


def test_invalid_ipv4_and_missing_source_are_rejected():
    with pytest.raises(ScanModelError):
        PortObservation(
            ip_address="8.8.8.999",
            port=22,
            transport="tcp",
            state="open",
            observed_at=OBSERVED_AT,
            source="mock",
        )

    with pytest.raises(ScanModelError):
        make_port().__class__(
            ip_address="192.168.1.20",
            port=22,
            transport="tcp",
            state="open",
            observed_at=OBSERVED_AT,
            source="",
        )