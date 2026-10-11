import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from database.inventory import create_device
from database.networks import create_network
from services.scanner_adapters.nmap_adapter import (
    CONSERVATIVE_TCP_PORTS,
    NmapServiceDiscoveryScanner,
    ScannerExecutionError,
    ScannerParseError,
    ScannerTimeoutError,
    ScannerUnavailableError,
)
from services.service_discovery import discover_services
from services.service_inventory import ServiceInventoryService
from database.services import list_ports, list_services


NMAP_SERVICE_XML = """
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.20" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed" />
        <service name="telnet" />
      </port>
      <port protocol="tcp" portid="25">
        <state state="filtered" />
      </port>
      <port protocol="udp" portid="53">
        <state state="open" />
        <service name="domain" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


def completed_process(stdout=NMAP_SERVICE_XML, returncode=0, stderr=""):
    return SimpleNamespace(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
    )


def test_builds_conservative_single_target_command():
    scanner = NmapServiceDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(),
    ) as run:
        scanner.discover_services("192.168.1.20")

    command = run.call_args.args[0]
    options = run.call_args.kwargs
    port_index = command.index("-p")

    assert command[0] == "nmap"
    assert command[1:5] == ["-sT", "-sV", "--version-light", "--open"]
    assert command[port_index + 1] == ",".join(
        str(port) for port in CONSERVATIVE_TCP_PORTS
    )
    assert command[-3:] == ["-oX", "-", "192.168.1.20"]
    assert command.count("192.168.1.20") == 1
    assert options == {
        "shell": False,
        "timeout": 45,
        "capture_output": True,
        "text": True,
        "check": False,
    }
    assert "-sS" not in command
    assert "-A" not in command
    assert "-O" not in command
    assert "--script" not in command
    assert "-p-" not in command
    assert "-sU" not in command
    assert "sudo" not in command


def test_parses_open_tcp_ports_and_service_evidence():
    scanner = NmapServiceDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(),
    ):
        result = scanner.discover_services("192.168.1.20")

    assert result.target_ip == "192.168.1.20"
    assert result.scanner == "nmap"
    assert [port.port for port in result.ports] == [22, 80, 443]
    assert [service.port for service in result.services] == [22, 80]
    assert result.services[0].service_name == "ssh"
    assert result.services[0].product == "OpenSSH"
    assert result.services[0].version == "9.6p1"
    assert result.services[0].extra_info == "Ubuntu"
    assert result.services[0].confidence == "HIGH"
    assert result.services[1].confidence == "HIGH"


def test_service_name_only_is_low_confidence():
    xml = """
    <nmaprun><host><status state="up" />
    <address addr="192.168.1.20" addrtype="ipv4" />
    <ports><port protocol="tcp" portid="22"><state state="open" />
    <service name="ssh" /></port></ports></host></nmaprun>
    """
    scanner = NmapServiceDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout=xml),
    ):
        result = scanner.discover_services("192.168.1.20")

    assert result.services[0].confidence == "LOW"
    assert result.services[0].product is None
    assert result.services[0].version is None


def test_empty_valid_result_is_supported():
    scanner = NmapServiceDiscoveryScanner()
    xml = "<?xml version='1.0'?><nmaprun />"

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout=xml),
    ):
        result = scanner.discover_services("192.168.1.20")

    assert result.ports == ()
    assert result.services == ()


@pytest.mark.parametrize(
    "target",
    ["8.8.8.8", "2001:db8::1", "192.168.1.0/24", "router", "bad-ip"],
)
def test_rejects_unsafe_or_non_single_ipv4_targets(target):
    scanner = NmapServiceDiscoveryScanner()

    with pytest.raises(ScannerParseError):
        scanner.discover_services(target)


def test_mismatched_xml_target_is_rejected():
    xml = NMAP_SERVICE_XML.replace("192.168.1.20", "192.168.1.21")
    scanner = NmapServiceDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout=xml),
    ):
        with pytest.raises(ScannerParseError):
            scanner.discover_services("192.168.1.20")


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        (FileNotFoundError, ScannerUnavailableError),
        (subprocess.TimeoutExpired("nmap", 45), ScannerTimeoutError),
    ],
)
def test_controlled_process_errors(side_effect, error):
    scanner = NmapServiceDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        side_effect=side_effect,
    ):
        with pytest.raises(error):
            scanner.discover_services("192.168.1.20")


def test_nonzero_and_malformed_outputs_raise_controlled_errors():
    scanner = NmapServiceDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout="", returncode=1),
    ):
        with pytest.raises(ScannerExecutionError):
            scanner.discover_services("192.168.1.20")

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout="<nmaprun>"),
    ):
        with pytest.raises(ScannerParseError):
            scanner.discover_services("192.168.1.20")


def test_authorized_service_discovery_to_inventory_is_mocked(tmp_path):
    db_path = tmp_path / "test.db"
    network = create_network(
        cidr="192.168.1.0/24",
        name="Test LAN",
        description="",
        authorized=True,
        enabled=True,
        db_path=db_path,
    )
    device = create_device(
        stable_key="network:1:mac:aa:bb:cc:dd:ee:ff",
        network_id=network["id"],
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="server",
        vendor="Vendor",
        first_seen="2026-10-11T12:00:00",
        last_seen="2026-10-11T12:00:00",
        last_ip_address="192.168.1.20",
        status="ONLINE",
        identity_confidence="HIGH",
        db_path=db_path,
    )
    scanner = NmapServiceDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(),
    ):
        result = discover_services(network, device, scanner)
        ServiceInventoryService(db_path).process_result(
            network,
            device,
            result,
        )

    assert len(list_ports(device["id"], db_path)) == 3
    assert len(list_services(device["id"], db_path)) == 2


def test_unauthorized_service_discovery_never_invokes_adapter():
    scanner = NmapServiceDiscoveryScanner()
    network = {
        "id": 1,
        "cidr": "192.168.1.0/24",
        "authorized": False,
        "enabled": True,
    }
    device = {
        "id": 10,
        "network_id": 1,
        "last_ip_address": "192.168.1.20",
    }

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run"
    ) as run:
        with pytest.raises(ValueError):
            discover_services(network, device, scanner)

    run.assert_not_called()