import subprocess
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from services.host_discovery import discover_hosts
from services.scanner_adapters.nmap_adapter import (
    NmapHostDiscoveryScanner,
    ScannerExecutionError,
    ScannerParseError,
    ScannerTimeoutError,
    ScannerUnavailableError,
)


NMAP_XML = """
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.1" addrtype="ipv4" />
    <address addr="AA-BB-CC-DD-EE-FF" addrtype="mac" vendor="Example Router" />
    <hostnames><hostname name="router" type="PTR" /></hostnames>
  </host>
  <host>
    <status state="up" />
    <address addr="192.168.1.20" addrtype="ipv4" />
    <address addr="11:22:33:44:55:66" addrtype="mac" vendor="Example Workstation" />
    <hostnames><hostname name="workstation" type="PTR" /></hostnames>
  </host>
  <host>
    <status state="up" />
    <address addr="192.168.1.30" addrtype="ipv4" />
  </host>
  <host>
    <status state="down" />
    <address addr="192.168.1.40" addrtype="ipv4" />
  </host>
</nmaprun>
"""


def completed_process(stdout=NMAP_XML, returncode=0, stderr=""):
    return SimpleNamespace(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
    )


def test_builds_conservative_nmap_command():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(),
    ) as run:
        scanner.discover_hosts("192.168.1.9/24")

    command = run.call_args.args[0]
    options = run.call_args.kwargs

    assert command == ["nmap", "-sn", "192.168.1.0/24", "-oX", "-"]
    assert options["shell"] is False
    assert options["timeout"] == 30
    assert options["capture_output"] is True
    assert options["text"] is True
    assert options["check"] is False
    assert "-sn" in command
    assert "-oX" in command
    assert "-sV" not in command
    assert "-A" not in command
    assert "-O" not in command
    assert "--script" not in command
    assert "22" not in command


def test_parses_up_hosts_and_ignores_down_hosts():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(),
    ):
        result = scanner.discover_hosts("192.168.1.0/24")

    assert result.target_network == "192.168.1.0/24"
    assert result.scanner == "nmap"
    assert result.started_at <= result.completed_at
    assert [host.ip_address for host in result.hosts] == [
        "192.168.1.1",
        "192.168.1.20",
        "192.168.1.30",
    ]
    assert result.hosts[0].mac_address == "aa:bb:cc:dd:ee:ff"
    assert result.hosts[0].hostname == "router"
    assert result.hosts[0].vendor == "Example Router"
    assert result.hosts[2].mac_address is None
    assert result.hosts[2].hostname is None
    assert result.hosts[2].vendor is None


def test_empty_scan_result_is_valid():
    xml = "<?xml version='1.0'?><nmaprun />"
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout=xml),
    ):
        result = scanner.discover_hosts("192.168.1.0/24")

    assert result.hosts == ()


def test_malformed_xml_raises_controlled_parse_error():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout="<nmaprun>"),
    ):
        with pytest.raises(ScannerParseError):
            scanner.discover_hosts("192.168.1.0/24")


def test_missing_executable_raises_controlled_unavailable_error():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        with pytest.raises(ScannerUnavailableError):
            scanner.discover_hosts("192.168.1.0/24")


def test_timeout_raises_controlled_timeout_error():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        side_effect=subprocess.TimeoutExpired("nmap", 30),
    ):
        with pytest.raises(ScannerTimeoutError):
            scanner.discover_hosts("192.168.1.0/24")


def test_nonzero_result_raises_controlled_execution_error():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout="", returncode=1),
    ):
        with pytest.raises(ScannerExecutionError):
            scanner.discover_hosts("192.168.1.0/24")


def test_oversized_output_raises_controlled_execution_error():
    scanner = NmapHostDiscoveryScanner(max_output_bytes=10)

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(stdout="01234567890"),
    ):
        with pytest.raises(ScannerExecutionError):
            scanner.discover_hosts("192.168.1.0/24")


def test_target_is_one_argument_and_unsafe_targets_are_rejected():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(),
    ) as run:
        scanner.discover_hosts("192.168.1.1/24")

    assert run.call_args.args[0][2] == "192.168.1.0/24"

    with pytest.raises(ValueError):
        scanner.discover_hosts("8.8.8.0/24")


def test_adapter_integrates_with_authorized_host_discovery_service():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        return_value=completed_process(),
    ):
        result = discover_hosts(
            {
                "cidr": "192.168.1.9/24",
                "authorized": True,
                "enabled": True,
            },
            scanner,
        )

    assert result.scanner == "nmap"
    assert result.target_network == "192.168.1.0/24"
    assert len(result.hosts) == 3


def test_adapter_does_not_scan_unauthorized_or_disabled_networks():
    scanner = NmapHostDiscoveryScanner()

    with patch(
        "services.scanner_adapters.nmap_adapter.subprocess.run"
    ) as run:
        with pytest.raises(ValueError):
            discover_hosts(
                {
                    "cidr": "192.168.1.0/24",
                    "authorized": False,
                    "enabled": True,
                },
                scanner,
            )

        with pytest.raises(ValueError):
            discover_hosts(
                {
                    "cidr": "192.168.1.0/24",
                    "authorized": True,
                    "enabled": False,
                },
                scanner,
            )

    run.assert_not_called()