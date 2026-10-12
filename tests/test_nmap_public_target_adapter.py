from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from services.scanner_adapters.nmap_adapter import (
    NmapHostDiscoveryScanner,
    NmapServiceDiscoveryScanner,
    ScannerParseError,
)


def test_public_host_discovery_uses_one_target_and_bounded_sn_command(monkeypatch):
    completed = SimpleNamespace(
        stdout=(
            '<nmaprun><host><status state="up"/>'
            '<address addr="8.8.8.8" addrtype="ipv4"/></host></nmaprun>'
        ),
        stderr="",
        returncode=0,
    )
    mocked_run = Mock(return_value=completed)
    monkeypatch.setattr("services.scanner_adapters.nmap_adapter.subprocess.run", mocked_run)

    result = NmapHostDiscoveryScanner().discover_public_host("8.8.8.8")

    command = mocked_run.call_args.args[0]
    assert command == ["nmap", "-sn", "-n", "8.8.8.8", "-oX", "-"]
    assert mocked_run.call_args.kwargs["shell"] is False
    assert mocked_run.call_args.kwargs["timeout"] == 30
    assert result.target_network == "8.8.8.8"
    assert [host.ip_address for host in result.hosts] == ["8.8.8.8"]


def test_public_service_scan_reuses_conservative_tcp_profile(monkeypatch):
    completed = SimpleNamespace(
        stdout=(
            '<nmaprun><host><status state="up"/>'
            '<address addr="8.8.8.8" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https" product="Example" version="1.0"/>'
            '</port></ports></host></nmaprun>'
        ),
        stderr="",
        returncode=0,
    )
    mocked_run = Mock(return_value=completed)
    monkeypatch.setattr("services.scanner_adapters.nmap_adapter.subprocess.run", mocked_run)

    result = NmapServiceDiscoveryScanner().discover_public_services("8.8.8.8")

    command = mocked_run.call_args.args[0]
    assert command[-1] == "8.8.8.8"
    assert "-n" in command
    assert "-sT" in command and "-sV" in command
    assert "--version-light" in command
    assert "--max-retries" in command and "2" in command
    assert "--host-timeout" in command and "30s" in command
    assert "-p-" not in command
    assert not {"-sS", "-A", "-O", "--script", "-sU"}.intersection(command)
    assert mocked_run.call_args.kwargs["shell"] is False
    assert result.target_ip == "8.8.8.8"
    assert len(result.ports) == 1 and result.ports[0].port == 443


def test_private_service_entry_point_remains_private_only(monkeypatch):
    mocked_run = Mock()
    monkeypatch.setattr("services.scanner_adapters.nmap_adapter.subprocess.run", mocked_run)

    with pytest.raises(ScannerParseError):
        NmapServiceDiscoveryScanner().discover_services("8.8.8.8")
    mocked_run.assert_not_called()


def test_public_host_result_rejects_out_of_scope_xml_host(monkeypatch):
    completed = SimpleNamespace(
        stdout=(
            '<nmaprun><host><status state="up"/>'
            '<address addr="1.1.1.1" addrtype="ipv4"/></host></nmaprun>'
        ),
        stderr="",
        returncode=0,
    )
    monkeypatch.setattr(
        "services.scanner_adapters.nmap_adapter.subprocess.run",
        Mock(return_value=completed),
    )

    with pytest.raises(ScannerParseError):
        NmapHostDiscoveryScanner().discover_public_host("8.8.8.8")
