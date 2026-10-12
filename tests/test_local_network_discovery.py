import json
import subprocess
from unittest.mock import Mock

import pytest

from services import local_network_discovery as discovery


def address_entry(
    name="wlan0",
    local="192.168.0.158",
    prefixlen=24,
    operstate="UP",
    flags=("BROADCAST", "UP", "LOWER_UP"),
):
    addr_info = []
    if local is not None:
        addr_info.append(
            {
                "family": "inet",
                "local": local,
                "prefixlen": prefixlen,
            }
        )
    return {
        "ifname": name,
        "flags": list(flags),
        "operstate": operstate,
        "addr_info": addr_info,
    }


def route_entry(
    dst="192.168.0.0/24",
    dev="wlan0",
    scope="link",
    route_type="unicast",
    flags=(),
):
    return {
        "dst": dst,
        "dev": dev,
        "scope": scope,
        "type": route_type,
        "flags": list(flags),
    }


def install_ip_output(monkeypatch, addresses=(), routes=()):
    outputs = {
        discovery.ADDRESS_ARGUMENTS: json.dumps(list(addresses)),
        discovery.ROUTE_ARGUMENTS: json.dumps(list(routes)),
    }

    def run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=outputs[tuple(command[1:])],
            stderr="",
        )

    mocked = Mock(side_effect=run)
    monkeypatch.setattr(discovery.subprocess, "run", mocked)
    return mocked


def test_interface_and_connected_route_are_merged_and_canonicalized(monkeypatch):
    run = install_ip_output(
        monkeypatch,
        addresses=[address_entry(local="192.168.0.158", prefixlen=24)],
        routes=[route_entry(dst="192.168.0.158/24")],
    )

    candidates = discovery.discover_local_networks()

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.cidr == "192.168.0.0/24"
    assert candidate.interface == "wlan0"
    assert candidate.address == "192.168.0.158"
    assert candidate.prefix_length == 24
    assert candidate.operstate == "UP"
    assert candidate.route_scope == "link"
    assert candidate.source == "connected_route+interface_address"
    assert len(candidate.evidence) == 2
    assert candidate.as_dict()["state"] == "CANDIDATE_NOT_AUTHORIZED"
    assert run.call_count == 2
    assert run.call_args_list[0].args[0] == [
        discovery.IP_EXECUTABLE,
        "-j",
        "address",
        "show",
    ]
    assert run.call_args_list[1].args[0] == [
        discovery.IP_EXECUTABLE,
        "-j",
        "-4",
        "route",
        "show",
    ]
    assert all(call.kwargs["shell"] is False for call in run.call_args_list)


def test_direct_route_can_supply_candidate_without_address_evidence(monkeypatch):
    install_ip_output(
        monkeypatch,
        addresses=[address_entry(local=None)],
        routes=[route_entry(dst="10.2.3.7/24")],
    )

    candidates = discovery.discover_local_networks()

    assert [candidate.cidr for candidate in candidates] == ["10.2.3.0/24"]
    assert candidates[0].source == "connected_route"
    assert candidates[0].address is None


def test_wlan0_up_candidate_is_returned_and_down_virbr0_is_excluded(monkeypatch):
    install_ip_output(
        monkeypatch,
        addresses=[
            address_entry(),
            address_entry(
                name="virbr0",
                local="192.168.122.1",
                operstate="DOWN",
            ),
        ],
        routes=[
            route_entry(),
            route_entry(
                dst="192.168.122.0/24",
                dev="virbr0",
                flags=("linkdown",),
            ),
        ],
    )

    assert [candidate.cidr for candidate in discovery.discover_local_networks()] == [
        "192.168.0.0/24"
    ]


def test_inactive_or_loopback_interfaces_are_excluded(monkeypatch):
    install_ip_output(
        monkeypatch,
        addresses=[
            address_entry(name="lo", local="10.0.0.1", flags=("UP", "LOOPBACK")),
            address_entry(name="eth0", local="10.0.0.1", operstate="UNKNOWN"),
            address_entry(name="eth1", local="10.0.0.1", flags=("BROADCAST",)),
        ],
    )

    assert discovery.discover_local_networks() == []


@pytest.mark.parametrize(
    ("local", "prefixlen"),
    [
        ("127.0.0.1", 24),
        ("169.254.1.1", 24),
        ("224.0.0.1", 24),
        ("0.0.0.1", 24),
        ("8.8.8.8", 24),
        ("192.0.2.10", 24),
        ("198.51.100.10", 24),
        ("203.0.113.10", 24),
        ("192.168.1.10", 23),
        ("192.168.1.10", 31),
        ("192.168.1.10", 32),
        ("10.1.2.0", 24),
        ("10.1.2.255", 24),
    ],
)
def test_interface_candidates_reject_invalid_or_unsupported_ranges(
    monkeypatch, local, prefixlen
):
    install_ip_output(
        monkeypatch,
        addresses=[address_entry(local=local, prefixlen=prefixlen)],
    )

    assert discovery.discover_local_networks() == []


@pytest.mark.parametrize(
    "destination",
    [
        "default",
        "192.168.0.0/23",
        "192.168.0.0/31",
        "192.168.0.1/32",
        "127.0.0.0/24",
        "169.254.0.0/24",
        "224.0.0.0/24",
        "0.0.0.0/24",
        "8.8.8.0/24",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    ],
)
def test_routes_reject_non_candidates(monkeypatch, destination):
    install_ip_output(
        monkeypatch,
        addresses=[address_entry(local=None)],
        routes=[route_entry(dst=destination)],
    )

    assert discovery.discover_local_networks() == []


@pytest.mark.parametrize(
    "route",
    [
        route_entry(flags=("linkdown",)),
        route_entry(route_type="blackhole"),
        route_entry(route_type="unreachable"),
        route_entry(route_type="prohibit"),
        route_entry(scope="global"),
        route_entry(dev="missing0"),
    ],
)
def test_routes_reject_down_invalid_or_non_link_routes(monkeypatch, route):
    install_ip_output(
        monkeypatch,
        addresses=[address_entry(local=None)],
        routes=[route],
    )

    assert discovery.discover_local_networks() == []


def test_duplicate_candidates_are_sorted_and_deduplicated(monkeypatch):
    install_ip_output(
        monkeypatch,
        addresses=[
            address_entry(name="wlan1", local="192.168.0.159"),
            address_entry(name="wlan0", local="192.168.0.158"),
        ],
        routes=[route_entry()],
    )

    candidates = discovery.discover_local_networks()
    assert len(candidates) == 1
    assert candidates[0].interface == "wlan0, wlan1"
    assert candidates[0].address == "192.168.0.158"
    assert candidates[0].evidence == tuple(sorted(candidates[0].evidence))


@pytest.mark.parametrize(
    ("stdout", "returncode", "error"),
    [
        ("not-json", 0, "malformed JSON"),
        ("{}", 0, "unexpected JSON"),
        ("[]", 1, "could not read"),
        ("x" * (discovery.MAX_OUTPUT_BYTES + 1), 0, "too much output"),
    ],
)
def test_command_failures_are_reported_without_parsing(
    monkeypatch, stdout, returncode, error
):
    mocked = Mock(
        return_value=subprocess.CompletedProcess(
            [discovery.IP_EXECUTABLE], returncode, stdout=stdout, stderr=""
        )
    )
    monkeypatch.setattr(discovery.subprocess, "run", mocked)

    with pytest.raises(discovery.LocalNetworkDiscoveryError, match=error):
        discovery.discover_local_networks()

    mocked.assert_called_once()


def test_command_timeout_is_controlled(monkeypatch):
    mocked = Mock(side_effect=subprocess.TimeoutExpired("ip", 5))
    monkeypatch.setattr(discovery.subprocess, "run", mocked)

    with pytest.raises(discovery.LocalNetworkDiscoveryError, match="timed out"):
        discovery.discover_local_networks()

    mocked.assert_called_once_with(
        [discovery.IP_EXECUTABLE, *discovery.ADDRESS_ARGUMENTS],
        shell=False,
        timeout=5,
        capture_output=True,
        text=True,
        check=False,
    )
