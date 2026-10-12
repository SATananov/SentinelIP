"""Passive discovery of candidate private networks from local Linux state."""

import ipaddress
import json
import subprocess
from dataclasses import dataclass


IP_EXECUTABLE = "/usr/sbin/ip"
ADDRESS_ARGUMENTS = ("-j", "address", "show")
ROUTE_ARGUMENTS = ("-j", "-4", "route", "show")
COMMAND_TIMEOUT_SECONDS = 5
MAX_OUTPUT_BYTES = 1_048_576
MIN_PREFIX_LENGTH = 24
MAX_PREFIX_LENGTH = 30

RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class LocalNetworkDiscoveryError(RuntimeError):
    """Raised when local Linux networking state cannot be read safely."""


@dataclass(frozen=True)
class LocalNetworkCandidate:
    cidr: str
    interface: str
    source: str
    address: str | None
    prefix_length: int
    operstate: str
    route_scope: str | None
    evidence: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "cidr": self.cidr,
            "interface": self.interface,
            "source": self.source,
            "address": self.address,
            "prefix_length": self.prefix_length,
            "operstate": self.operstate,
            "route_scope": self.route_scope,
            "evidence": list(self.evidence),
            "state": "CANDIDATE_NOT_AUTHORIZED",
        }


def _run_ip(arguments: tuple[str, ...]) -> list:
    try:
        completed = subprocess.run(
            [IP_EXECUTABLE, *arguments],
            shell=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LocalNetworkDiscoveryError(
            "The local ip utility is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalNetworkDiscoveryError(
            "Reading local network state timed out."
        ) from exc
    except OSError as exc:
        raise LocalNetworkDiscoveryError(
            "The local ip utility could not be started."
        ) from exc

    output_size = len(completed.stdout.encode("utf-8")) if completed.stdout else 0
    error_size = len(completed.stderr.encode("utf-8")) if completed.stderr else 0
    if output_size + error_size > MAX_OUTPUT_BYTES:
        raise LocalNetworkDiscoveryError(
            "The local ip utility returned too much output."
        )

    if completed.returncode != 0:
        raise LocalNetworkDiscoveryError(
            "The local ip utility could not read networking state."
        )

    try:
        result = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise LocalNetworkDiscoveryError(
            "The local ip utility returned malformed JSON."
        ) from exc

    if not isinstance(result, list):
        raise LocalNetworkDiscoveryError(
            "The local ip utility returned an unexpected JSON structure."
        )
    return result


def _candidate_network(value: str, prefix_length: int):
    if type(prefix_length) is not int:
        return None
    if not MIN_PREFIX_LENGTH <= prefix_length <= MAX_PREFIX_LENGTH:
        return None

    try:
        network = ipaddress.ip_network(f"{value}/{prefix_length}", strict=False)
    except ValueError:
        return None

    if network.version != 4:
        return None
    if not any(network.subnet_of(private_range) for private_range in RFC1918_NETWORKS):
        return None
    return network


def _active_interfaces(address_data: list) -> dict[str, dict]:
    interfaces = {}
    for entry in address_data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("ifname")
        flags = entry.get("flags")
        operstate = entry.get("operstate")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(flags, list)
            or "UP" not in flags
            or "LOOPBACK" in flags
            or operstate != "UP"
        ):
            continue
        interfaces[name] = {"operstate": operstate, "addresses": []}

    for entry in address_data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("ifname")
        interface = interfaces.get(name)
        if interface is None:
            continue
        addr_info = entry.get("addr_info")
        if not isinstance(addr_info, list):
            continue
        for address in addr_info:
            if not isinstance(address, dict) or address.get("family") != "inet":
                continue
            local = address.get("local")
            prefix_length = address.get("prefixlen")
            if not isinstance(local, str):
                continue
            try:
                parsed_address = ipaddress.ip_address(local)
            except ValueError:
                continue
            if parsed_address.version != 4:
                continue
            network = _candidate_network(local, prefix_length)
            if network is None:
                continue
            if parsed_address in (network.network_address, network.broadcast_address):
                continue
            interface["addresses"].append((network, str(parsed_address)))
    return interfaces


def _candidate_record(
    candidates: dict[str, dict],
    *,
    network: ipaddress.IPv4Network,
    interface: str,
    source: str,
    address: str | None,
    operstate: str,
    route_scope: str | None,
    evidence: str,
) -> None:
    cidr = network.with_prefixlen
    current = candidates.setdefault(
        cidr,
        {
            "interfaces": set(),
            "sources": set(),
            "addresses": set(),
            "operstates": set(),
            "route_scopes": set(),
            "evidence": set(),
        },
    )
    current["interfaces"].add(interface)
    current["sources"].add(source)
    current["operstates"].add(operstate)
    current["evidence"].add(evidence)
    if address is not None:
        current["addresses"].add(address)
    if route_scope is not None:
        current["route_scopes"].add(route_scope)


def discover_local_networks() -> list[LocalNetworkCandidate]:
    """Return active RFC1918 candidates without probing or persisting them."""
    address_data = _run_ip(ADDRESS_ARGUMENTS)
    route_data = _run_ip(ROUTE_ARGUMENTS)
    interfaces = _active_interfaces(address_data)
    candidates: dict[str, dict] = {}

    for name, interface in interfaces.items():
        for network, address in interface["addresses"]:
            _candidate_record(
                candidates,
                network=network,
                interface=name,
                source="interface_address",
                address=address,
                operstate=interface["operstate"],
                route_scope=None,
                evidence=f"assigned IPv4 address {address}/{network.prefixlen}",
            )

    for route in route_data:
        if not isinstance(route, dict):
            continue
        destination = route.get("dst")
        interface_name = route.get("dev")
        flags = route.get("flags", [])
        route_type = route.get("type", "unicast")
        route_scope = route.get("scope")
        interface = interfaces.get(interface_name)
        if (
            not isinstance(destination, str)
            or destination == "default"
            or not isinstance(interface_name, str)
            or interface is None
            or not isinstance(flags, list)
            or any(str(flag).lower() == "linkdown" for flag in flags)
            or route_type != "unicast"
            or route_scope != "link"
        ):
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        normalized = _candidate_network(
            str(network.network_address), network.prefixlen
        )
        if normalized is None:
            continue
        _candidate_record(
            candidates,
            network=normalized,
            interface=interface_name,
            source="connected_route",
            address=None,
            operstate=interface["operstate"],
            route_scope=route_scope,
            evidence=f"directly connected IPv4 route {normalized.with_prefixlen}",
        )

    records = []
    for cidr, evidence in candidates.items():
        network = ipaddress.ip_network(cidr)
        sources = sorted(evidence["sources"])
        records.append(
            LocalNetworkCandidate(
                cidr=cidr,
                interface=", ".join(sorted(evidence["interfaces"])),
                source="+".join(sources),
                address=sorted(evidence["addresses"])[0]
                if evidence["addresses"]
                else None,
                prefix_length=network.prefixlen,
                operstate=", ".join(sorted(evidence["operstates"])),
                route_scope=", ".join(sorted(evidence["route_scopes"]))
                if evidence["route_scopes"]
                else None,
                evidence=tuple(sorted(evidence["evidence"])),
            )
        )

    return sorted(
        records,
        key=lambda candidate: (
            int(ipaddress.ip_network(candidate.cidr).network_address),
            candidate.prefix_length,
            candidate.interface,
        ),
    )
