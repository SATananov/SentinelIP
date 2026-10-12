"""Small public IPv4 scopes include every address, including both endpoints."""
import ipaddress

from services.public_target_policy import normalize_public_ipv4

PUBLIC_CIDR_CONFIRMATION_VERSION = "public_cidr_authorization_v1"
MAX_PUBLIC_CIDR_ADDRESSES = 8


class PublicCIDRPolicyError(ValueError):
    pass


def normalize_public_cidr(target: str) -> str:
    if not isinstance(target, str) or target.count("/") != 1:
        raise PublicCIDRPolicyError("Enter an IPv4 CIDR with a prefix from /29 to /32.")
    value = target.strip()
    prefix = value.split("/")[1]
    if not prefix.isascii() or not prefix.isdecimal():
        raise PublicCIDRPolicyError("A numeric IPv4 prefix is required.")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise PublicCIDRPolicyError("Invalid IPv4 CIDR.") from exc
    if network.version != 4:
        raise PublicCIDRPolicyError("IPv6 targets are not supported.")
    if network.num_addresses > MAX_PUBLIC_CIDR_ADDRESSES:
        raise PublicCIDRPolicyError("Range too large for SentinelIP bounded public scanning. Maximum allowed: 8 addresses (/29).")
    # Check the entire (at most eight address) range, not only its first address.
    try:
        for address in network:
            normalize_public_ipv4(str(address))
    except ValueError as exc:
        raise PublicCIDRPolicyError("Every address in the CIDR must be eligible public IPv4.") from exc
    return str(network)


def public_cidr_addresses(target: str) -> tuple[str, ...]:
    return tuple(str(address) for address in ipaddress.ip_network(normalize_public_cidr(target)))
