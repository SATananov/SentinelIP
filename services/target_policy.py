import ipaddress
from dataclasses import dataclass


MAX_PREFIX_LENGTH = 24


class TargetPolicyError(ValueError):
    """Raised when a network target is outside the authorized policy."""


@dataclass(frozen=True)
class ValidatedNetwork:
    cidr: str


def validate_cidr(cidr: str) -> ValidatedNetwork:
    if not isinstance(cidr, str) or not cidr.strip():
        raise TargetPolicyError("CIDR must be a non-empty string.")

    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise TargetPolicyError("CIDR must be a valid IPv4 network.") from exc

    if network.version != 4:
        raise TargetPolicyError("IPv6 networks are not supported.")

    if network.prefixlen < MAX_PREFIX_LENGTH:
        raise TargetPolicyError("Networks must be /24 or narrower.")

    if network.is_loopback:
        raise TargetPolicyError("Loopback networks are not allowed.")

    if network.is_multicast:
        raise TargetPolicyError("Multicast networks are not allowed.")

    if network.is_unspecified:
        raise TargetPolicyError("Unspecified networks are not allowed.")

    if network.is_link_local:
        raise TargetPolicyError("Link-local networks are not allowed.")

    if not network.is_private:
        raise TargetPolicyError("Only private IPv4 networks are allowed.")

    return ValidatedNetwork(cidr=network.with_prefixlen)


def normalize_cidr(cidr: str) -> str:
    return validate_cidr(cidr).cidr