import ipaddress


class PublicTargetPolicyError(ValueError):
    """Raised when a target is not an eligible single public IPv4 address."""


PUBLIC_IPV4_CONFIRMATION_VERSION = "public_ipv4_authorization_v1"


_EXCLUDED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
)


def normalize_public_ipv4(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise PublicTargetPolicyError("Target must be one public IPv4 address.")
    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise PublicTargetPolicyError(
            "Target must be one public IPv4 address."
        ) from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise PublicTargetPolicyError("IPv6 targets are not supported.")
    if any(address in network for network in _EXCLUDED_NETWORKS):
        raise PublicTargetPolicyError(
            "Target is in a private or special-purpose IPv4 range."
        )
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or not address.is_global
    ):
        raise PublicTargetPolicyError(
            "Target must be a globally routable unicast IPv4 address."
        )
    return str(address)
