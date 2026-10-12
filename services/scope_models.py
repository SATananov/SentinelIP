from enum import Enum


class ScopeType(str, Enum):
    PRIVATE_NETWORK = "PRIVATE_NETWORK"
    PUBLIC_IPV4 = "PUBLIC_IPV4"
    PUBLIC_CIDR = "PUBLIC_CIDR"
    HOSTNAME = "HOSTNAME"


class ScopeError(ValueError):
    """Raised when an authorized scope is incomplete or inconsistent."""
