import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime


MAC_PATTERN = re.compile(r"^[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}$")


class ScanModelError(ValueError):
    """Raised when a normalized scan model contains invalid evidence."""


def normalize_ipv4(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScanModelError("Host IP address must be a non-empty string.")

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ScanModelError("Host IP address must be valid IPv4.") from exc

    if address.version != 4:
        raise ScanModelError("Host IP address must be IPv4.")

    return str(address)


def normalize_mac(value: str | None) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ScanModelError("MAC address must be a string.")

    normalized = value.strip()

    if not normalized:
        return None

    if not MAC_PATTERN.fullmatch(normalized):
        raise ScanModelError("MAC address must contain six hexadecimal octets.")

    return normalized.replace("-", ":").lower()


def normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip()
    return normalized or None


@dataclass(frozen=True)
class HostDiscoveryResult:
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    status: str = "up"
    discovered_at: datetime | None = None
    source: str = "unknown"

    def __post_init__(self):
        if self.discovered_at is None:
            raise ScanModelError("Discovery timestamp is required.")

        if self.status != "up":
            raise ScanModelError("Host discovery status must be 'up'.")

        if not isinstance(self.source, str) or not self.source.strip():
            raise ScanModelError("Discovery source is required.")

        object.__setattr__(self, "ip_address", normalize_ipv4(self.ip_address))
        object.__setattr__(self, "mac_address", normalize_mac(self.mac_address))
        object.__setattr__(self, "hostname", normalize_optional_text(self.hostname))
        object.__setattr__(self, "vendor", normalize_optional_text(self.vendor))
        object.__setattr__(self, "source", self.source.strip())


@dataclass(frozen=True)
class ScanResult:
    target_network: str
    scanner: str
    started_at: datetime
    completed_at: datetime
    hosts: tuple[HostDiscoveryResult, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.target_network, str):
            raise ScanModelError("Target network must be a normalized CIDR string.")

        if not self.target_network.strip():
            raise ScanModelError("Target network is required.")

        if not isinstance(self.scanner, str) or not self.scanner.strip():
            raise ScanModelError("Scanner name is required.")

        object.__setattr__(self, "target_network", self.target_network.strip())
        object.__setattr__(self, "scanner", self.scanner.strip())
        object.__setattr__(self, "hosts", tuple(self.hosts))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "errors", tuple(self.errors))