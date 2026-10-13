"""Platform-neutral remote sensor policy; no execution or inventory ingestion."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import ipaddress


class RemoteSensorError(ValueError):
    pass


class RemoteSensorAuthError(RemoteSensorError):
    pass


class RemoteSensorConflictError(RemoteSensorError):
    pass


class Capability(str, Enum):
    LOCAL_NETWORK_DISCOVERY = "LOCAL_NETWORK_DISCOVERY"
    HOST_DISCOVERY = "HOST_DISCOVERY"
    SERVICE_DISCOVERY = "SERVICE_DISCOVERY"
    LOG_COLLECTION = "LOG_COLLECTION"


class SensorStatus(str, Enum):
    PENDING = "PENDING"
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DISABLED = "DISABLED"


HEARTBEAT_WINDOW = timedelta(minutes=5)
RFC1918 = tuple(ipaddress.IPv4Network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def capabilities(values):
    if not isinstance(values, (list, tuple)) or len(values) > len(Capability):
        raise RemoteSensorError("Invalid capability list.")
    try:
        return tuple(sorted({Capability(value).value for value in values}))
    except (ValueError, TypeError) as exc:
        raise RemoteSensorError("Unsupported capability.") from exc


def sensor_status(*, enabled, site_enabled, last_seen_at, now):
    if not enabled or not site_enabled:
        return SensorStatus.DISABLED.value
    if last_seen_at is None:
        return SensorStatus.PENDING.value
    elapsed = now - datetime.fromisoformat(last_seen_at)
    return (SensorStatus.ONLINE if timedelta(0) <= elapsed <= HEARTBEAT_WINDOW else SensorStatus.OFFLINE).value


def private_lan(cidr):
    try:
        network = ipaddress.IPv4Network(cidr, strict=True)
    except (ValueError, TypeError) as exc:
        raise RemoteSensorError("A canonical private IPv4 network is required.") from exc
    if network.prefixlen < 24 or not any(network.subnet_of(r) for r in RFC1918):
        raise RemoteSensorError("Remote scope must be RFC1918 /24 or narrower.")
    return network


@dataclass(frozen=True)
class LocalScopeGrant:
    """Independently installed local allowlist entry, never a job-supplied grant."""
    sensor_uuid: str
    scope_id: int
    cidr: str

    def __post_init__(self):
        if not self.sensor_uuid or type(self.scope_id) is not int or self.scope_id <= 0:
            raise RemoteSensorError("Invalid local grant identity.")
        private_lan(self.cidr)

    def validate_target(self, sensor_uuid, scope_id, target):
        if sensor_uuid != self.sensor_uuid or scope_id != self.scope_id:
            raise RemoteSensorError("Target identity does not match the local grant.")
        try:
            address = ipaddress.IPv4Address(target)
        except (ValueError, TypeError) as exc:
            raise RemoteSensorError("A concrete IPv4 address is required.") from exc
        if str(address) != target or address not in private_lan(self.cidr):
            raise RemoteSensorError("Target is outside the local grant.")
        return str(address)


@dataclass(frozen=True)
class IssuedSecret:
    record: dict
    secret: str = field(repr=False)
