"""Normalized factual evidence model for perimeter network activity."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class PerimeterModelError(ValueError):
    """Raised when perimeter evidence cannot be normalized safely."""


class PerimeterSourceType(str, Enum):
    FIREWALL = "FIREWALL"
    ROUTER = "ROUTER"
    GATEWAY = "GATEWAY"
    SENSOR = "SENSOR"
    OTHER = "OTHER"


class PerimeterEventType(str, Enum):
    CONNECTION_ATTEMPT = "CONNECTION_ATTEMPT"
    FLOW = "FLOW"
    POLICY_DECISION = "POLICY_DECISION"
    OTHER = "OTHER"


class PerimeterDirection(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    LATERAL = "LATERAL"
    UNKNOWN = "UNKNOWN"


class PerimeterAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REJECT = "REJECT"
    UNKNOWN = "UNKNOWN"


class PerimeterProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "password",
        "credential",
        "credentials",
        "authorization",
        "authorization_header",
        "cookie",
        "cookies",
        "secret",
        "token",
    }
)
_MAX_METADATA_BYTES = 8192


def _positive_id(name: str, value: int | None, *, required: bool = True) -> int | None:
    if value is None and not required:
        return None
    if type(value) is not int or value <= 0:
        raise PerimeterModelError(f"{name} must be a positive integer.")
    return value


def _bounded_text(name: str, value: str | None, limit: int, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise PerimeterModelError(f"{name} is required.")
        return None
    if not isinstance(value, str):
        raise PerimeterModelError(f"{name} must be text.")
    normalized = value.strip()
    if (required and not normalized) or len(normalized) > limit:
        raise PerimeterModelError(f"{name} is invalid.")
    return normalized or None


def _timestamp(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PerimeterModelError("Perimeter timestamp must be timezone-aware.")
    normalized = value.astimezone(timezone.utc)
    if normalized > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise PerimeterModelError("Perimeter timestamp is too far in the future.")
    return normalized


def _ip(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PerimeterModelError(f"{name} is required.")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise PerimeterModelError(f"{name} is invalid.") from exc
    canonical = str(address)
    if canonical != value.strip():
        raise PerimeterModelError(f"{name} must be canonical.")
    return canonical


def _port(name: str, value: int | None) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 1 <= value <= 65535:
        raise PerimeterModelError(f"{name} must be between 1 and 65535.")
    return value


def _metadata(value: dict | None) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PerimeterModelError("Perimeter metadata must be an object.")

    def visit(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).casefold() in _FORBIDDEN_METADATA_KEYS:
                    raise PerimeterModelError("Sensitive perimeter metadata is not allowed.")
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise PerimeterModelError("Perimeter metadata must be JSON-compatible.")

    visit(value)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PerimeterModelError("Perimeter metadata must be JSON-compatible.") from exc
    if len(encoded) > _MAX_METADATA_BYTES:
        raise PerimeterModelError("Perimeter metadata is too large.")
    return value


@dataclass(frozen=True)
class PerimeterEvent:
    external_event_id: str
    site_id: int
    source_type: PerimeterSourceType | str
    source_key: str
    observed_at: datetime
    event_type: PerimeterEventType | str
    direction: PerimeterDirection | str
    action: PerimeterAction | str
    protocol: PerimeterProtocol | str
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    interface: str | None = None
    source_reference: str | None = None
    raw_event_hash: str | None = None
    metadata: dict | None = None
    sensor_id: int | None = None

    def __post_init__(self):
        try:
            source_type = PerimeterSourceType(self.source_type.value if isinstance(self.source_type, PerimeterSourceType) else str(self.source_type).strip().upper())
            event_type = PerimeterEventType(self.event_type.value if isinstance(self.event_type, PerimeterEventType) else str(self.event_type).strip().upper())
            direction = PerimeterDirection(self.direction.value if isinstance(self.direction, PerimeterDirection) else str(self.direction).strip().upper())
            action = PerimeterAction(self.action.value if isinstance(self.action, PerimeterAction) else str(self.action).strip().upper())
            protocol = PerimeterProtocol(self.protocol.value if isinstance(self.protocol, PerimeterProtocol) else str(self.protocol).strip().upper())
        except ValueError as exc:
            raise PerimeterModelError("Perimeter enum value is invalid.") from exc

        external_event_id = _bounded_text("external_event_id", self.external_event_id, 200, required=True)
        source_key = _bounded_text("source_key", self.source_key, 128, required=True)
        site_id = _positive_id("site_id", self.site_id)
        sensor_id = _positive_id("sensor_id", self.sensor_id, required=False)
        observed_at = _timestamp(self.observed_at)
        source_ip = _ip("source_ip", self.source_ip)
        destination_ip = _ip("destination_ip", self.destination_ip)
        source_port = _port("source_port", self.source_port)
        destination_port = _port("destination_port", self.destination_port)

        if protocol in {PerimeterProtocol.TCP, PerimeterProtocol.UDP} and destination_port is None:
            raise PerimeterModelError("TCP/UDP perimeter events require destination_port.")
        if protocol is PerimeterProtocol.ICMP and (source_port is not None or destination_port is not None):
            raise PerimeterModelError("ICMP perimeter events cannot carry TCP/UDP ports.")

        interface = _bounded_text("interface", self.interface, 128)
        source_reference = _bounded_text("source_reference", self.source_reference, 256)
        raw_event_hash = _bounded_text("raw_event_hash", self.raw_event_hash, 64)
        if raw_event_hash is not None:
            raw_event_hash = raw_event_hash.lower()
            if _HASH_RE.fullmatch(raw_event_hash) is None:
                raise PerimeterModelError("raw_event_hash must be a SHA-256 hex digest.")

        object.__setattr__(self, "external_event_id", external_event_id)
        object.__setattr__(self, "site_id", site_id)
        object.__setattr__(self, "sensor_id", sensor_id)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "source_key", source_key)
        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "source_ip", source_ip)
        object.__setattr__(self, "destination_ip", destination_ip)
        object.__setattr__(self, "source_port", source_port)
        object.__setattr__(self, "destination_port", destination_port)
        object.__setattr__(self, "interface", interface)
        object.__setattr__(self, "source_reference", source_reference)
        object.__setattr__(self, "raw_event_hash", raw_event_hash)
        object.__setattr__(self, "metadata", _metadata(self.metadata))
