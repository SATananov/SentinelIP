"""Immutable factual correlations between perimeter evidence and inventory devices."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from services.perimeter_models import PerimeterAction, PerimeterProtocol


class PerimeterHostCorrelationError(ValueError):
    pass


class PerimeterHostCorrelationType(str, Enum):
    DESTINATION_DEVICE_MATCH = "DESTINATION_DEVICE_MATCH"


class PerimeterHostCorrelationState(str, Enum):
    REVIEW = "REVIEW"


class PerimeterHostCorrelationConfidence(str, Enum):
    HIGH = "HIGH"


def _positive_id(name, value):
    if type(value) is not int or value <= 0:
        raise PerimeterHostCorrelationError(f"{name} must be a positive integer.")
    return value


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PerimeterHostCorrelationError("Host correlation timestamps must be timezone-aware.")
    return value.astimezone(timezone.utc)


def _literal_ip(value):
    if not isinstance(value, str) or not value:
        raise PerimeterHostCorrelationError("destination_ip is required.")
    try:
        canonical = str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise PerimeterHostCorrelationError("destination_ip is invalid.") from exc
    if canonical != value:
        raise PerimeterHostCorrelationError("destination_ip must be canonical.")
    return canonical


@dataclass(frozen=True)
class PerimeterHostCorrelation:
    site_id: int
    sensor_id: int | None
    event_id: int
    scope_id: int
    network_id: int
    device_id: int
    destination_ip: str
    destination_port: int | None
    protocol: PerimeterProtocol | str
    action: PerimeterAction | str
    observed_at: datetime
    device_last_seen: datetime
    device_status: str
    identity_confidence: str
    rule_id: str = "perimeter-host-current-inventory-v1"
    rule_version: str = "1"
    reason: str = (
        "The perimeter destination exactly matches one device in the site's current authorized private-network inventory. "
        "This is an inventory association for review, not proof that the host accepted traffic or was compromised."
    )
    correlation_type: PerimeterHostCorrelationType | str = PerimeterHostCorrelationType.DESTINATION_DEVICE_MATCH
    state: PerimeterHostCorrelationState | str = PerimeterHostCorrelationState.REVIEW
    confidence: PerimeterHostCorrelationConfidence | str = PerimeterHostCorrelationConfidence.HIGH

    def __post_init__(self):
        object.__setattr__(self, "correlation_type", PerimeterHostCorrelationType(self.correlation_type))
        object.__setattr__(self, "state", PerimeterHostCorrelationState(self.state))
        object.__setattr__(self, "confidence", PerimeterHostCorrelationConfidence(self.confidence))
        object.__setattr__(self, "protocol", PerimeterProtocol(self.protocol))
        object.__setattr__(self, "action", PerimeterAction(self.action))
        for name in ("site_id", "event_id", "scope_id", "network_id", "device_id"):
            _positive_id(name, getattr(self, name))
        if self.sensor_id is not None:
            _positive_id("sensor_id", self.sensor_id)
        object.__setattr__(self, "destination_ip", _literal_ip(self.destination_ip))
        if self.destination_port is not None and (type(self.destination_port) is not int or not 1 <= self.destination_port <= 65535):
            raise PerimeterHostCorrelationError("destination_port must be between 1 and 65535.")
        if self.protocol in {PerimeterProtocol.TCP, PerimeterProtocol.UDP} and self.destination_port is None:
            raise PerimeterHostCorrelationError("TCP/UDP host correlations require a destination port.")
        object.__setattr__(self, "observed_at", _utc(self.observed_at))
        object.__setattr__(self, "device_last_seen", _utc(self.device_last_seen))
        if self.device_status not in {"ONLINE", "OFFLINE"}:
            raise PerimeterHostCorrelationError("device_status is invalid.")
        if self.identity_confidence not in {"HIGH", "MEDIUM", "LOW"}:
            raise PerimeterHostCorrelationError("identity_confidence is invalid.")
        for name in ("rule_id", "rule_version", "reason"):
            value = getattr(self, name)
            limit = 512 if name == "reason" else 128
            if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
                raise PerimeterHostCorrelationError(f"{name} is invalid.")
            object.__setattr__(self, name, value.strip())

    @property
    def stable_key(self):
        identity = [self.correlation_type.value, self.rule_id, self.rule_version, self.site_id, self.event_id, self.device_id]
        digest = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode("utf-8")).hexdigest()
        return f"perimeter-host-correlation:{digest}"
