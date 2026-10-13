"""Immutable deterministic correlations for perimeter policy outcomes."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from services.perimeter_models import PerimeterAction, PerimeterProtocol, PerimeterSourceType


class PerimeterPolicyCorrelationError(ValueError):
    pass


class PerimeterPolicyCorrelationType(str, Enum):
    BLOCK_THEN_ALLOW = "BLOCK_THEN_ALLOW"
    ALLOW_THEN_BLOCK = "ALLOW_THEN_BLOCK"


class PerimeterPolicyCorrelationState(str, Enum):
    REVIEW = "REVIEW"


class PerimeterPolicyCorrelationConfidence(str, Enum):
    HIGH = "HIGH"


def _positive_id(name, value):
    if type(value) is not int or value <= 0:
        raise PerimeterPolicyCorrelationError(f"{name} must be a positive integer.")
    return value


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PerimeterPolicyCorrelationError("Perimeter correlation timestamps must be timezone-aware.")
    return value.astimezone(timezone.utc)


def _literal_ip(name, value):
    if not isinstance(value, str) or not value:
        raise PerimeterPolicyCorrelationError(f"{name} is required.")
    try:
        canonical = str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise PerimeterPolicyCorrelationError(f"{name} is invalid.") from exc
    if canonical != value:
        raise PerimeterPolicyCorrelationError(f"{name} must be canonical.")
    return canonical


@dataclass(frozen=True)
class PerimeterPolicyCorrelation:
    correlation_type: PerimeterPolicyCorrelationType | str
    site_id: int
    sensor_id: int | None
    primary_event_id: int
    event_ids: tuple[int, ...]
    allowed_event_ids: tuple[int, ...]
    blocked_event_ids: tuple[int, ...]
    source_type: PerimeterSourceType | str
    source_key: str
    source_ip: str
    destination_ip: str
    destination_port: int | None
    protocol: PerimeterProtocol | str
    primary_action: PerimeterAction | str
    first_seen: datetime
    last_seen: datetime
    rule_id: str
    rule_version: str
    reason: str
    state: PerimeterPolicyCorrelationState | str = PerimeterPolicyCorrelationState.REVIEW
    confidence: PerimeterPolicyCorrelationConfidence | str = PerimeterPolicyCorrelationConfidence.HIGH

    def __post_init__(self):
        object.__setattr__(self, "correlation_type", PerimeterPolicyCorrelationType(self.correlation_type))
        object.__setattr__(self, "state", PerimeterPolicyCorrelationState(self.state))
        object.__setattr__(self, "confidence", PerimeterPolicyCorrelationConfidence(self.confidence))
        object.__setattr__(self, "protocol", PerimeterProtocol(self.protocol))
        object.__setattr__(self, "source_type", PerimeterSourceType(self.source_type))
        object.__setattr__(self, "primary_action", PerimeterAction(self.primary_action))
        _positive_id("site_id", self.site_id)
        if self.sensor_id is not None:
            _positive_id("sensor_id", self.sensor_id)
        _positive_id("primary_event_id", self.primary_event_id)

        for name in ("event_ids", "allowed_event_ids", "blocked_event_ids"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not values:
                raise PerimeterPolicyCorrelationError(f"{name} must contain immutable event IDs.")
            if any(type(value) is not int or value <= 0 for value in values) or len(set(values)) != len(values):
                raise PerimeterPolicyCorrelationError(f"{name} must contain unique positive event IDs.")

        if self.primary_event_id not in self.event_ids:
            raise PerimeterPolicyCorrelationError("Correlation evidence must include the primary event.")
        allowed = set(self.allowed_event_ids)
        blocked = set(self.blocked_event_ids)
        if allowed & blocked:
            raise PerimeterPolicyCorrelationError("Allowed and blocked evidence must not overlap.")
        if set(self.event_ids) != allowed | blocked:
            raise PerimeterPolicyCorrelationError("Correlation event IDs must exactly match allowed and blocked evidence.")
        if self.primary_action == PerimeterAction.ALLOW and self.primary_event_id not in allowed:
            raise PerimeterPolicyCorrelationError("ALLOW primary event must be allowed evidence.")
        if self.primary_action in {PerimeterAction.BLOCK, PerimeterAction.REJECT} and self.primary_event_id not in blocked:
            raise PerimeterPolicyCorrelationError("Blocked primary event must be blocked evidence.")
        if self.primary_action not in {PerimeterAction.ALLOW, PerimeterAction.BLOCK, PerimeterAction.REJECT}:
            raise PerimeterPolicyCorrelationError("UNKNOWN policy actions cannot create a correlation.")

        if not isinstance(self.source_key, str) or not self.source_key.strip() or len(self.source_key.strip()) > 128:
            raise PerimeterPolicyCorrelationError("source_key is invalid.")
        object.__setattr__(self, "source_key", self.source_key.strip())
        object.__setattr__(self, "source_ip", _literal_ip("source_ip", self.source_ip))
        object.__setattr__(self, "destination_ip", _literal_ip("destination_ip", self.destination_ip))
        if self.destination_port is not None and (type(self.destination_port) is not int or not 1 <= self.destination_port <= 65535):
            raise PerimeterPolicyCorrelationError("destination_port must be between 1 and 65535.")
        if self.protocol in {PerimeterProtocol.TCP, PerimeterProtocol.UDP} and self.destination_port is None:
            raise PerimeterPolicyCorrelationError("TCP/UDP correlations require a destination port.")

        object.__setattr__(self, "first_seen", _utc(self.first_seen))
        object.__setattr__(self, "last_seen", _utc(self.last_seen))
        if self.last_seen < self.first_seen:
            raise PerimeterPolicyCorrelationError("Correlation timestamps are out of order.")
        for name in ("rule_id", "rule_version", "reason"):
            value = getattr(self, name)
            limit = 512 if name == "reason" else 128
            if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
                raise PerimeterPolicyCorrelationError(f"{name} is invalid.")
            object.__setattr__(self, name, value.strip())

    @property
    def stable_key(self):
        identity = [
            self.correlation_type.value,
            self.rule_id,
            self.rule_version,
            self.site_id,
            self.primary_event_id,
            list(self.event_ids),
        ]
        digest = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode("utf-8")).hexdigest()
        return f"perimeter-policy-correlation:{digest}"

    @property
    def event_count(self):
        return len(self.event_ids)

    @property
    def allow_count(self):
        return len(self.allowed_event_ids)

    @property
    def blocked_count(self):
        return len(self.blocked_event_ids)
