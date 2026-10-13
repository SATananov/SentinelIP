"""Immutable deterministic review signals derived from perimeter evidence."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from services.perimeter_models import PerimeterAction, PerimeterProtocol


class PerimeterDetectionError(ValueError):
    pass


class PerimeterDetectionType(str, Enum):
    INBOUND_ATTEMPT = "INBOUND_ATTEMPT"
    REPEATED_INBOUND_ATTEMPTS = "REPEATED_INBOUND_ATTEMPTS"


class PerimeterDetectionState(str, Enum):
    REVIEW = "REVIEW"


class PerimeterDetectionConfidence(str, Enum):
    HIGH = "HIGH"


def _positive_id(name, value):
    if type(value) is not int or value <= 0:
        raise PerimeterDetectionError(f"{name} must be a positive integer.")
    return value


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PerimeterDetectionError("Perimeter detection timestamps must be timezone-aware.")
    return value.astimezone(timezone.utc)


def _literal_ip(name, value):
    if not isinstance(value, str) or not value:
        raise PerimeterDetectionError(f"{name} is required.")
    try:
        canonical = str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise PerimeterDetectionError(f"{name} is invalid.") from exc
    if canonical != value:
        raise PerimeterDetectionError(f"{name} must be canonical.")
    return canonical


@dataclass(frozen=True)
class PerimeterDetection:
    detection_type: PerimeterDetectionType | str
    site_id: int
    sensor_id: int | None
    primary_event_id: int
    event_ids: tuple[int, ...]
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: PerimeterProtocol | str
    action: PerimeterAction | str
    first_seen: datetime
    last_seen: datetime
    rule_id: str
    rule_version: str
    reason: str
    state: PerimeterDetectionState | str = PerimeterDetectionState.REVIEW
    confidence: PerimeterDetectionConfidence | str = PerimeterDetectionConfidence.HIGH

    def __post_init__(self):
        object.__setattr__(self, "detection_type", PerimeterDetectionType(self.detection_type))
        object.__setattr__(self, "state", PerimeterDetectionState(self.state))
        object.__setattr__(self, "confidence", PerimeterDetectionConfidence(self.confidence))
        object.__setattr__(self, "protocol", PerimeterProtocol(self.protocol))
        object.__setattr__(self, "action", PerimeterAction(self.action))
        _positive_id("site_id", self.site_id)
        if self.sensor_id is not None:
            _positive_id("sensor_id", self.sensor_id)
        _positive_id("primary_event_id", self.primary_event_id)
        if not isinstance(self.event_ids, tuple) or not self.event_ids:
            raise PerimeterDetectionError("Immutable perimeter event IDs are required.")
        if any(type(value) is not int or value <= 0 for value in self.event_ids):
            raise PerimeterDetectionError("Perimeter event IDs must be positive integers.")
        if len(set(self.event_ids)) != len(self.event_ids) or self.primary_event_id not in self.event_ids:
            raise PerimeterDetectionError("Perimeter detection evidence must be unique and include the primary event.")
        if self.detection_type == PerimeterDetectionType.INBOUND_ATTEMPT and len(self.event_ids) != 1:
            raise PerimeterDetectionError("A single inbound attempt must reference exactly one event.")
        if self.detection_type == PerimeterDetectionType.REPEATED_INBOUND_ATTEMPTS and len(self.event_ids) < 5:
            raise PerimeterDetectionError("Repeated inbound attempts require at least five matching events.")
        object.__setattr__(self, "source_ip", _literal_ip("source_ip", self.source_ip))
        object.__setattr__(self, "destination_ip", _literal_ip("destination_ip", self.destination_ip))
        for name in ("source_port", "destination_port"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or not 1 <= value <= 65535):
                raise PerimeterDetectionError(f"{name} must be between 1 and 65535.")
        if self.protocol in {PerimeterProtocol.TCP, PerimeterProtocol.UDP} and self.destination_port is None:
            raise PerimeterDetectionError("TCP/UDP detections require a destination port.")
        object.__setattr__(self, "first_seen", _utc(self.first_seen))
        object.__setattr__(self, "last_seen", _utc(self.last_seen))
        if self.last_seen < self.first_seen:
            raise PerimeterDetectionError("Perimeter detection timestamps are out of order.")
        for name in ("rule_id", "rule_version", "reason"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value.strip()) > (512 if name == "reason" else 128):
                raise PerimeterDetectionError(f"{name} is invalid.")
            object.__setattr__(self, name, value.strip())

    @property
    def stable_key(self):
        identity = [
            self.detection_type.value,
            self.rule_id,
            self.rule_version,
            self.site_id,
            self.primary_event_id,
            list(self.event_ids),
        ]
        return "perimeter-detection:" + hashlib.sha256(
            json.dumps(identity, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @property
    def event_count(self):
        return len(self.event_ids)

    @property
    def unique_source_count(self):
        return 1
