import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ChangeModelError(ValueError):
    """Raised when a change record is not a valid factual change."""


class ChangeType(str, Enum):
    NEW_DEVICE = "NEW_DEVICE"
    DEVICE_DISAPPEARED = "DEVICE_DISAPPEARED"
    DEVICE_REAPPEARED = "DEVICE_REAPPEARED"
    IP_CHANGED = "IP_CHANGED"
    NEW_PORT = "NEW_PORT"
    PORT_CLOSED = "PORT_CLOSED"
    PORT_REOPENED = "PORT_REOPENED"
    SERVICE_CHANGED = "SERVICE_CHANGED"
    SERVICE_VERSION_CHANGED = "SERVICE_VERSION_CHANGED"
    SERVICE_IDENTIFIED = "SERVICE_IDENTIFIED"
    SERVICE_BECAME_UNKNOWN = "SERVICE_BECAME_UNKNOWN"


class ChangeConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


def serialize_change_value(value) -> str | None:
    if value is None:
        return None

    if isinstance(value, str):
        return value

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ChangeModelError("Change values must be serializable.") from exc


@dataclass(frozen=True)
class ChangeRecord:
    change_type: ChangeType | str
    device_id: int
    network_id: int
    observed_at: datetime
    source: str
    confidence: ChangeConfidence | str
    evidence_type: str
    message: str
    port_id: int | None = None
    service_id: int | None = None
    previous_value: object | None = None
    current_value: object | None = None
    correlation_key: str | None = None
    metadata_json: object | None = None

    def __post_init__(self):
        change_type_value = (
            self.change_type.value
            if isinstance(self.change_type, ChangeType)
            else str(self.change_type).strip().upper()
        )
        confidence_value = (
            self.confidence.value
            if isinstance(self.confidence, ChangeConfidence)
            else str(self.confidence).strip().upper()
        )

        try:
            normalized_type = ChangeType(change_type_value)
            normalized_confidence = ChangeConfidence(confidence_value)
        except ValueError as exc:
            raise ChangeModelError("Change type or confidence is invalid.") from exc

        for field_name, value in (
            ("device_id", self.device_id),
            ("network_id", self.network_id),
        ):
            if type(value) is not int or value <= 0:
                raise ChangeModelError(f"{field_name} must be a positive integer.")

        for field_name, value in (
            ("port_id", self.port_id),
            ("service_id", self.service_id),
        ):
            if value is not None and (type(value) is not int or value <= 0):
                raise ChangeModelError(f"{field_name} must be a positive integer.")

        if not isinstance(self.observed_at, datetime):
            raise ChangeModelError("Change timestamp is required.")

        for field_name, value in (
            ("source", self.source),
            ("evidence_type", self.evidence_type),
            ("message", self.message),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ChangeModelError(f"{field_name} is required.")

        if self.correlation_key is not None:
            if not isinstance(self.correlation_key, str) or not self.correlation_key.strip():
                raise ChangeModelError("Correlation key must be non-empty.")

        object.__setattr__(self, "change_type", normalized_type)
        object.__setattr__(self, "confidence", normalized_confidence)
        object.__setattr__(self, "source", self.source.strip())
        object.__setattr__(self, "evidence_type", self.evidence_type.strip())
        object.__setattr__(self, "message", self.message.strip())
        object.__setattr__(
            self,
            "correlation_key",
            self.correlation_key.strip() if self.correlation_key else None,
        )
