import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class FindingModelError(ValueError):
    """Raised when a finding does not contain valid assessment data."""


class FindingType(str, Enum):
    PLAINTEXT_SERVICE = "PLAINTEXT_SERVICE"
    LEGACY_PROTOCOL = "LEGACY_PROTOCOL"
    EXPOSED_REMOTE_ADMIN = "EXPOSED_REMOTE_ADMIN"
    DATABASE_SERVICE_EXPOSED = "DATABASE_SERVICE_EXPOSED"
    CACHE_SERVICE_EXPOSED = "CACHE_SERVICE_EXPOSED"
    WEB_ADMIN_REVIEW = "WEB_ADMIN_REVIEW"
    NEW_SERVICE_EXPOSURE = "NEW_SERVICE_EXPOSURE"
    UNKNOWN_SERVICE_REVIEW = "UNKNOWN_SERVICE_REVIEW"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


def serialize_finding_metadata(value) -> str | None:
    if value is None:
        return None

    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise FindingModelError("Finding metadata must be serializable.") from exc


@dataclass(frozen=True)
class FindingRecord:
    finding_type: FindingType | str
    device_id: int
    network_id: int
    severity: FindingSeverity | str
    confidence: FindingConfidence | str
    status: FindingStatus | str
    title: str
    reason: str
    recommendation: str
    evidence_type: str
    source: str
    rule_id: str
    rule_version: str
    stable_key: str
    first_seen: datetime
    last_seen: datetime
    port_id: int | None = None
    service_id: int | None = None
    change_id: int | None = None
    resolved_at: datetime | None = None
    metadata: object | None = None

    def __post_init__(self):
        values = (
            FindingType,
            self.finding_type,
            FindingSeverity,
            self.severity,
            FindingConfidence,
            self.confidence,
            FindingStatus,
            self.status,
        )
        try:
            finding_type = values[0](
                self.finding_type.value
                if isinstance(self.finding_type, FindingType)
                else str(self.finding_type).strip().upper()
            )
            severity = values[2](
                self.severity.value
                if isinstance(self.severity, FindingSeverity)
                else str(self.severity).strip().upper()
            )
            confidence = values[4](
                self.confidence.value
                if isinstance(self.confidence, FindingConfidence)
                else str(self.confidence).strip().upper()
            )
            status = values[6](
                self.status.value
                if isinstance(self.status, FindingStatus)
                else str(self.status).strip().upper()
            )
        except ValueError as exc:
            raise FindingModelError("Finding type, severity, confidence, or status is invalid.") from exc

        for field_name, value in (
            ("device_id", self.device_id),
            ("network_id", self.network_id),
        ):
            if type(value) is not int or value <= 0:
                raise FindingModelError(f"{field_name} must be positive.")

        for field_name, value in (
            ("port_id", self.port_id),
            ("service_id", self.service_id),
            ("change_id", self.change_id),
        ):
            if value is not None and (type(value) is not int or value <= 0):
                raise FindingModelError(f"{field_name} must be positive when supplied.")

        for field_name, value in (
            ("title", self.title),
            ("reason", self.reason),
            ("recommendation", self.recommendation),
            ("evidence_type", self.evidence_type),
            ("source", self.source),
            ("rule_id", self.rule_id),
            ("rule_version", self.rule_version),
            ("stable_key", self.stable_key),
        ):
            if not isinstance(value, str) or not value.strip():
                raise FindingModelError(f"{field_name} is required.")

        if not isinstance(self.first_seen, datetime) or not isinstance(self.last_seen, datetime):
            raise FindingModelError("Finding timestamps are required.")

        if self.resolved_at is not None and not isinstance(self.resolved_at, datetime):
            raise FindingModelError("Resolved timestamp must be a datetime.")

        object.__setattr__(self, "finding_type", finding_type)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "status", status)

        for field_name in (
            "title",
            "reason",
            "recommendation",
            "evidence_type",
            "source",
            "rule_id",
            "rule_version",
            "stable_key",
        ):
            object.__setattr__(self, field_name, getattr(self, field_name).strip())