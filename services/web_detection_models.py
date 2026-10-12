"""Immutable, allowlisted web evidence and review records."""
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum

from services.finding_models import FindingConfidence, FindingSeverity
from services.telemetry_models import WebEventType, normalize_domain


class WebDetectionError(ValueError):
    pass


class WebDetectionType(str, Enum):
    CROSS_DOMAIN_LOGIN_REDIRECT = "CROSS_DOMAIN_LOGIN_REDIRECT"
    LOGIN_DOMAIN_REVIEW = "LOGIN_DOMAIN_REVIEW"
    REDIRECT_CHAIN_REVIEW = "REDIRECT_CHAIN_REVIEW"
    SUSPICIOUS_DOWNLOAD_FLOW = "SUSPICIOUS_DOWNLOAD_FLOW"


class WebDetectionState(str, Enum):
    REVIEW = "REVIEW"


# Fixed projection: detection never loads paths or arbitrary telemetry metadata.
EVIDENCE_COLUMNS = """id, sensor_id, device_id, hostname, event_type, observed_at,
    received_at, browser_session_id, tab_id, redirect_from_domain, redirect_to_domain,
    has_login_form, has_password_form, download_detected, source"""


def utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            raise WebDetectionError("Invalid evidence timestamp.") from None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise WebDetectionError("Timezone-aware timestamps are required.")
    return value.astimezone(timezone.utc)


def positive_id(value):
    if type(value) is not int or value <= 0:
        raise WebDetectionError("Persisted positive IDs are required.")


@dataclass(frozen=True)
class WebEvidence:
    observation_id: int
    sensor_id: int
    device_id: int | None
    hostname: str
    event_type: WebEventType
    observed_at: datetime
    received_at: datetime
    browser_session_id: str | None = None
    tab_id: str | None = None
    redirect_from_domain: str | None = None
    redirect_to_domain: str | None = None
    has_login_form: bool = False
    has_password_form: bool = False
    download_detected: bool = False
    source: str = "browser"

    def __post_init__(self):
        positive_id(self.observation_id)
        positive_id(self.sensor_id)
        if self.device_id is not None:
            positive_id(self.device_id)
        if self.source != "browser":
            raise WebDetectionError("Only persisted browser evidence is supported.")
        object.__setattr__(self, "event_type", WebEventType(self.event_type))
        object.__setattr__(self, "hostname", normalize_domain(self.hostname))
        for name in ("observed_at", "received_at"):
            object.__setattr__(self, name, utc(getattr(self, name)))
        for name in ("redirect_from_domain", "redirect_to_domain"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, normalize_domain(value))
        for name in ("browser_session_id", "tab_id"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise WebDetectionError("Invalid browser context.")
            if value is not None and not value.strip():
                object.__setattr__(self, name, None)
        for name in ("has_login_form", "has_password_form", "download_detected"):
            value = getattr(self, name)
            if type(value) not in (bool, int) or value not in (0, 1):
                raise WebDetectionError("Invalid structural signal.")
            object.__setattr__(self, name, bool(value))

    @classmethod
    def from_row(cls, row):
        # Never copy arbitrary metadata, paths, URLs, or credentials.
        names = cls.__dataclass_fields__.keys() - {"observation_id"}
        return cls(observation_id=row["id"], **{name: row[name] for name in names})

    @property
    def context(self):
        if self.browser_session_id is None:
            return None
        return (self.sensor_id, self.device_id, self.browser_session_id, self.tab_id)

    def snapshot(self):
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["observed_at"] = self.observed_at.isoformat()
        data["received_at"] = self.received_at.isoformat()
        return data


@dataclass(frozen=True)
class WebDetection:
    detection_type: WebDetectionType
    severity: FindingSeverity
    confidence: FindingConfidence
    state: WebDetectionState
    sensor_id: int
    device_id: int | None
    primary_observation_id: int
    hostname: str
    reason: str
    evidence: tuple[WebEvidence, ...]
    rule_id: str
    rule_version: str
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self):
        for name, enum in (("detection_type", WebDetectionType), ("severity", FindingSeverity),
                           ("confidence", FindingConfidence), ("state", WebDetectionState)):
            object.__setattr__(self, name, enum(getattr(self, name)))
        if self.severity not in (FindingSeverity.LOW, FindingSeverity.MEDIUM) or self.confidence != FindingConfidence.MEDIUM:
            raise WebDetectionError("Web reviews require conservative severity and confidence.")
        positive_id(self.sensor_id)
        positive_id(self.primary_observation_id)
        if self.device_id is not None:
            positive_id(self.device_id)
        if not isinstance(self.evidence, tuple) or not self.evidence or not all(isinstance(e, WebEvidence) for e in self.evidence):
            raise WebDetectionError("Immutable evidence is required.")
        ids = tuple(e.observation_id for e in self.evidence)
        if len(set(ids)) != len(ids) or self.primary_observation_id not in ids:
            raise WebDetectionError("Primary and related evidence must be unambiguous.")
        primary = next(e for e in self.evidence if e.observation_id == self.primary_observation_id)
        for item in self.evidence:
            if (item.sensor_id, item.device_id) != (self.sensor_id, self.device_id):
                raise WebDetectionError("Evidence identity mismatch.")
            if len(self.evidence) > 1 and (primary.context is None or item.context != primary.context):
                raise WebDetectionError("Explicit matching browser context is required.")
        object.__setattr__(self, "hostname", normalize_domain(self.hostname))
        if primary.hostname != self.hostname:
            raise WebDetectionError("Primary hostname mismatch.")
        for name in ("reason", "rule_id", "rule_version"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise WebDetectionError("Rule identity and reason are required.")
        for name in ("first_seen", "last_seen"):
            object.__setattr__(self, name, utc(getattr(self, name)))
        if self.last_seen < self.first_seen:
            raise WebDetectionError("Review timestamps are out of order.")

    @property
    def related_observation_ids(self):
        return tuple(e.observation_id for e in self.evidence if e.observation_id != self.primary_observation_id)

    @property
    def stable_key(self):
        identity = [self.rule_id, self.rule_version, self.sensor_id, self.device_id,
                    self.primary_observation_id, self.hostname, sorted(e.observation_id for e in self.evidence)]
        return "web-review:" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
