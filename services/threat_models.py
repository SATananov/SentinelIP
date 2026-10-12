"""Immutable local threat-pattern records; consequences are never confirmed."""
import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum

from services.finding_models import FindingConfidence, FindingSeverity
from services.telemetry_models import normalize_domain
from services.web_detection_models import WebEvidence, utc


class ThreatError(ValueError):
    pass


class ThreatType(str, Enum):
    SSH_BRUTE_FORCE_THREAT = "SSH_BRUTE_FORCE_THREAT"
    SUSPICIOUS_AUTH_ACTIVITY = "SUSPICIOUS_AUTH_ACTIVITY"
    WEB_CREDENTIAL_FLOW_THREAT = "WEB_CREDENTIAL_FLOW_THREAT"


class ThreatState(str, Enum):
    ANOMALOUS = "ANOMALOUS"
    SUSPECTED = "SUSPECTED"


class EvidenceType(str, Enum):
    SSH_EVENT = "SSH_EVENT"
    WEB_DETECTION = "WEB_DETECTION"
    FINDING = "FINDING"
    CVE_MATCH = "CVE_MATCH"
    CHANGE = "CHANGE"


def positive_id(value):
    if type(value) is not int or value <= 0:
        raise ThreatError("A positive persisted evidence ID is required.")


def ssh_time(value):
    try:
        result = datetime.fromisoformat(value) if isinstance(value, str) else value
        if not isinstance(result, datetime):
            raise ValueError
        return result.astimezone(timezone.utc) if result.utcoffset() is not None else result
    except (ValueError, TypeError, OverflowError):
        raise ThreatError("Invalid authentication timestamp.") from None


@dataclass(frozen=True)
class SSHThreatEvidence:
    evidence_id: int
    source_ip: str
    username: str | None
    event_type: str
    event_count: int
    timestamp: datetime

    def __post_init__(self):
        positive_id(self.evidence_id)
        if not isinstance(self.source_ip, str) or "%" in self.source_ip:
            raise ThreatError("A literal source IP is required.")
        object.__setattr__(self, "source_ip", str(ipaddress.ip_address(self.source_ip)))
        if self.event_type not in {"LOGIN_FAILED", "SSH_PREAUTH", "LOGIN_SUCCESS", "CONNECTION_CLOSED"}:
            raise ThreatError("Unsupported authentication event.")
        if self.username is not None and not isinstance(self.username, str):
            raise ThreatError("Invalid username evidence.")
        positive_id(self.event_count)
        object.__setattr__(self, "timestamp", ssh_time(self.timestamp))

    @property
    def evidence_type(self):
        return EvidenceType.SSH_EVENT

    def snapshot(self):
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result


@dataclass(frozen=True)
class WebThreatEvidence:
    evidence_id: int
    detection_type: str
    sensor_id: int
    device_id: int | None
    primary_observation_id: int
    hostname: str
    reason: str
    observations: tuple[WebEvidence, ...]
    rule_id: str
    rule_version: str
    first_seen: datetime
    # last_seen is mutable evaluation bookkeeping, not threat-pattern evidence.

    def __post_init__(self):
        positive_id(self.evidence_id)
        positive_id(self.sensor_id)
        positive_id(self.primary_observation_id)
        if self.device_id is not None:
            positive_id(self.device_id)
        if self.detection_type not in {"CROSS_DOMAIN_LOGIN_REDIRECT", "SUSPICIOUS_DOWNLOAD_FLOW",
                                       "LOGIN_DOMAIN_REVIEW", "REDIRECT_CHAIN_REVIEW"}:
            raise ThreatError("Unsupported web detection.")
        if not isinstance(self.observations, tuple) or not self.observations or not all(isinstance(e, WebEvidence) for e in self.observations):
            raise ThreatError("Immutable web evidence is required.")
        ids = [e.observation_id for e in self.observations]
        if len(set(ids)) != len(ids) or self.primary_observation_id not in ids:
            raise ThreatError("Unambiguous primary web evidence is required.")
        for item in self.observations:
            if (item.sensor_id, item.device_id) != (self.sensor_id, self.device_id):
                raise ThreatError("Web evidence identity mismatch.")
            if len(ids) > 1 and (self.primary.context is None or item.context != self.primary.context):
                raise ThreatError("Web evidence context mismatch.")
        object.__setattr__(self, "hostname", normalize_domain(self.hostname))
        if self.hostname != self.primary.hostname:
            raise ThreatError("Web hostname mismatch.")
        for value in (self.reason, self.rule_id, self.rule_version):
            if not isinstance(value, str) or not value.strip():
                raise ThreatError("Web rule provenance is required.")
        object.__setattr__(self, "first_seen", utc(self.first_seen))

    @property
    def primary(self):
        return next(e for e in self.observations if e.observation_id == self.primary_observation_id)

    @property
    def evidence_type(self):
        return EvidenceType.WEB_DETECTION

    def snapshot(self):
        return {"evidence_id": self.evidence_id, "detection_type": self.detection_type,
                "state": "REVIEW", "confidence": "MEDIUM",
                "severity": "MEDIUM" if self.detection_type in {"CROSS_DOMAIN_LOGIN_REDIRECT", "SUSPICIOUS_DOWNLOAD_FLOW"} else "LOW",
                "sensor_id": self.sensor_id, "device_id": self.device_id,
                "primary_observation_id": self.primary_observation_id, "hostname": self.hostname,
                "reason": self.reason, "rule_id": self.rule_id, "rule_version": self.rule_version,
                "first_seen": self.first_seen.isoformat(),
                "observations": [e.snapshot() for e in self.observations]}


@dataclass(frozen=True)
class ThreatDetection:
    threat_type: ThreatType
    state: ThreatState
    severity: FindingSeverity
    confidence: FindingConfidence
    evidence: tuple[SSHThreatEvidence | WebThreatEvidence, ...]
    primary_evidence_id: int
    anchor_id: int
    reason: str
    recommendation: str
    rule_id: str
    rule_version: str
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self):
        for name, enum in (("threat_type", ThreatType), ("state", ThreatState),
                           ("severity", FindingSeverity), ("confidence", FindingConfidence)):
            object.__setattr__(self, name, enum(getattr(self, name)))
        if self.severity not in {FindingSeverity.LOW, FindingSeverity.MEDIUM, FindingSeverity.HIGH}:
            raise ThreatError("Invalid threat severity.")
        positive_id(self.primary_evidence_id)
        positive_id(self.anchor_id)
        expected = WebThreatEvidence if self.threat_type == ThreatType.WEB_CREDENTIAL_FLOW_THREAT else SSHThreatEvidence
        if not isinstance(self.evidence, tuple) or not self.evidence or not all(isinstance(e, expected) for e in self.evidence):
            raise ThreatError("Immutable source-specific evidence is required.")
        ids = [e.evidence_id for e in self.evidence]
        if len(ids) != len(set(ids)) or self.primary_evidence_id not in ids:
            raise ThreatError("Unambiguous primary evidence is required.")
        if expected is SSHThreatEvidence:
            if len({e.source_ip for e in self.evidence}) != 1 or self.anchor_id != self.primary_evidence_id:
                raise ThreatError("Authentication evidence identity mismatch.")
        else:
            for item in self.evidence:
                if (item.sensor_id, item.device_id) != (self.primary.sensor_id, self.primary.device_id):
                    raise ThreatError("Web evidence identity mismatch.")
                if len(ids) > 1 and (self.primary.primary.context is None or item.primary.context != self.primary.primary.context):
                    raise ThreatError("Explicit matching web context is required.")
            if self.anchor_id != self.primary.primary_observation_id:
                raise ThreatError("Invalid web flow anchor.")
        for value in (self.reason, self.recommendation, self.rule_id, self.rule_version):
            if not isinstance(value, str) or not value.strip():
                raise ThreatError("Threat explanation and rule identity are required.")
        for name in ("first_seen", "last_seen"):
            object.__setattr__(self, name, utc(getattr(self, name)))
        if self.last_seen < self.first_seen:
            raise ThreatError("Threat timestamps are out of order.")

    @property
    def primary(self):
        return next(e for e in self.evidence if e.evidence_id == self.primary_evidence_id)

    @property
    def source_ip(self):
        return self.primary.source_ip if isinstance(self.primary, SSHThreatEvidence) else None

    @property
    def sensor_id(self):
        return self.primary.sensor_id if isinstance(self.primary, WebThreatEvidence) else None

    @property
    def device_id(self):
        return self.primary.device_id if isinstance(self.primary, WebThreatEvidence) else None

    @property
    def hostname(self):
        return self.primary.hostname if isinstance(self.primary, WebThreatEvidence) else None

    @property
    def stable_key(self):
        identity = [self.threat_type.value, self.rule_id, self.rule_version, self.source_ip,
                    self.sensor_id, self.device_id, self.anchor_id]
        return "threat:" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
