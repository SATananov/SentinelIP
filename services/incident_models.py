"""Explicit investigation records built from persisted correlations.

An Incident is an investigation object, not proof of compromise, malware,
phishing, attacker identity, or successful intrusion.
"""

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from services.telemetry_models import normalize_domain
from services.threat_models import positive_id, ssh_time
from services.web_detection_models import utc


class IncidentError(ValueError):
    pass


class IncidentType(str, Enum):
    AUTHENTICATION_REVIEW = "AUTHENTICATION_REVIEW"
    WEB_ACTIVITY_REVIEW = "WEB_ACTIVITY_REVIEW"
    MULTI_SIGNAL_REVIEW = "MULTI_SIGNAL_REVIEW"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"


class IncidentPriority(str, Enum):
    MEDIUM = "MEDIUM"


@dataclass(frozen=True)
class IncidentCorrelation:
    correlation_id: int
    correlation_type: str
    state: str
    severity: str
    confidence: str
    first_seen: datetime
    last_seen: datetime
    reason: str
    rule_id: str
    rule_version: str
    entity_refs: tuple[tuple[str, int], ...]
    device_id: int | None = None
    sensor_id: int | None = None
    source_ip: str | None = None
    hostname: str | None = None

    def __post_init__(self):
        positive_id(self.correlation_id)
        if self.correlation_type not in {"SSH_AUTH_ACTIVITY_PATTERN", "WEB_CREDENTIAL_ACTIVITY_CHAIN"}:
            raise IncidentError("Unsupported correlation type.")
        if self.severity != "MEDIUM":
            raise IncidentError("Incident Model 01 accepts bounded MEDIUM correlations.")
        if self.confidence not in {"MEDIUM", "HIGH"}:
            raise IncidentError("Unsupported correlation confidence.")
        if self.correlation_type == "SSH_AUTH_ACTIVITY_PATTERN":
            if self.state != "PATTERN" or self.confidence != "HIGH" or not self.source_ip:
                raise IncidentError("Invalid SSH correlation interpretation.")
        else:
            if self.state != "CHAIN_REVIEW" or self.confidence != "MEDIUM" or self.sensor_id is None:
                raise IncidentError("Invalid web correlation interpretation.")
        object.__setattr__(self, "first_seen", ssh_time(self.first_seen))
        object.__setattr__(self, "last_seen", ssh_time(self.last_seen))
        if self.last_seen < self.first_seen:
            raise IncidentError("Correlation timestamps are out of order.")
        for value in (self.reason, self.rule_id, self.rule_version):
            if not isinstance(value, str) or not value.strip():
                raise IncidentError("Correlation provenance is required.")
        if self.device_id is not None:
            positive_id(self.device_id)
        if self.sensor_id is not None:
            positive_id(self.sensor_id)
        if self.source_ip is not None:
            object.__setattr__(self, "source_ip", str(ipaddress.ip_address(self.source_ip)))
        if self.hostname is not None:
            object.__setattr__(self, "hostname", normalize_domain(self.hostname))
        if not isinstance(self.entity_refs, tuple) or len(self.entity_refs) < 2:
            raise IncidentError("Correlation entity references are required.")
        normalized = []
        for item in self.entity_refs:
            if not isinstance(item, tuple) or len(item) != 2 or item[0] not in {"THREAT", "WEB_DETECTION"}:
                raise IncidentError("Invalid correlation entity reference.")
            positive_id(item[1])
            normalized.append((item[0], item[1]))
        if len(set(normalized)) != len(normalized):
            raise IncidentError("Correlation entity references must be unique.")
        object.__setattr__(self, "entity_refs", tuple(sorted(normalized)))

    def snapshot(self):
        return {
            "correlation_id": self.correlation_id,
            "correlation_type": self.correlation_type,
            "state": self.state,
            "severity": self.severity,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "reason": self.reason,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "device_id": self.device_id,
            "sensor_id": self.sensor_id,
            "source_ip": self.source_ip,
            "hostname": self.hostname,
            "entity_refs": [{"entity_type": kind, "entity_id": entity_id} for kind, entity_id in self.entity_refs],
        }


@dataclass(frozen=True)
class Incident:
    incident_type: IncidentType
    status: IncidentStatus
    priority: IncidentPriority
    primary_correlation_id: int
    correlations: tuple[IncidentCorrelation, ...]
    title: str
    reason: str
    recommendation: str
    rule_id: str
    rule_version: str
    opened_at: datetime

    def __post_init__(self):
        object.__setattr__(self, "incident_type", IncidentType(self.incident_type))
        object.__setattr__(self, "status", IncidentStatus(self.status))
        object.__setattr__(self, "priority", IncidentPriority(self.priority))
        positive_id(self.primary_correlation_id)
        if not isinstance(self.correlations, tuple) or not self.correlations or not all(isinstance(i, IncidentCorrelation) for i in self.correlations):
            raise IncidentError("At least one immutable correlation is required.")
        if len(self.correlations) > 25:
            raise IncidentError("Incident Model 01 correlation limit exceeded.")
        ids = [item.correlation_id for item in self.correlations]
        if len(set(ids)) != len(ids):
            raise IncidentError("Correlation identities must be unique.")
        object.__setattr__(self, "correlations", tuple(sorted(self.correlations, key=lambda i: i.correlation_id)))
        if self.primary_correlation_id not in ids:
            raise IncidentError("Primary correlation must belong to the incident.")
        if self.incident_type != derive_incident_type(self.correlations):
            raise IncidentError("Incident classification mismatch.")
        if self.status != IncidentStatus.OPEN:
            raise IncidentError("Incident Model 01 creates OPEN investigations only.")
        if self.priority != IncidentPriority.MEDIUM:
            raise IncidentError("Incident Model 01 uses bounded MEDIUM priority.")
        for value in (self.title, self.reason, self.recommendation, self.rule_id, self.rule_version):
            if not isinstance(value, str) or not value.strip():
                raise IncidentError("Incident explanation and provenance are required.")
        object.__setattr__(self, "opened_at", utc(self.opened_at))

    @property
    def first_seen(self):
        return min(item.first_seen for item in self.correlations)

    @property
    def last_seen(self):
        return max(item.last_seen for item in self.correlations)

    @property
    def stable_key(self):
        identity = [self.incident_type.value, self.rule_id, self.rule_version, sorted(i.correlation_id for i in self.correlations)]
        return "incident:" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()


def derive_incident_type(correlations):
    types = {item.correlation_type for item in correlations}
    if types == {"SSH_AUTH_ACTIVITY_PATTERN"}:
        return IncidentType.AUTHENTICATION_REVIEW
    if types == {"WEB_CREDENTIAL_ACTIVITY_CHAIN"}:
        return IncidentType.WEB_ACTIVITY_REVIEW
    return IncidentType.MULTI_SIGNAL_REVIEW


def build_incident(correlations, opened_at):
    if not isinstance(correlations, tuple):
        raise IncidentError("Immutable correlation collection is required.")
    if not correlations:
        raise IncidentError("At least one correlation is required.")
    ordered = tuple(sorted(correlations, key=lambda i: i.correlation_id))
    incident_type = derive_incident_type(ordered)
    if incident_type == IncidentType.AUTHENTICATION_REVIEW:
        title = "Authentication activity review"
        reason = ("Persisted authentication correlation evidence was explicitly opened for investigation. "
                  "This review does not establish an attacker identity, successful access, or host compromise.")
        recommendation = "Review the linked authentication evidence and verify whether the observed activity was expected."
    elif incident_type == IncidentType.WEB_ACTIVITY_REVIEW:
        title = "Web credential activity review"
        reason = ("Persisted web credential-flow correlation evidence was explicitly opened for investigation. "
                  "This review does not confirm phishing, malware, credential theft, or compromise.")
        recommendation = "Review the linked web evidence and verify whether the observed credential flow and related activity were expected."
    else:
        title = "Multi-signal security review"
        reason = ("Selected persisted correlations were explicitly grouped for investigation. Their inclusion in one review "
                  "does not establish causality, a common actor, compromise, or a confirmed attack.")
        recommendation = "Review each linked correlation and its original provenance before drawing any cross-signal conclusion."
    return Incident(
        incident_type=incident_type,
        status=IncidentStatus.OPEN,
        priority=IncidentPriority.MEDIUM,
        primary_correlation_id=ordered[0].correlation_id,
        correlations=ordered,
        title=title,
        reason=reason,
        recommendation=recommendation,
        rule_id="incident.explicit_review",
        rule_version="1",
        opened_at=opened_at,
    )
