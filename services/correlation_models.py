"""Immutable relationship records and fixed, privacy-minimal entity projections."""
import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum

from services.finding_models import FindingConfidence, FindingSeverity
from services.telemetry_models import normalize_domain
from services.threat_models import positive_id, ssh_time
from services.web_detection_models import utc


class CorrelationError(ValueError):
    pass


class EntityType(str, Enum):
    THREAT = "THREAT"
    WEB_DETECTION = "WEB_DETECTION"
    FINDING = "FINDING"
    CHANGE = "CHANGE"
    SSH_EVENT = "SSH_EVENT"
    CVE_MATCH = "CVE_MATCH"


class CorrelationType(str, Enum):
    SSH_AUTH_ACTIVITY_PATTERN = "SSH_AUTH_ACTIVITY_PATTERN"
    WEB_CREDENTIAL_ACTIVITY_CHAIN = "WEB_CREDENTIAL_ACTIVITY_CHAIN"


class CorrelationState(str, Enum):
    RELATED = "RELATED"
    PATTERN = "PATTERN"
    CHAIN_REVIEW = "CHAIN_REVIEW"


@dataclass(frozen=True)
class CorrelationEntity:
    entity_type: EntityType
    entity_id: int
    signal_type: str
    state: str
    severity: FindingSeverity
    confidence: FindingConfidence
    entity_timestamp: datetime
    first_seen: datetime
    rule_id: str
    rule_version: str
    reason: str
    source_evidence_type: str
    source_evidence_id: int
    device_id: int | None = None
    sensor_id: int | None = None
    source_ip: str | None = None
    hostname: str | None = None
    browser_session_id: str | None = None
    tab_id: str | None = None
    primary_observation_id: int | None = None
    observation_ids: tuple[int, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "entity_type", EntityType(self.entity_type))
        if self.entity_type not in {EntityType.THREAT, EntityType.WEB_DETECTION}:
            raise CorrelationError("This entity category is deferred.")
        positive_id(self.entity_id)
        positive_id(self.source_evidence_id)
        for name in ("device_id", "sensor_id", "primary_observation_id"):
            if getattr(self, name) is not None:
                positive_id(getattr(self, name))
        for name, enum in (("severity", FindingSeverity), ("confidence", FindingConfidence)):
            object.__setattr__(self, name, enum(getattr(self, name)))
        object.__setattr__(self, "entity_timestamp", ssh_time(self.entity_timestamp))
        object.__setattr__(self, "first_seen", utc(self.first_seen))
        for name in ("signal_type", "state", "rule_id", "rule_version", "reason"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise CorrelationError("Entity provenance is required.")
        if self.source_evidence_type not in {"SSH_EVENT", "WEB_DETECTION", "WEB_OBSERVATION"}:
            raise CorrelationError("Invalid source evidence category.")
        if self.source_ip is not None:
            object.__setattr__(self, "source_ip", str(ipaddress.ip_address(self.source_ip)))
        if self.hostname is not None:
            object.__setattr__(self, "hostname", normalize_domain(self.hostname))
        for name in ("browser_session_id", "tab_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise CorrelationError("Context IDs must be explicit nonempty strings.")
        if not isinstance(self.observation_ids, tuple):
            raise CorrelationError("Observation identities must be immutable.")
        for value in self.observation_ids:
            positive_id(value)
        object.__setattr__(self, "observation_ids", tuple(sorted(set(self.observation_ids))))
        if self.primary_observation_id is not None and self.primary_observation_id not in self.observation_ids:
            raise CorrelationError("Primary observation must be in the evidence set.")

    @property
    def identity(self):
        return self.entity_type.value, self.entity_id

    @property
    def web_context(self):
        if self.sensor_id is None or self.browser_session_id is None:
            return None
        return self.sensor_id, self.device_id, self.browser_session_id, self.tab_id

    def snapshot(self):
        result = asdict(self)
        for name in ("entity_type", "severity", "confidence"):
            result[name] = getattr(self, name).value
        result["entity_timestamp"] = self.entity_timestamp.isoformat()
        result["first_seen"] = self.first_seen.isoformat()
        return result


@dataclass(frozen=True)
class Correlation:
    correlation_type: CorrelationType
    state: CorrelationState
    severity: FindingSeverity
    confidence: FindingConfidence
    primary_entity_type: EntityType
    primary_entity_id: int
    entities: tuple[CorrelationEntity, ...]
    reason: str
    rule_id: str
    rule_version: str
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self):
        for name, enum in (("correlation_type", CorrelationType), ("state", CorrelationState),
                           ("severity", FindingSeverity), ("confidence", FindingConfidence),
                           ("primary_entity_type", EntityType)):
            object.__setattr__(self, name, enum(getattr(self, name)))
        positive_id(self.primary_entity_id)
        if not isinstance(self.entities, tuple) or len(self.entities) < 2 or not all(isinstance(e, CorrelationEntity) for e in self.entities):
            raise CorrelationError("At least two immutable typed entities are required.")
        identities = [e.identity for e in self.entities]
        if len(set(identities)) != len(identities) or (self.primary_entity_type.value, self.primary_entity_id) not in identities:
            raise CorrelationError("Entity identities must be unique and include the primary.")
        object.__setattr__(self, "entities", tuple(sorted(self.entities, key=lambda e: e.identity)))
        if self.severity != FindingSeverity.MEDIUM:
            raise CorrelationError("Version 1 correlations use bounded MEDIUM severity.")
        if self.correlation_type == CorrelationType.SSH_AUTH_ACTIVITY_PATTERN:
            if self.state != CorrelationState.PATTERN or self.confidence != FindingConfidence.HIGH:
                raise CorrelationError("Invalid SSH pattern interpretation.")
            if any(e.entity_type != EntityType.THREAT or not e.source_ip or e.source_ip != self.primary.source_ip
                   or (e.device_id, e.sensor_id) != (self.primary.device_id, self.primary.sensor_id) for e in self.entities):
                raise CorrelationError("SSH sources and concrete identities must match.")
        else:
            if self.state != CorrelationState.CHAIN_REVIEW or self.confidence != FindingConfidence.MEDIUM:
                raise CorrelationError("Invalid web chain interpretation.")
            if self.primary.web_context is None or any(e.web_context != self.primary.web_context for e in self.entities):
                raise CorrelationError("Explicit matching web context is required.")
        for value in (self.reason, self.rule_id, self.rule_version):
            if not isinstance(value, str) or not value.strip():
                raise CorrelationError("Correlation explanation and rule identity are required.")
        for name in ("first_seen", "last_seen"):
            object.__setattr__(self, name, utc(getattr(self, name)))
        if self.last_seen < self.first_seen:
            raise CorrelationError("Evaluation timestamps are out of order.")

    @property
    def primary(self):
        return next(e for e in self.entities if e.identity == (self.primary_entity_type.value, self.primary_entity_id))

    @property
    def stable_key(self):
        context = (self.primary.source_ip, self.primary.sensor_id, self.primary.device_id,
                   self.primary.browser_session_id, self.primary.tab_id)
        identity = [self.correlation_type.value, self.rule_id, self.rule_version, context,
                    sorted(e.identity for e in self.entities)]
        return "correlation:" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
