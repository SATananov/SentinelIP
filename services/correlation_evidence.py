"""Bounded, allowlisted projections of persisted entities and primary snapshots."""
import json
from services.correlation_models import CorrelationEntity, CorrelationError, EntityType
from services.threat_evidence import WEB_COLUMNS, web_from_row
from services.threat_models import SSHThreatEvidence

THREAT_COLUMNS = """id, threat_type, state, severity, confidence, source_ip, sensor_id, device_id,
    hostname, primary_evidence_type, primary_evidence_id, reason, rule_id, rule_version, first_seen"""
MAX_SNAPSHOT_SIZE = 2_000_000


def _json(text):
    if not isinstance(text, str) or len(text) > MAX_SNAPSHOT_SIZE:
        raise CorrelationError("Source snapshot exceeds the correlation limit.")
    try:
        result = json.loads(text)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, RecursionError):
        raise CorrelationError("Invalid primary evidence snapshot.") from None


def _web_projection(row, web, entity_type):
    primary = web.primary
    return CorrelationEntity(
        entity_type=entity_type, entity_id=row["id"],
        signal_type=row["threat_type"] if entity_type == EntityType.THREAT else web.detection_type,
        state=row["state"], severity=row["severity"], confidence=row["confidence"],
        entity_timestamp=primary.observed_at, first_seen=row["first_seen"],
        rule_id=row["rule_id"], rule_version=row["rule_version"], reason=row["reason"],
        source_evidence_type="WEB_DETECTION" if entity_type == EntityType.THREAT else "WEB_OBSERVATION",
        source_evidence_id=web.evidence_id if entity_type == EntityType.THREAT else web.primary_observation_id,
        device_id=web.device_id, sensor_id=web.sensor_id, hostname=web.hostname,
        browser_session_id=primary.browser_session_id, tab_id=primary.tab_id,
        primary_observation_id=web.primary_observation_id,
        observation_ids=tuple(e.observation_id for e in web.observations),
    )


def load_entity(connection, entity_type, entity_id):
    kind = EntityType(entity_type)
    if kind == EntityType.WEB_DETECTION:
        row = connection.execute(f"SELECT {WEB_COLUMNS} FROM web_detections WHERE id=?", (entity_id,)).fetchone()
        if row is None:
            raise CorrelationError("Persisted web detection not found.")
        return _web_projection(row, web_from_row(row), kind)
    if kind != EntityType.THREAT:
        raise CorrelationError("Entity category is deferred.")
    row = connection.execute(f"SELECT {THREAT_COLUMNS} FROM threat_detections WHERE id=?", (entity_id,)).fetchone()
    if row is None:
        raise CorrelationError("Persisted threat not found.")
    source = connection.execute("""SELECT evidence_snapshot FROM threat_evidence
        WHERE threat_id=? AND evidence_type=? AND evidence_id=?""",
        (entity_id, row["primary_evidence_type"], row["primary_evidence_id"])).fetchone()
    if source is None:
        raise CorrelationError("Threat primary provenance is unavailable.")
    data = _json(source[0])
    try:
        if row["primary_evidence_type"] == "SSH_EVENT":
            event = SSHThreatEvidence(**{name: data[name] for name in SSHThreatEvidence.__dataclass_fields__})
            if event.evidence_id != row["primary_evidence_id"] or event.source_ip != row["source_ip"]:
                raise ValueError
            if row["threat_type"] not in {"SSH_BRUTE_FORCE_THREAT", "SUSPICIOUS_AUTH_ACTIVITY"}:
                raise ValueError
            return CorrelationEntity(
                entity_type=kind, entity_id=entity_id, signal_type=row["threat_type"], state=row["state"],
                severity=row["severity"], confidence=row["confidence"], entity_timestamp=event.timestamp,
                first_seen=row["first_seen"], rule_id=row["rule_id"], rule_version=row["rule_version"],
                reason=row["reason"], source_evidence_type="SSH_EVENT", source_evidence_id=event.evidence_id,
                source_ip=event.source_ip, device_id=row["device_id"], sensor_id=row["sensor_id"],
            )
        web_row = {**data, "id": data["evidence_id"], "structured_evidence": json.dumps(data["observations"])}
        web = web_from_row(web_row)
        if (web.evidence_id != row["primary_evidence_id"] or row["threat_type"] != "WEB_CREDENTIAL_FLOW_THREAT"
                or (web.sensor_id, web.device_id, web.hostname) != (row["sensor_id"], row["device_id"], row["hostname"])):
            raise ValueError
        return _web_projection(row, web, kind)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise CorrelationError("Threat primary snapshot is inconsistent or invalid.") from None
