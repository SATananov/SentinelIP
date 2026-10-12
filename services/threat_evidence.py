"""Allowlisted adapters for persisted source evidence, without raw log messages."""
import json

from services.threat_models import SSHThreatEvidence, WebThreatEvidence, ThreatError
from services.web_detection_models import WebEvidence

SSH_COLUMNS = "id, source_ip, username, event_type, event_count, timestamp"
WEB_COLUMNS = """id, detection_type, state, severity, confidence, sensor_id, device_id,
    primary_observation_id, hostname, reason, structured_evidence, rule_id, rule_version, first_seen"""
MAX_SNAPSHOT_SIZE = 2_000_000
MAX_OBSERVATIONS = 1000


def ssh_from_row(row):
    return SSHThreatEvidence(row["id"], row["source_ip"], row["username"], row["event_type"],
                             row["event_count"], row["timestamp"])


def web_from_row(row):
    if row["primary_observation_id"] is None:
        raise ThreatError("Web detection primary observation reference is no longer available.")
    expected_severity = "MEDIUM" if row["detection_type"] in {"CROSS_DOMAIN_LOGIN_REDIRECT", "SUSPICIOUS_DOWNLOAD_FLOW"} else "LOW"
    if (row["state"] != "REVIEW" or row["confidence"] != "MEDIUM"
            or row["severity"] != expected_severity):
        raise ThreatError("Only conservative persisted web reviews are supported.")
    text = row["structured_evidence"]
    if not isinstance(text, str) or len(text) > MAX_SNAPSHOT_SIZE:
        raise ThreatError("Web evidence snapshot exceeds the supported limit.")
    try:
        data = json.loads(text)
        if not isinstance(data, list) or not 1 <= len(data) <= MAX_OBSERVATIONS:
            raise ValueError
        names = WebEvidence.__dataclass_fields__
        observations = tuple(WebEvidence(**{name: item[name] for name in names}) for item in data)
        return WebThreatEvidence(
            evidence_id=row["id"], detection_type=row["detection_type"], sensor_id=row["sensor_id"],
            device_id=row["device_id"], primary_observation_id=row["primary_observation_id"],
            hostname=row["hostname"], reason=row["reason"], observations=observations,
            rule_id=row["rule_id"], rule_version=row["rule_version"], first_seen=row["first_seen"],
        )
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ThreatError("Invalid persisted web detection evidence.") from None
