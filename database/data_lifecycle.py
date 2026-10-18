"""Read-only inventory and retention preview for the local operator."""

import json
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection
from services.finding_models import FindingConfidence, FindingSeverity
from services.web_detection_models import (
    WebDetection, WebDetectionState, WebDetectionType, WebEvidence,
)


ACTIVE = "ACTIVE_RETENTION_POLICY"
UNDEFINED = "POLICY_UNDEFINED"
PRESERVE = "PRESERVE"
TRANSIENT = "TRANSIENT_INTERNAL"
MAX_CLEANUP_BATCH = 100
_CLEANUP_TABLES = {
    "DNS_OBSERVATIONS": "dns_observations",
    "WEB_OBSERVATIONS": "web_observations",
}

# Product/domain order is intentionally stable for the operator preview.
# Grouped inventory/history classes count the listed implementation tables.
_CLASS_QUERIES = (
    ("LEGACY_EVENTS", UNDEFINED, "SELECT COUNT(*) FROM events"),
    ("NETWORKS", PRESERVE, "SELECT COUNT(*) FROM networks"),
    ("DEVICES", PRESERVE, "SELECT COUNT(*) FROM devices"),
    ("DEVICE_OBSERVATIONS", UNDEFINED,
     "SELECT (SELECT COUNT(*) FROM device_observations) + (SELECT COUNT(*) FROM scope_device_observations)"),
    ("INVENTORY_HISTORY", UNDEFINED,
     "SELECT (SELECT COUNT(*) FROM ports) + (SELECT COUNT(*) FROM port_observations) + "
     "(SELECT COUNT(*) FROM services) + (SELECT COUNT(*) FROM service_observations) + "
     "(SELECT COUNT(*) FROM changes) + (SELECT COUNT(*) FROM findings) + (SELECT COUNT(*) FROM cve_matches)"),
    ("CVE_CATALOG", PRESERVE, "SELECT COUNT(*) FROM cve_records"),
    ("TELEMETRY_SENSORS", PRESERVE, "SELECT COUNT(*) FROM telemetry_sensors"),
    ("DNS_OBSERVATIONS", ACTIVE, "SELECT COUNT(*) FROM dns_observations"),
    ("WEB_OBSERVATIONS", ACTIVE, "SELECT COUNT(*) FROM web_observations"),
    ("WEB_DETECTIONS", UNDEFINED,
     "SELECT (SELECT COUNT(*) FROM web_detections) + (SELECT COUNT(*) FROM web_detection_observations)"),
    ("THREAT_DETECTIONS", UNDEFINED,
     "SELECT (SELECT COUNT(*) FROM threat_detections) + (SELECT COUNT(*) FROM threat_evidence)"),
    ("THREAT_CORRELATIONS", UNDEFINED,
     "SELECT (SELECT COUNT(*) FROM correlations) + (SELECT COUNT(*) FROM correlation_entities)"),
    ("LEGACY_INCIDENTS", UNDEFINED,
     "SELECT (SELECT COUNT(*) FROM incidents) + (SELECT COUNT(*) FROM incident_correlations)"),
    ("PERIMETER_EVENTS", UNDEFINED, "SELECT COUNT(*) FROM perimeter_events"),
    ("PERIMETER_DETECTIONS", UNDEFINED, "SELECT COUNT(*) FROM perimeter_detections"),
    ("PERIMETER_POLICY_CORRELATIONS", UNDEFINED, "SELECT COUNT(*) FROM perimeter_policy_correlations"),
    ("PERIMETER_HOST_CORRELATIONS", UNDEFINED, "SELECT COUNT(*) FROM perimeter_host_correlations"),
    ("EXTERNAL_EXPOSURES", UNDEFINED, "SELECT COUNT(*) FROM external_exposures"),
    ("EXTERNAL_EXPOSURE_OBSERVATIONS", UNDEFINED, "SELECT COUNT(*) FROM external_exposure_observations"),
    ("EXTERNAL_EXPOSURE_CHANGES", UNDEFINED, "SELECT COUNT(*) FROM external_exposure_changes"),
    ("EXTERNAL_EXPOSURE_ASSESSMENTS", UNDEFINED,
     "SELECT (SELECT COUNT(*) FROM external_exposure_policies) + "
     "(SELECT COUNT(*) FROM external_exposure_assessments) + "
     "(SELECT COUNT(*) FROM external_exposure_classifications) + "
     "(SELECT COUNT(*) FROM external_exposure_presence)"),
    ("REMOTE_SENSOR_TASKS", UNDEFINED, "SELECT COUNT(*) FROM remote_sensor_tasks"),
    ("REMOTE_SENSORS", PRESERVE, "SELECT COUNT(*) FROM remote_sensors"),
    ("ENROLLMENT_RECORDS", UNDEFINED, "SELECT COUNT(*) FROM sensor_enrollment_tokens"),
    ("SITES", PRESERVE, "SELECT COUNT(*) FROM sites"),
    ("SCOPES", PRESERVE,
     "SELECT (SELECT COUNT(*) FROM authorized_scopes) + (SELECT COUNT(*) FROM remote_scope_sites) + "
     "(SELECT COUNT(*) FROM network_scope_links) + (SELECT COUNT(*) FROM scope_cidr_addresses) + "
     "(SELECT COUNT(*) FROM scope_hostname_addresses)"),
    ("SENSOR_ASSIGNMENTS", PRESERVE, "SELECT COUNT(*) FROM sensor_scope_assignments"),
    ("INCIDENT_REVIEWS", PRESERVE, "SELECT COUNT(*) FROM incident_reviews"),
    ("REVIEW_EVIDENCE_LINKS", PRESERVE, "SELECT COUNT(*) FROM incident_review_evidence"),
    ("REVIEW_NOTES", PRESERVE, "SELECT COUNT(*) FROM incident_review_notes"),
    ("REVIEW_TIMELINE", PRESERVE, "SELECT COUNT(*) FROM incident_review_events"),
    ("SENSOR_TRANSPORT_NONCES", TRANSIENT, "SELECT COUNT(*) FROM sensor_transport_nonces"),
    ("SCHEMA_MIGRATIONS", PRESERVE, "SELECT COUNT(*) FROM schema_migrations"),
)

_EMPTY_ITEM = {
    "total_rows": 0,
    "expired_rows": 0,
    "eligible_rows": 0,
    "protected_by_review": 0,
    "protected_by_dependency": 0,
    "policy_undefined": 0,
    "invalid_retention_rows": 0,
    "oldest_eligible_at": None,
}


def _utc_now():
    return datetime.now(timezone.utc)


def _iso_utc(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_retention(value):
    if value is None:
        return None, "null"
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError, OverflowError):
        return None, "invalid"
    # Legacy naive ISO timestamps have an unambiguous application convention: UTC.
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc), "valid"


def _complete_detection(row):
    """Validate that a detection retains its complete typed evidence snapshot."""
    try:
        raw = json.loads(row["structured_evidence"])
        if not isinstance(raw, list) or not raw:
            return None
        evidence = tuple(WebEvidence(**item) for item in raw if isinstance(item, dict))
        if len(evidence) != len(raw):
            return None
        detection = WebDetection(
            detection_type=WebDetectionType(row["detection_type"]),
            severity=FindingSeverity(row["severity"]),
            confidence=FindingConfidence(row["confidence"]),
            state=WebDetectionState(row["state"]),
            sensor_id=row["sensor_id"],
            device_id=row["device_id"],
            primary_observation_id=row["primary_observation_id"],
            hostname=row["hostname"],
            reason=row["reason"],
            evidence=evidence,
            rule_id=row["rule_id"],
            rule_version=row["rule_version"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
        return {item.observation_id for item in detection.evidence}
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OverflowError):
        return None


def _web_observation_dependency_status(connection, observation_ids):
    """Return observation IDs having a detection without a complete snapshot."""
    protected = set()
    seen = set()

    def inspect(row, observation_id):
        key = (row["id"], observation_id)
        if key in seen:
            return
        seen.add(key)
        snapshot_ids = _complete_detection(row)
        if snapshot_ids is None or observation_id not in snapshot_ids:
            protected.add(observation_id)

    # There is no standalone index on primary_observation_id, so scan detections once.
    primary_rows = connection.execute(
        """SELECT id, detection_type, severity, confidence, state, sensor_id,
                  device_id, primary_observation_id, hostname, reason, structured_evidence,
                  rule_id, rule_version, first_seen, last_seen
           FROM web_detections"""
    )
    for row in primary_rows:
        observation_id = row["primary_observation_id"]
        if observation_id in observation_ids:
            inspect(row, observation_id)

    # The explicit observation link has an index; query it in SQLite-safe batches.
    ordered_ids = sorted(observation_ids)
    for start in range(0, len(ordered_ids), 400):
        chunk = ordered_ids[start:start + 400]
        marks = ",".join("?" for _ in chunk)
        rows = connection.execute(
            f"""SELECT d.id, d.detection_type, d.severity, d.confidence, d.state, d.sensor_id,
                       d.device_id, d.primary_observation_id, d.hostname, d.reason,
                       d.structured_evidence, d.rule_id, d.rule_version, d.first_seen,
                       d.last_seen, l.observation_id AS linked_observation_id
                FROM web_detection_observations l
                JOIN web_detections d ON d.id = l.detection_id
                WHERE l.observation_id IN ({marks})""",
            chunk,
        )
        for row in rows:
            if row["linked_observation_id"] is not None:
                inspect(row, row["linked_observation_id"])
    return protected


# Canonical policy used by both the informational 18B preview and destructive
# 18C cleanup. Keep snapshot validation and dependency classification here.
def web_observation_protected_by_dependency(connection, observation_ids):
    return _web_observation_dependency_status(connection, observation_ids)


def _active_observation_item(connection, data_class, table, evaluated_at):
    item = {"data_class": data_class, "policy_state": ACTIVE, **_EMPTY_ITEM}
    item["total_rows"] = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    retention_values = connection.execute(f"SELECT id, retention_until FROM {table}")
    eligible_ids = set()
    eligible_dates = {}
    for row_id, raw_deadline in retention_values:
        deadline, status = _parse_retention(raw_deadline)
        if status == "null":
            item["policy_undefined"] += 1
        elif status == "invalid":
            item["invalid_retention_rows"] += 1
        elif deadline <= evaluated_at:
            item["expired_rows"] += 1
            eligible_ids.add(row_id)
            eligible_dates[row_id] = deadline
    if table == "web_observations" and eligible_ids:
        protected = web_observation_protected_by_dependency(connection, eligible_ids)
        item["protected_by_dependency"] = len(protected)
        eligible_ids.difference_update(protected)
        eligible_dates = {row_id: deadline for row_id, deadline in eligible_dates.items()
                          if row_id in eligible_ids}
    item["eligible_rows"] = len(eligible_ids)
    if eligible_dates:
        item["oldest_eligible_at"] = _iso_utc(min(eligible_dates.values()))
    return item


def _classify_counts(connection):
    items = []
    for data_class, policy_state, sql in _CLASS_QUERIES:
        item = {"data_class": data_class, "policy_state": policy_state, **_EMPTY_ITEM}
        item["total_rows"] = connection.execute(sql).fetchone()[0]
        if policy_state == UNDEFINED:
            item["policy_undefined"] = item["total_rows"]
        items.append(item)
    return items


def preview_data_lifecycle(db_path=DB_PATH, evaluated_at=None):
    evaluated_at = evaluated_at or _utc_now()
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluated_at must be timezone-aware")
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        items = _classify_counts(connection)
        by_name = {item["data_class"]: item for item in items}
        for name, table in (("DNS_OBSERVATIONS", "dns_observations"),
                            ("WEB_OBSERVATIONS", "web_observations")):
            by_name[name].update(_active_observation_item(connection, name, table, evaluated_at))
        return {"evaluated_at": _iso_utc(evaluated_at), "items": items}


def cleanup_data_lifecycle(data_class, db_path=DB_PATH, evaluated_at=None):
    """Delete one bounded batch of expired DNS or snapshot-safe web observations."""
    if data_class not in _CLEANUP_TABLES:
        raise ValueError("Unsupported data class")
    table = _CLEANUP_TABLES[data_class]

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        evaluated_at = evaluated_at or _utc_now()
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        evaluated_at = evaluated_at.astimezone(timezone.utc)
        # Python's ISO parser defines the accepted timestamp forms, matching 18B.
        rows = connection.execute(
            f"SELECT id, retention_until FROM {table}"
        ).fetchall()
        expired = []
        for row in rows:
            deadline, status = _parse_retention(row["retention_until"])
            if status == "valid" and deadline <= evaluated_at:
                expired.append((row["id"], deadline, row["retention_until"]))

        protected_ids = set()
        if data_class == "WEB_OBSERVATIONS" and expired:
            protected_ids = web_observation_protected_by_dependency(
                connection, {row_id for row_id, _, _ in expired}
            )
        eligible = [row for row in expired if row[0] not in protected_ids]
        eligible_before = len(eligible)
        # Equivalent to julianday(deadline), then id; normalized aware datetimes
        # preserve chronological ordering across offsets and naive-UTC legacy values.
        selected = sorted(eligible, key=lambda row: (row[1], row[0]))[:MAX_CLEANUP_BATCH]
        selected_protected = set()
        if data_class == "WEB_OBSERVATIONS" and selected:
            selected_protected = web_observation_protected_by_dependency(
                connection, {row_id for row_id, _, _ in selected}
            )

        deleted_count = 0
        for row_id, _, _ in selected:
            if row_id in selected_protected:
                continue
            # Explicitly revalidate presence and expiry before deleting this ID.
            current = connection.execute(
                f"SELECT retention_until FROM {table} WHERE id = ?", (row_id,)
            ).fetchone()
            if current is None:
                continue
            deadline, status = _parse_retention(current["retention_until"])
            if status != "valid" or deadline > evaluated_at:
                continue
            # Dependency safety was classified from current relations under this
            # same IMMEDIATE transaction; no competing writer can change it here.
            cursor = connection.execute(f"DELETE FROM {table} WHERE id = ?", (row_id,))
            deleted_count += cursor.rowcount

        remaining_rows = connection.execute(
            f"SELECT id, retention_until FROM {table}"
        ).fetchall()
        remaining_expired = set()
        for row in remaining_rows:
            deadline, status = _parse_retention(row["retention_until"])
            if status == "valid" and deadline <= evaluated_at:
                remaining_expired.add(row["id"])
        remaining_protected = set()
        if data_class == "WEB_OBSERVATIONS" and remaining_expired:
            remaining_protected = web_observation_protected_by_dependency(
                connection, remaining_expired
            )
        remaining_eligible = len(remaining_expired - remaining_protected)
        protected_count = len(remaining_protected)
        connection.commit()

    return {
        "data_class": data_class,
        "evaluated_at": _iso_utc(evaluated_at),
        "eligible_before": eligible_before,
        "deleted_count": deleted_count,
        "protected_count": protected_count,
        "remaining_eligible": remaining_eligible,
        "batch_limit": MAX_CLEANUP_BATCH,
    }

