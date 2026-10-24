"""Read-only inventory and retention preview for the local operator."""

import heapq
import ipaddress
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

from database.db import DB_PATH, get_connection
from database.management_audit import record_event
from services.finding_models import FindingConfidence, FindingSeverity
from services.web_detection_models import (
    WebDetection, WebDetectionState, WebDetectionType, WebEvidence,
)


ACTIVE = "ACTIVE_RETENTION_POLICY"
UNDEFINED = "POLICY_UNDEFINED"
PRESERVE = "PRESERVE"
TRANSIENT = "TRANSIENT_INTERNAL"
MAX_CLEANUP_BATCH = 100
LEGACY_EVENT_RETENTION_DAYS = 90
_CLEANUP_TABLES = {
    "DNS_OBSERVATIONS": "dns_observations",
    "WEB_OBSERVATIONS": "web_observations",
}

# Product/domain order is intentionally stable for the operator preview.
# Grouped inventory/history classes count the listed implementation tables.
_CLASS_QUERIES = (
    ("LEGACY_EVENTS", ACTIVE, None),
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


def _iso_local_naive(value):
    return value.isoformat()


def _local_wall_time(value):
    """Convert the lifecycle clock to the naive local form used by SSH events."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=None)
    return value.astimezone().replace(tzinfo=None)


_LEGACY_EVENT_CLASSIFICATION_SQL = """
    SELECT e.id,
           CASE WHEN typeof(e.timestamp)='text' AND length(CAST(e.timestamp AS BLOB))<=64
                THEN e.timestamp ELSE NULL END AS timestamp_value,
           typeof(e.timestamp) AS timestamp_type,
           CASE WHEN typeof(e.source_ip)='text' AND length(CAST(e.source_ip AS BLOB))<=45
                THEN e.source_ip ELSE NULL END AS source_ip_value,
           CASE WHEN typeof(e.username) IN ('null','text') THEN 1 ELSE 0 END AS username_valid,
           CASE WHEN typeof(e.event_type)='text' AND e.event_type IN
                ('LOGIN_FAILED','SSH_PREAUTH','LOGIN_SUCCESS','CONNECTION_CLOSED')
                THEN 1 ELSE 0 END AS event_type_valid,
           CASE WHEN typeof(e.severity)='text' AND e.severity IN ('INFO','WARNING','ALERT')
                THEN 1 ELSE 0 END AS severity_valid,
           CASE WHEN typeof(e.message)='text' THEN 1 ELSE 0 END AS message_valid,
           CASE WHEN typeof(e.event_count)='integer' AND e.event_count>0
                THEN 1 ELSE 0 END AS event_count_valid,
           EXISTS (SELECT 1 FROM threat_evidence te WHERE te.ssh_event_id=e.id)
                AS is_protected
    FROM events e
"""


def _parse_legacy_event_time(row):
    if row["timestamp_type"] != "text" or row["timestamp_value"] is None:
        return None
    raw = row["timestamp_value"]
    if not isinstance(raw, str) or len(raw) < 16 or raw[10] not in {"T", " "}:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    # The producer stores naive local wall-clock time. Offset-aware/corrupt
    # historical values are preserved rather than assigned guessed semantics.
    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        return None
    return parsed


def _legacy_event_row_valid(row, parsed_time):
    try:
        ipaddress.ip_address(row["source_ip_value"])
        source_ip_valid = True
    except (TypeError, ValueError):
        source_ip_valid = False
    return (
        row["id"] > 0
        and parsed_time is not None
        and source_ip_valid
        and row["username_valid"]
        and row["event_type_valid"]
        and row["severity_valid"]
        and row["message_valid"]
        and row["event_count_valid"]
    )


def _classify_legacy_events(connection, evaluated_at, *, select_limit=0):
    """Stream only classification metadata and retain at most select_limit IDs."""
    cutoff = evaluated_at - timedelta(days=LEGACY_EVENT_RETENTION_DAYS)
    stats = {
        "total_rows": 0,
        "expired_rows": 0,
        "eligible_rows": 0,
        "protected_rows": 0,
        "malformed_skipped_rows": 0,
        "future_skipped_rows": 0,
        "oldest_retained_at": None,
        "oldest_eligible_at": None,
    }

    def eligible_candidates():
        cursor = connection.execute(_LEGACY_EVENT_CLASSIFICATION_SQL)
        for row in cursor:
            stats["total_rows"] += 1
            parsed_time = _parse_legacy_event_time(row)
            if row["is_protected"]:
                stats["protected_rows"] += 1
            if not _legacy_event_row_valid(row, parsed_time):
                stats["malformed_skipped_rows"] += 1
                continue
            oldest = stats["oldest_retained_at"]
            if oldest is None or parsed_time < oldest:
                stats["oldest_retained_at"] = parsed_time
            if parsed_time > evaluated_at:
                stats["future_skipped_rows"] += 1
                continue
            if parsed_time <= cutoff:
                stats["expired_rows"] += 1
                if row["is_protected"]:
                    continue
                stats["eligible_rows"] += 1
                oldest_eligible = stats["oldest_eligible_at"]
                if oldest_eligible is None or parsed_time < oldest_eligible:
                    stats["oldest_eligible_at"] = parsed_time
                yield parsed_time, row["id"]

    if select_limit > 0:
        selected = heapq.nsmallest(
            select_limit, eligible_candidates(), key=lambda item: (item[0], item[1])
        )
    else:
        for _ in eligible_candidates():
            pass
        selected = []
    return stats, selected, cutoff


def _legacy_event_item(connection, evaluated_at):
    stats, _, cutoff = _classify_legacy_events(connection, evaluated_at)
    return {
        "data_class": "LEGACY_EVENTS",
        "policy_state": ACTIVE,
        **_EMPTY_ITEM,
        "total_rows": stats["total_rows"],
        "expired_rows": stats["expired_rows"],
        "eligible_rows": stats["eligible_rows"],
        "protected_by_dependency": stats["protected_rows"],
        "malformed_skipped_rows": stats["malformed_skipped_rows"],
        "future_skipped_rows": stats["future_skipped_rows"],
        "oldest_eligible_at": (
            _iso_local_naive(stats["oldest_eligible_at"])
            if stats["oldest_eligible_at"] is not None else None
        ),
        "oldest_retained_at": (
            _iso_local_naive(stats["oldest_retained_at"])
            if stats["oldest_retained_at"] is not None else None
        ),
        "retention_days": LEGACY_EVENT_RETENTION_DAYS,
        "evaluated_at_local": _iso_local_naive(evaluated_at),
        "cutoff_at_local": _iso_local_naive(cutoff),
        "max_delete_rows": MAX_CLEANUP_BATCH,
    }


def _cleanup_legacy_events(db_path, evaluated_at):
    with closing(get_connection(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        try:
            stats, selected, cutoff = _classify_legacy_events(
                connection, evaluated_at, select_limit=MAX_CLEANUP_BATCH
            )
            selected_ids = [row_id for _, row_id in selected]
            if selected_ids:
                marks = ",".join("?" for _ in selected_ids)
                newly_protected = {
                    row[0] for row in connection.execute(
                        f"SELECT ssh_event_id FROM threat_evidence "
                        f"WHERE ssh_event_id IN ({marks})", selected_ids
                    )
                }
                if newly_protected:
                    stats["protected_rows"] += len(newly_protected)
                    stats["eligible_rows"] -= len(newly_protected)
                    selected_ids = [row_id for row_id in selected_ids
                                    if row_id not in newly_protected]

            deleted_count = 0
            if selected_ids:
                marks = ",".join("?" for _ in selected_ids)
                cursor = connection.execute(
                    f"""DELETE FROM events
                        WHERE id IN ({marks})
                          AND NOT EXISTS (
                              SELECT 1 FROM threat_evidence te
                              WHERE te.ssh_event_id=events.id
                          )""",
                    selected_ids,
                )
                deleted_count = cursor.rowcount
                if deleted_count != len(selected_ids):
                    raise sqlite3.IntegrityError("Selected event set changed during cleanup.")

            # Management-audit schema currently permits DNS/web classes only.
            # Do not mislabel this cleanup or require a schema migration here.
            result = {
                "data_class": "LEGACY_EVENTS",
                "evaluated_at_local": _iso_local_naive(evaluated_at),
                "cutoff_at_local": _iso_local_naive(cutoff),
                "eligible_before": stats["eligible_rows"],
                "deleted_count": deleted_count,
                "remaining_eligible": stats["eligible_rows"] - deleted_count,
                "protected_count": stats["protected_rows"],
                "malformed_skipped_rows": stats["malformed_skipped_rows"],
                "future_skipped_rows": stats["future_skipped_rows"],
                "batch_limit": MAX_CLEANUP_BATCH,
            }
            connection.commit()
            return result
        except BaseException:
            connection.rollback()
            raise


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
        if sql is not None:
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
        by_name["LEGACY_EVENTS"].update(
            _legacy_event_item(connection, _local_wall_time(evaluated_at))
        )
        for name, table in (("DNS_OBSERVATIONS", "dns_observations"),
                            ("WEB_OBSERVATIONS", "web_observations")):
            by_name[name].update(_active_observation_item(connection, name, table, evaluated_at))
        return {"evaluated_at": _iso_utc(evaluated_at), "items": items}


def cleanup_data_lifecycle(data_class, db_path=DB_PATH, evaluated_at=None):
    """Delete one explicitly requested bounded lifecycle cleanup batch."""
    if data_class not in {*_CLEANUP_TABLES, "LEGACY_EVENTS"}:
        raise ValueError("Unsupported data class")
    if data_class == "LEGACY_EVENTS":
        evaluated_at = evaluated_at or _utc_now()
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return _cleanup_legacy_events(db_path, _local_wall_time(evaluated_at))
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
        evaluated_text = _iso_utc(evaluated_at)
        record_event(
            connection, event_type="DATA_LIFECYCLE_CLEANUP_EXECUTED",
            entity_type="DATA_LIFECYCLE", entity_id="DATA_LIFECYCLE",
            actor_type="LOCAL_OPERATOR", cleanup_data_class=data_class,
            cleanup_evaluated_at=evaluated_text, cleanup_eligible_before=eligible_before,
            cleanup_deleted_count=deleted_count, cleanup_protected_count=protected_count,
            cleanup_remaining_eligible=remaining_eligible,
            cleanup_batch_limit=MAX_CLEANUP_BATCH,
        )
        connection.commit()

    return {
        "data_class": data_class,
        "evaluated_at": evaluated_text,
        "eligible_before": eligible_before,
        "deleted_count": deleted_count,
        "protected_count": protected_count,
        "remaining_eligible": remaining_eligible,
        "batch_limit": MAX_CLEANUP_BATCH,
    }

