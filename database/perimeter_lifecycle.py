"""TEMP-backed dependency-aware retention for perimeter evidence."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone


PERIMETER_RETENTION_DAYS = 180
PERIMETER_MAX_COMPONENTS_PER_APPLY = 25
PERIMETER_FETCH_BATCH_SIZE = 128
MAX_MEMBERSHIP_JSON_BYTES = 8192
MAX_RECEIVED_AT_BYTES = 128
MAX_SQLITE_ID = 9_223_372_036_854_775_807

_PERIMETER_EVIDENCE_TYPES = {
    "PERIMETER_DETECTION": "DETECTION",
    "PERIMETER_POLICY_CORRELATION": "POLICY",
    "PERIMETER_HOST_CORRELATION": "HOST",
}
_ALL_EVIDENCE_TYPES = _PERIMETER_EVIDENCE_TYPES.keys() | {
    "EXTERNAL_EXPOSURE_CHANGE", "THREAT_DETECTION", "THREAT_CORRELATION", "WEB_DETECTION",
}
_TIMELINE_EVENT_TYPES = {
    "REVIEW_CREATED", "STATE_CHANGED", "REVIEW_CLOSED", "REVIEW_REOPENED",
    "PRIORITY_CHANGED", "CONFIDENCE_CHANGED", "DISPOSITION_CHANGED",
    "REVIEW_FIELD_CHANGED", "FINAL_SUMMARY_CHANGED", "ANALYST_NOTE_ADDED", "ANALYST_NOTE_CLEARED",
    "EVIDENCE_ATTACHED", "EVIDENCE_DETACHED",
}


def _iso_utc(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _aware_iso(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _strict_text(value):
    """Decode bounded SQLite text bytes without replacement or lossy coercion."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
    return value if isinstance(value, str) else None


def _drop_temp_tables(connection):
    for table in (
        "_pc_events", "_pc_derived", "_pc_members", "_pc_edges",
        "_pc_component_members", "_pc_refs", "_pc_protected",
        "_pc_component_stats", "_pc_derived_counts", "_pc_flags", "_pc_selected",
        "_pc_unassigned",
        "_pc_delete_events", "_pc_delete_detections", "_pc_delete_policy",
        "_pc_delete_hosts",
    ):
        connection.execute(f"DROP TABLE IF EXISTS temp.{table}")


def _create_temp_tables(connection):
    # Keep TEMP data in SQLite's temporary storage with a small page cache. These
    # settings apply only to this connection; TEMP files remain resource-consuming.
    connection.execute("PRAGMA temp_store = FILE")
    connection.execute("PRAGMA temp.cache_size = 200")
    _drop_temp_tables(connection)
    statements = (
        """CREATE TEMP TABLE _pc_events (
            event_id INTEGER PRIMARY KEY,
            site_id INTEGER,
            received_key TEXT,
            age_class TEXT NOT NULL,
            anomaly INTEGER NOT NULL DEFAULT 0,
            component_id INTEGER
        )""",
        """CREATE TEMP TABLE _pc_derived (
            kind TEXT NOT NULL,
            derived_id INTEGER NOT NULL,
            primary_event_id INTEGER,
            site_id INTEGER,
            component_id INTEGER,
            PRIMARY KEY (kind, derived_id)
        ) WITHOUT ROWID""",
        """CREATE TEMP TABLE _pc_members (
            kind TEXT NOT NULL,
            derived_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            PRIMARY KEY (kind, derived_id, event_id)
        ) WITHOUT ROWID""",
        """CREATE TEMP TABLE _pc_edges (
            src INTEGER NOT NULL,
            dst INTEGER NOT NULL,
            PRIMARY KEY (src, dst)
        ) WITHOUT ROWID""",
        """CREATE TEMP TABLE _pc_component_members (
            event_id INTEGER PRIMARY KEY,
            component_id INTEGER NOT NULL
        )""",
        "CREATE INDEX _pc_component_members_component ON _pc_component_members(component_id)",
        """CREATE TEMP TABLE _pc_refs (
            kind TEXT NOT NULL,
            derived_id INTEGER NOT NULL,
            PRIMARY KEY (kind, derived_id)
        ) WITHOUT ROWID""",
        "CREATE TEMP TABLE _pc_protected (component_id INTEGER PRIMARY KEY)",
        "CREATE TEMP TABLE _pc_selected (component_id INTEGER PRIMARY KEY)",
    )
    for statement in statements:
        connection.execute(statement)


def _event_age(raw, received_type, evaluated_at, cutoff):
    if received_type != "text":
        return None, "MALFORMED"
    raw = _strict_text(raw)
    if raw is None or len(raw.encode("utf-8")) > MAX_RECEIVED_AT_BYTES:
        return None, "MALFORMED"
    parsed = _aware_iso(raw)
    if parsed is None:
        return None, "MALFORMED"
    if parsed > evaluated_at:
        return parsed.isoformat(timespec="microseconds"), "FUTURE"
    if parsed <= cutoff:
        return parsed.isoformat(timespec="microseconds"), "ELIGIBLE"
    return parsed.isoformat(timespec="microseconds"), "NEWER"


def _stream_events(connection, evaluated_at, cutoff):
    cursor = connection.execute(
        """SELECT id, site_id,
                  CASE WHEN typeof(received_at)='text'
                         AND length(CAST(received_at AS BLOB)) <= ?
                       THEN CAST(received_at AS BLOB) END,
                  typeof(received_at)
           FROM perimeter_events ORDER BY id""",
        (MAX_RECEIVED_AT_BYTES,),
    )
    pending = []
    while True:
        rows = cursor.fetchmany(PERIMETER_FETCH_BATCH_SIZE)
        if not rows:
            break
        for event_id, site_id, received_at, received_type in rows:
            key, age_class = _event_age(received_at, received_type, evaluated_at, cutoff)
            if type(event_id) is not int or event_id <= 0 or type(site_id) is not int or site_id <= 0:
                age_class = "MALFORMED"
                site_id = None
            pending.append((event_id, site_id, key, age_class))
        connection.executemany(
            "INSERT INTO _pc_events(event_id,site_id,received_key,age_class) VALUES(?,?,?,?)",
            pending,
        )
        pending.clear()


def _parse_id_list(raw):
    raw = _strict_text(raw)
    if raw is None:
        return None
    try:
        values = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(values, list) or not values or len(values) > 256:
        return None
    if any(type(value) is not int or not 0 < value <= MAX_SQLITE_ID for value in values):
        return None
    if len(set(values)) != len(values):
        return None
    return values


def _insert_derived_members(connection, kind, cursor, *, membership_columns, has_primary=True):
    bad_rows = 0
    bad_localizable = []
    while True:
        rows = cursor.fetchmany(PERIMETER_FETCH_BATCH_SIZE)
        if not rows:
            break
        derived_batch = []
        member_batch = []
        for row in rows:
            derived_id = row[0]
            primary_raw = row[1] if has_primary else row[1]
            site_id = row[2]
            raws = row[3:3 + membership_columns]
            primary_id = primary_raw if type(primary_raw) is int and primary_raw > 0 else None
            if kind == "HOST":
                primary_id = primary_raw if type(primary_raw) is int and primary_raw > 0 else None
            derived_batch.append((kind, derived_id, primary_id, site_id if type(site_id) is int else None))

            parsed = [_parse_id_list(raw) for raw in raws]
            valid = all(values is not None for values in parsed)
            if valid and kind == "DETECTION":
                event_ids = parsed[0]
                detection_type, event_count = row[4:6]
                valid = (
                    primary_id is not None and primary_id in event_ids
                    and type(event_count) is int and event_count == len(event_ids)
                    and (detection_type == "INBOUND_ATTEMPT" and len(event_ids) == 1
                         or detection_type == "REPEATED_INBOUND_ATTEMPTS" and len(event_ids) >= 5)
                )
                memberships = event_ids if valid else []
            elif valid and kind == "POLICY":
                event_ids, allowed_ids, blocked_ids = parsed
                event_count, allow_count, blocked_count, primary_action = row[6:10]
                allowed_set, blocked_set = set(allowed_ids), set(blocked_ids)
                valid = (
                    primary_id is not None
                    and primary_id in event_ids
                    and not allowed_set.intersection(blocked_set)
                    and set(event_ids) == allowed_set.union(blocked_set)
                    and type(event_count) is int and event_count == len(event_ids)
                    and type(allow_count) is int and allow_count == len(allowed_ids)
                    and type(blocked_count) is int and blocked_count == len(blocked_ids)
                    and (primary_action == "ALLOW" and primary_id in allowed_set
                         or primary_action in {"BLOCK", "REJECT"} and primary_id in blocked_set)
                )
                memberships = event_ids if valid else []
            elif kind == "HOST":
                valid = primary_id is not None
                memberships = [primary_id] if valid else []
            else:
                memberships = []

            if valid:
                member_batch.extend((kind, derived_id, event_id) for event_id in memberships)
            else:
                bad_rows += 1
                if primary_id is not None:
                    bad_localizable.append(primary_id)

        connection.executemany(
            "INSERT INTO _pc_derived(kind,derived_id,primary_event_id,site_id) VALUES(?,?,?,?)",
            derived_batch,
        )
        if member_batch:
            connection.executemany(
                "INSERT INTO _pc_members(kind,derived_id,event_id) VALUES(?,?,?)",
                member_batch,
            )
        if bad_localizable:
            connection.executemany(
                "UPDATE _pc_events SET anomaly=1 WHERE event_id=?",
                ((event_id,) for event_id in bad_localizable),
            )
            bad_localizable.clear()
    return bad_rows


def _stream_derived(connection):
    malformed_rows = 0
    detection_cursor = connection.execute(
        """SELECT id, primary_event_id, site_id,
                  CASE WHEN typeof(event_ids_json)='text'
                         AND length(CAST(event_ids_json AS BLOB)) <= ?
                       THEN CAST(event_ids_json AS BLOB) END,
                  detection_type,event_count
           FROM perimeter_detections ORDER BY id""",
        (MAX_MEMBERSHIP_JSON_BYTES,),
    )
    malformed_rows += _insert_derived_members(
        connection, "DETECTION", detection_cursor, membership_columns=1
    )

    policy_cursor = connection.execute(
        """SELECT id, primary_event_id, site_id,
                  CASE WHEN typeof(event_ids_json)='text'
                         AND length(CAST(event_ids_json AS BLOB)) <= ? THEN CAST(event_ids_json AS BLOB) END,
                  CASE WHEN typeof(allowed_event_ids_json)='text'
                         AND length(CAST(allowed_event_ids_json AS BLOB)) <= ? THEN CAST(allowed_event_ids_json AS BLOB) END,
                  CASE WHEN typeof(blocked_event_ids_json)='text'
                         AND length(CAST(blocked_event_ids_json AS BLOB)) <= ? THEN CAST(blocked_event_ids_json AS BLOB) END,
                  event_count,allow_count,blocked_count,primary_action
           FROM perimeter_policy_correlations ORDER BY id""",
        (MAX_MEMBERSHIP_JSON_BYTES,) * 3,
    )
    malformed_rows += _insert_derived_members(
        connection, "POLICY", policy_cursor, membership_columns=3
    )

    host_cursor = connection.execute(
        "SELECT id, event_id, site_id FROM perimeter_host_correlations ORDER BY id"
    )
    malformed_rows += _insert_derived_members(
        connection, "HOST", host_cursor, membership_columns=0
    )

    # Every JSON member must resolve to an event on the derived row's site.
    invalid_members = connection.execute(
        """SELECT COUNT(*) FROM (
               SELECT d.kind,d.derived_id
               FROM _pc_members m
               JOIN _pc_derived d ON d.kind=m.kind AND d.derived_id=m.derived_id
               LEFT JOIN _pc_events e ON e.event_id=m.event_id
               WHERE e.event_id IS NULL OR e.site_id IS NULL OR e.site_id != d.site_id
               GROUP BY d.kind,d.derived_id
           )"""
    ).fetchone()[0]
    if invalid_members:
        malformed_rows += invalid_members
        connection.execute(
            """UPDATE _pc_events SET anomaly=1 WHERE event_id IN (
                   SELECT d.primary_event_id FROM _pc_members m
                   JOIN _pc_derived d ON d.kind=m.kind AND d.derived_id=m.derived_id
                   LEFT JOIN _pc_events e ON e.event_id=m.event_id
                   WHERE e.event_id IS NULL OR e.site_id IS NULL OR e.site_id != d.site_id
               )"""
        )

    # The primary event itself must also exist and agree with the derived row's site.
    invalid_primary = connection.execute(
        """SELECT COUNT(*) FROM _pc_derived d
           LEFT JOIN _pc_events e ON e.event_id=d.primary_event_id
           WHERE d.primary_event_id IS NULL OR e.event_id IS NULL OR e.site_id IS NULL
              OR e.site_id != d.site_id"""
    ).fetchone()[0]
    if invalid_primary:
        malformed_rows += invalid_primary
        connection.execute(
            """UPDATE _pc_events SET anomaly=1 WHERE event_id IN (
                   SELECT d.primary_event_id FROM _pc_derived d
                   LEFT JOIN _pc_events e ON e.event_id=d.primary_event_id
                   WHERE d.primary_event_id IS NULL OR e.event_id IS NULL OR e.site_id IS NULL
                      OR e.site_id != d.site_id
               )"""
        )
    return malformed_rows


def _build_edges_and_components(connection):
    connection.execute(
        """INSERT OR IGNORE INTO _pc_edges(src,dst)
           SELECT d.primary_event_id,m.event_id
           FROM _pc_members m JOIN _pc_derived d
             ON d.kind=m.kind AND d.derived_id=m.derived_id
           WHERE m.event_id != d.primary_event_id"""
    )
    connection.execute(
        """INSERT OR IGNORE INTO _pc_edges(src,dst)
           SELECT m.event_id,d.primary_event_id
           FROM _pc_members m JOIN _pc_derived d
             ON d.kind=m.kind AND d.derived_id=m.derived_id
           WHERE m.event_id != d.primary_event_id"""
    )
    connection.execute(
        """INSERT INTO _pc_component_members(event_id,component_id)
           SELECT e.event_id,e.event_id FROM _pc_events e
           WHERE NOT EXISTS (SELECT 1 FROM _pc_edges x WHERE x.src=e.event_id)"""
    )
    connection.execute(
        """CREATE TEMP TABLE _pc_unassigned(event_id INTEGER PRIMARY KEY) WITHOUT ROWID"""
    )
    connection.execute(
        """INSERT INTO _pc_unassigned(event_id)
           SELECT e.event_id FROM _pc_events e
           WHERE EXISTS (SELECT 1 FROM _pc_edges x WHERE x.src=e.event_id)"""
    )
    while True:
        seed = connection.execute("SELECT MIN(event_id) FROM _pc_unassigned").fetchone()[0]
        if seed is None:
            break
        connection.execute(
            """WITH RECURSIVE reach(event_id) AS (
                   VALUES (?)
                   UNION
                   SELECT edge.dst FROM _pc_edges edge JOIN reach ON edge.src=reach.event_id
               )
               INSERT INTO _pc_component_members(event_id,component_id)
               SELECT event_id,? FROM reach""",
            (seed, seed),
        )
        connection.execute(
            "DELETE FROM _pc_unassigned WHERE event_id IN "
            "(SELECT event_id FROM _pc_component_members WHERE component_id=?)",
            (seed,),
        )
    connection.execute(
        """UPDATE _pc_events
           SET component_id=(SELECT component_id FROM _pc_component_members
                            WHERE _pc_component_members.event_id=_pc_events.event_id)"""
    )
    connection.execute(
        """UPDATE _pc_derived
           SET component_id=(SELECT component_id FROM _pc_events
                            WHERE _pc_events.event_id=_pc_derived.primary_event_id)"""
    )
    inconsistent = connection.execute(
        """SELECT COUNT(*) FROM (
               SELECT m.kind,m.derived_id,MIN(cm.component_id),MAX(cm.component_id)
               FROM _pc_members m JOIN _pc_component_members cm ON cm.event_id=m.event_id
               GROUP BY m.kind,m.derived_id
               HAVING MIN(cm.component_id) != MAX(cm.component_id)
           )"""
    ).fetchone()[0]
    connection.execute(
        """CREATE TEMP TABLE _pc_derived_counts AS
           SELECT d.component_id,
                  SUM(CASE WHEN d.kind='DETECTION' THEN 1 ELSE 0 END) AS detections,
                  SUM(CASE WHEN d.kind='POLICY' THEN 1 ELSE 0 END) AS policies,
                  SUM(CASE WHEN d.kind='HOST' THEN 1 ELSE 0 END) AS hosts
           FROM _pc_derived d WHERE d.component_id IS NOT NULL
           GROUP BY d.component_id"""
    )
    connection.execute(
        """CREATE TEMP TABLE _pc_component_stats AS
           SELECT m.component_id,
                  COUNT(*) AS events,
                  SUM(CASE WHEN e.age_class='ELIGIBLE' THEN 1 ELSE 0 END) AS eligible_events,
                  SUM(CASE WHEN e.age_class='NEWER' THEN 1 ELSE 0 END) AS newer_events,
                  SUM(CASE WHEN e.age_class='FUTURE' THEN 1 ELSE 0 END) AS future_events,
                  SUM(CASE WHEN e.age_class='MALFORMED' THEN 1 ELSE 0 END) AS malformed_events,
                  SUM(e.anomaly) AS anomaly_events,
                  MIN(e.received_key) AS oldest_received_key,
                  MAX(e.received_key) AS newest_received_key,
                  MIN(e.event_id) AS min_event_id,
                  COALESCE(dc.detections,0) AS detections,
                  COALESCE(dc.policies,0) AS policies,
                  COALESCE(dc.hosts,0) AS hosts
           FROM _pc_component_members m JOIN _pc_events e ON e.event_id=m.event_id
           LEFT JOIN _pc_derived_counts dc ON dc.component_id=m.component_id
           GROUP BY m.component_id"""
    )
    return inconsistent


def _all_incident_refs(connection):
    malformed_references = 0
    current = connection.execute(
        """SELECT CASE WHEN typeof(evidence_type)='text'
                         AND length(CAST(evidence_type AS BLOB)) <= 64 THEN CAST(evidence_type AS BLOB) END,
                  evidence_id,typeof(evidence_id)
           FROM incident_review_evidence ORDER BY id"""
    )
    while True:
        rows = current.fetchmany(PERIMETER_FETCH_BATCH_SIZE)
        if not rows:
            break
        refs = []
        for evidence_type, evidence_id, evidence_id_type in rows:
            evidence_type = _strict_text(evidence_type)
            if evidence_type not in _ALL_EVIDENCE_TYPES:
                malformed_references += 1
            elif evidence_type in _PERIMETER_EVIDENCE_TYPES:
                if evidence_id_type != "integer" or type(evidence_id) is not int or evidence_id <= 0:
                    malformed_references += 1
                else:
                    refs.append((_PERIMETER_EVIDENCE_TYPES[evidence_type], evidence_id))
        if refs:
            connection.executemany("INSERT OR IGNORE INTO _pc_refs(kind,derived_id) VALUES(?,?)", refs)

    timeline = connection.execute(
        """SELECT CASE WHEN typeof(event_type)='text'
                         AND length(CAST(event_type AS BLOB)) <= 64 THEN CAST(event_type AS BLOB) END,
                  CASE WHEN typeof(evidence_type)='text'
                         AND length(CAST(evidence_type AS BLOB)) <= 64 THEN CAST(evidence_type AS BLOB) END,
                  evidence_id,typeof(evidence_id)
           FROM incident_review_events ORDER BY id"""
    )
    while True:
        rows = timeline.fetchmany(PERIMETER_FETCH_BATCH_SIZE)
        if not rows:
            break
        refs = []
        for event_type, evidence_type, evidence_id, evidence_id_type in rows:
            event_type = _strict_text(event_type)
            evidence_type = _strict_text(evidence_type)
            if event_type not in _TIMELINE_EVENT_TYPES:
                malformed_references += 1
                continue
            if event_type not in {"EVIDENCE_ATTACHED", "EVIDENCE_DETACHED"}:
                continue
            if evidence_type not in _ALL_EVIDENCE_TYPES:
                malformed_references += 1
            elif evidence_type in _PERIMETER_EVIDENCE_TYPES:
                if evidence_id_type != "integer" or type(evidence_id) is not int or evidence_id <= 0:
                    malformed_references += 1
                else:
                    refs.append((_PERIMETER_EVIDENCE_TYPES[evidence_type], evidence_id))
        if refs:
            connection.executemany("INSERT OR IGNORE INTO _pc_refs(kind,derived_id) VALUES(?,?)", refs)

    unresolved = connection.execute(
        """SELECT COUNT(*) FROM _pc_refs r LEFT JOIN _pc_derived d
             ON d.kind=r.kind AND d.derived_id=r.derived_id
           WHERE d.derived_id IS NULL OR d.component_id IS NULL"""
    ).fetchone()[0]
    connection.execute(
        """INSERT OR IGNORE INTO _pc_protected(component_id)
           SELECT DISTINCT d.component_id FROM _pc_refs r JOIN _pc_derived d
             ON d.kind=r.kind AND d.derived_id=r.derived_id
           WHERE d.component_id IS NOT NULL"""
    )
    return malformed_references + unresolved, malformed_references, unresolved


def _stats(connection, evaluated_at, cutoff, *, global_block, ambiguous_references,
            graph_anomalies, unresolved_references):
    connection.execute(
        """CREATE TEMP TABLE _pc_flags AS
           SELECT c.*,
                  CASE WHEN c.eligible_events=c.events AND c.newer_events=0
                              AND c.future_events=0 AND c.malformed_events=0
                              AND c.anomaly_events=0
                       THEN 1 ELSE 0 END AS age_safe,
                  CASE WHEN p.component_id IS NULL THEN 0 ELSE 1 END AS review_protected,
                  c.events+c.detections+c.policies+c.hosts AS total_rows
           FROM _pc_component_stats c LEFT JOIN _pc_protected p
             ON p.component_id=c.component_id"""
    )
    counts = connection.execute(
        """SELECT COUNT(*),
                  COALESCE(SUM(age_safe=1 AND review_protected=0),0),
                  COALESCE(SUM(review_protected=1),0),
                  COALESCE(SUM(newer_events>0),0),
                  COALESCE(SUM(future_events>0 OR malformed_events>0 OR anomaly_events>0),0),
                  COALESCE(SUM(CASE WHEN age_safe=1 THEN total_rows ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN age_safe=1 AND review_protected=1 THEN total_rows ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN age_safe=1 AND review_protected=0 THEN events ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN age_safe=1 AND review_protected=0 THEN detections ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN age_safe=1 AND review_protected=0 THEN policies ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN age_safe=1 AND review_protected=0 THEN hosts ELSE 0 END),0),
                  MIN(CASE WHEN age_safe=1 AND review_protected=0 THEN oldest_received_key END),
                  MAX(CASE WHEN age_safe=1 AND review_protected=0 THEN newest_received_key END),
                  COALESCE(SUM(future_events),0),COALESCE(SUM(malformed_events),0),
                  COALESCE(SUM(CASE WHEN review_protected=1 THEN events ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN review_protected=1 THEN detections ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN review_protected=1 THEN policies ELSE 0 END),0),
                  COALESCE(SUM(CASE WHEN review_protected=1 THEN hosts ELSE 0 END),0)
           FROM _pc_flags"""
    ).fetchone()
    (total_components, candidate_components, protected_components, newer_components,
     ambiguous_components, expired_rows, aged_protected_rows, eligible_events,
     eligible_detections, eligible_policies, eligible_hosts, oldest, newest,
     future_events, malformed_events, protected_events, protected_detections,
     protected_policies, protected_hosts) = counts

    # A global ambiguity makes no component safe to delete, even if local stats
    # can still be displayed to help the operator understand the situation.
    eligible_components = 0 if global_block else candidate_components
    if global_block:
        eligible_events = eligible_detections = eligible_policies = eligible_hosts = 0
        oldest = newest = None

    eligible_size = connection.execute(
        """SELECT events,detections+policies+hosts,total_rows
           FROM _pc_flags WHERE age_safe=1 AND review_protected=0 AND ?=0
           ORDER BY total_rows DESC,min_event_id ASC LIMIT 1""",
        (int(bool(global_block)),),
    ).fetchone()
    protected_size = connection.execute(
        """SELECT total_rows FROM _pc_flags WHERE review_protected=1
           ORDER BY total_rows DESC,min_event_id ASC LIMIT 1"""
    ).fetchone()
    oldest_eligible = _iso_utc(datetime.fromisoformat(oldest)) if oldest else None
    newest_eligible = _iso_utc(datetime.fromisoformat(newest)) if newest else None
    total_events = connection.execute("SELECT COUNT(*) FROM _pc_events").fetchone()[0]
    total_detections = connection.execute("SELECT COUNT(*) FROM _pc_derived WHERE kind='DETECTION'").fetchone()[0]
    total_policies = connection.execute("SELECT COUNT(*) FROM _pc_derived WHERE kind='POLICY'").fetchone()[0]
    total_hosts = connection.execute("SELECT COUNT(*) FROM _pc_derived WHERE kind='HOST'").fetchone()[0]
    total_rows = total_events + total_detections + total_policies + total_hosts
    selected_reasons = global_block
    return {
        "data_class": "PERIMETER_EVIDENCE",
        "policy_state": "ACTIVE_RETENTION_POLICY",
        "total_rows": total_rows,
        "expired_rows": expired_rows,
        "eligible_rows": eligible_events + eligible_detections + eligible_policies + eligible_hosts,
        "protected_by_review": protected_events + protected_detections + protected_policies + protected_hosts,
        "protected_by_dependency": 0,
        "policy_undefined": 0,
        "invalid_retention_rows": malformed_events,
        "oldest_eligible_at": oldest_eligible,
        "evaluation_time": _iso_utc(evaluated_at),
        "retention_days": PERIMETER_RETENTION_DAYS,
        "cutoff": _iso_utc(cutoff),
        "max_components_per_apply": PERIMETER_MAX_COMPONENTS_PER_APPLY,
        "events_classified": total_events,
        "total_components": total_components,
        "eligible_components": eligible_components,
        "age_eligible_components_before_global_block": candidate_components,
        "protected_components": protected_components,
        "newer_components": newer_components,
        "ambiguous_components": ambiguous_components,
        "ambiguous_references": ambiguous_references,
        "graph_anomalies": graph_anomalies,
        "unresolved_references": unresolved_references,
        "malformed_or_future_events": malformed_events + future_events,
        "malformed_skipped_rows": malformed_events,
        "future_skipped_rows": future_events,
        "eligible_events": eligible_events,
        "eligible_detections": eligible_detections,
        "eligible_policy_correlations": eligible_policies,
        "eligible_host_correlations": eligible_hosts,
        "protected_events": protected_events,
        "protected_detections": protected_detections,
        "protected_policy_correlations": protected_policies,
        "protected_host_correlations": protected_hosts,
        "oldest_eligible_received_at": oldest_eligible,
        "newest_eligible_received_at": newest_eligible,
        "largest_eligible_component_events": eligible_size[0] if eligible_size else 0,
        "largest_eligible_component_derived_rows": eligible_size[1] if eligible_size else 0,
        "largest_eligible_component_total_rows": eligible_size[2] if eligible_size else 0,
        "largest_protected_component_total_rows": protected_size[0] if protected_size else 0,
        "cleanup_blocked": bool(selected_reasons),
        "cleanup_block_reason": (
            "Cleanup is blocked because perimeter evidence has malformed or unresolved relationships."
            if selected_reasons else None
        ),
    }


def classify_perimeter_evidence(connection, evaluated_at):
    """Build TEMP graph state and return counts without persistent writes."""
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluated_at must be timezone-aware")
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    cutoff = evaluated_at - timedelta(days=PERIMETER_RETENTION_DAYS)
    _create_temp_tables(connection)
    _stream_events(connection, evaluated_at, cutoff)
    graph_anomalies = _stream_derived(connection)
    inconsistent_components = _build_edges_and_components(connection)
    ambiguous_references, malformed_references, unresolved_references = _all_incident_refs(connection)
    # Any malformed membership, component split, or unresolved Incident Review
    # reference makes the complete run unsafe; no component will be selected.
    global_block = bool(graph_anomalies or inconsistent_components or ambiguous_references)
    stats = _stats(
        connection, evaluated_at, cutoff,
        global_block=global_block,
        ambiguous_references=ambiguous_references,
        graph_anomalies=graph_anomalies + inconsistent_components,
        unresolved_references=unresolved_references,
    )
    stats["ambiguous_references"] = malformed_references + unresolved_references
    stats["cleanup_blocked"] = global_block
    if global_block:
        stats["cleanup_block_reason"] = (
            "Cleanup is blocked because perimeter evidence has malformed or unresolved relationships."
        )
    return stats


def apply_perimeter_evidence_cleanup(connection, evaluated_at):
    """Reclassify inside the caller's write transaction, then delete full components."""
    stats = classify_perimeter_evidence(connection, evaluated_at)
    base = {
        "data_class": "PERIMETER_EVIDENCE",
        "evaluation_time": stats["evaluation_time"],
        "cutoff": stats["cutoff"],
        "retention_days": PERIMETER_RETENTION_DAYS,
        "max_components_per_apply": PERIMETER_MAX_COMPONENTS_PER_APPLY,
        "cleanup_blocked": stats["cleanup_blocked"],
        "cleanup_block_reason": stats["cleanup_block_reason"],
        "eligible_components_before_apply": stats["eligible_components"],
        "components_deleted": 0,
        "events_deleted": 0,
        "detections_deleted": 0,
        "policy_correlations_deleted": 0,
        "host_correlations_deleted": 0,
        "largest_selected_component_events": 0,
        "largest_selected_component_derived_rows": 0,
        "largest_selected_component_total_rows": 0,
    }
    if stats["cleanup_blocked"] or stats["eligible_components"] == 0:
        return base

    connection.execute(
        """INSERT INTO _pc_selected(component_id)
           SELECT component_id FROM _pc_flags
           WHERE age_safe=1 AND review_protected=0
           ORDER BY oldest_received_key ASC,min_event_id ASC
           LIMIT ?""",
        (PERIMETER_MAX_COMPONENTS_PER_APPLY,),
    )
    largest_selected = connection.execute(
        """SELECT events,detections+policies+hosts,total_rows
           FROM _pc_flags JOIN _pc_selected USING(component_id)
           ORDER BY total_rows DESC,min_event_id ASC LIMIT 1"""
    ).fetchone()
    if largest_selected is not None:
        base.update({
            "largest_selected_component_events": largest_selected[0],
            "largest_selected_component_derived_rows": largest_selected[1],
            "largest_selected_component_total_rows": largest_selected[2],
        })
    for table in (
        "CREATE TEMP TABLE _pc_delete_events(id INTEGER PRIMARY KEY)",
        "CREATE TEMP TABLE _pc_delete_detections(id INTEGER PRIMARY KEY)",
        "CREATE TEMP TABLE _pc_delete_policy(id INTEGER PRIMARY KEY)",
        "CREATE TEMP TABLE _pc_delete_hosts(id INTEGER PRIMARY KEY)",
        """INSERT INTO _pc_delete_events
           SELECT event_id FROM _pc_component_members
           WHERE component_id IN (SELECT component_id FROM _pc_selected)""",
        """INSERT INTO _pc_delete_detections
           SELECT derived_id FROM _pc_derived
           WHERE kind='DETECTION' AND component_id IN (SELECT component_id FROM _pc_selected)""",
        """INSERT INTO _pc_delete_policy
           SELECT derived_id FROM _pc_derived
           WHERE kind='POLICY' AND component_id IN (SELECT component_id FROM _pc_selected)""",
        """INSERT INTO _pc_delete_hosts
           SELECT derived_id FROM _pc_derived
           WHERE kind='HOST' AND component_id IN (SELECT component_id FROM _pc_selected)""",
    ):
        connection.execute(table)
    expected = {
        "components_deleted": connection.execute("SELECT COUNT(*) FROM _pc_selected").fetchone()[0],
        "events_deleted": connection.execute("SELECT COUNT(*) FROM _pc_delete_events").fetchone()[0],
        "detections_deleted": connection.execute("SELECT COUNT(*) FROM _pc_delete_detections").fetchone()[0],
        "policy_correlations_deleted": connection.execute("SELECT COUNT(*) FROM _pc_delete_policy").fetchone()[0],
        "host_correlations_deleted": connection.execute("SELECT COUNT(*) FROM _pc_delete_hosts").fetchone()[0],
    }
    delete_steps = (
        ("perimeter_host_correlations", "_pc_delete_hosts", "host_correlations_deleted"),
        ("perimeter_detections", "_pc_delete_detections", "detections_deleted"),
        ("perimeter_policy_correlations", "_pc_delete_policy", "policy_correlations_deleted"),
        ("perimeter_events", "_pc_delete_events", "events_deleted"),
    )
    for table, selected, count_key in delete_steps:
        cursor = connection.execute(
            f"DELETE FROM {table} WHERE id IN (SELECT id FROM {selected})"
        )
        if cursor.rowcount != expected[count_key]:
            raise sqlite3.IntegrityError("Perimeter component changed during lifecycle cleanup.")
    base.update(expected)
    return base
