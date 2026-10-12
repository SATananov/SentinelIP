"""Atomic threat upserts with typed live links and immutable audit snapshots."""
import json
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database
from services.threat_evidence import SSH_COLUMNS, WEB_COLUMNS, ssh_from_row, web_from_row
from services.threat_models import ThreatDetection, ThreatError, EvidenceType


def _read(connection, threat_id):
    row = connection.execute("SELECT * FROM threat_detections WHERE id = ?", (threat_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["evidence"] = []
    for row in connection.execute("SELECT * FROM threat_evidence WHERE threat_id = ? ORDER BY evidence_type, evidence_id", (threat_id,)):
        item = dict(row)
        item["snapshot"] = json.loads(item.pop("evidence_snapshot"))
        result["evidence"].append(item)
    return result


def persist_threat(connection, candidate: ThreatDetection):
    """Caller owns the transaction; the engine holds one across reads and writes."""
    if not isinstance(candidate, ThreatDetection):
        raise TypeError("ThreatDetection is required.")
    snapshots = []
    for evidence in candidate.evidence:
        is_ssh = evidence.evidence_type == EvidenceType.SSH_EVENT
        table, columns, adapt = ("events", SSH_COLUMNS, ssh_from_row) if is_ssh else ("web_detections", WEB_COLUMNS, web_from_row)
        row = connection.execute(f"SELECT {columns} FROM {table} WHERE id = ?", (evidence.evidence_id,)).fetchone()
        if row is None or adapt(row) != evidence:
            raise ThreatError("Threat evidence must match its persisted source.")
        snapshots.append((evidence, json.dumps(evidence.snapshot(), sort_keys=True, separators=(",", ":"))))
    first, last = candidate.first_seen.isoformat(), candidate.last_seen.isoformat()
    connection.execute(
        """INSERT INTO threat_detections (
            stable_key, threat_type, state, severity, confidence, device_id, source_ip, sensor_id, hostname,
            primary_evidence_type, primary_evidence_id, anchor_id, reason, recommendation, rule_id, rule_version,
            first_seen, last_seen, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(stable_key) DO UPDATE SET
            last_seen = MAX(threat_detections.last_seen, excluded.last_seen),
            updated_at = MAX(threat_detections.updated_at, excluded.updated_at)""",
        (candidate.stable_key, candidate.threat_type.value, candidate.state.value, candidate.severity.value,
         candidate.confidence.value, candidate.device_id, candidate.source_ip, candidate.sensor_id,
         candidate.hostname, candidate.primary.evidence_type.value, candidate.primary_evidence_id, candidate.anchor_id,
         candidate.reason, candidate.recommendation, candidate.rule_id, candidate.rule_version, first, last, first, last),
    )
    threat_id = connection.execute("SELECT id FROM threat_detections WHERE stable_key = ?", (candidate.stable_key,)).fetchone()[0]
    for evidence, snapshot in snapshots:
        existing = connection.execute("""SELECT evidence_snapshot FROM threat_evidence
            WHERE threat_id=? AND evidence_type=? AND evidence_id=?""",
            (threat_id, evidence.evidence_type.value, evidence.evidence_id)).fetchone()
        if existing is not None and existing[0] != snapshot:
            raise ThreatError("Existing threat evidence changed; historical snapshots cannot be overwritten.")
        connection.execute(
            """INSERT INTO threat_evidence(threat_id, evidence_type, evidence_id, ssh_event_id, web_detection_id, evidence_snapshot)
               VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(threat_id, evidence_type, evidence_id) DO NOTHING""",
            (threat_id, evidence.evidence_type.value, evidence.evidence_id,
             evidence.evidence_id if evidence.evidence_type == EvidenceType.SSH_EVENT else None,
             evidence.evidence_id if evidence.evidence_type == EvidenceType.WEB_DETECTION else None, snapshot),
        )
    return _read(connection, threat_id)


def upsert_threat(candidate: ThreatDetection, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        return persist_threat(connection, candidate)


def get_threat(threat_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _read(connection, threat_id)


def list_threats(db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        ids = connection.execute("SELECT id FROM threat_detections ORDER BY id").fetchall()
        return [_read(connection, row[0]) for row in ids]


def query_threats(
    *,
    limit=20,
    offset=0,
    threat_type=None,
    state=None,
    severity=None,
    confidence=None,
    source_ip=None,
    device_id=None,
    sensor_id=None,
    db_path=DB_PATH,
):
    """Bounded read-only threat query for API presentation."""
    initialize_database(db_path)

    clauses = []
    params = []

    for column, value in (
        ("threat_type", threat_type),
        ("state", state),
        ("severity", severity),
        ("confidence", confidence),
        ("source_ip", source_ip),
        ("device_id", device_id),
        ("sensor_id", sensor_id),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        total = connection.execute(
            f"SELECT COUNT(*) FROM threat_detections{where}",
            tuple(params),
        ).fetchone()[0]

        rows = connection.execute(
            f"""SELECT id
                FROM threat_detections
                {where}
                ORDER BY id DESC
                LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()

        return {
            "total": total,
            "items": [_read(connection, row["id"]) for row in rows],
        }
