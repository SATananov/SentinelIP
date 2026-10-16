"""Durable web reviews, independent of operational risk findings."""
import json
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database
from services.web_detection_models import EVIDENCE_COLUMNS, WebDetection, WebDetectionError, WebEvidence


def _row(row):
    if row is None:
        return None
    result = dict(row)
    result["evidence"] = json.loads(result.pop("structured_evidence"))
    return result


def upsert_detections(detections: tuple[WebDetection, ...], db_path=DB_PATH):
    if not all(isinstance(d, WebDetection) for d in detections):
        raise TypeError("WebDetection records are required.")
    initialize_database(db_path)
    results = []
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        # Verify references and snapshots under the same write transaction.
        connection.execute("BEGIN IMMEDIATE")
        for detection in detections:
            for evidence in detection.evidence:
                row = connection.execute(f"SELECT {EVIDENCE_COLUMNS} FROM web_observations WHERE id = ?",
                                         (evidence.observation_id,)).fetchone()
                if row is None or WebEvidence.from_row(dict(row)) != evidence:
                    raise WebDetectionError("Detection evidence must match persisted web observations.")
            first = detection.first_seen.isoformat()
            last = detection.last_seen.isoformat()
            connection.execute(
                """INSERT INTO web_detections (
                    stable_key, detection_type, severity, confidence, state, sensor_id, device_id,
                    primary_observation_id, hostname, reason, structured_evidence, rule_id,
                    rule_version, first_seen, last_seen, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stable_key) DO UPDATE SET
                    last_seen = MAX(web_detections.last_seen, excluded.last_seen),
                    updated_at = MAX(web_detections.updated_at, excluded.updated_at)""",
                (detection.stable_key, detection.detection_type.value, detection.severity.value,
                 detection.confidence.value, detection.state.value, detection.sensor_id, detection.device_id,
                 detection.primary_observation_id, detection.hostname, detection.reason,
                 json.dumps([e.snapshot() for e in detection.evidence], sort_keys=True, separators=(",", ":")),
                 detection.rule_id, detection.rule_version, first, last, first, last),
            )
            stored = connection.execute("SELECT * FROM web_detections WHERE stable_key = ?",
                                        (detection.stable_key,)).fetchone()
            for evidence in detection.evidence:
                connection.execute("""INSERT INTO web_detection_observations (detection_id, observation_id)
                                      VALUES (?, ?) ON CONFLICT(detection_id, observation_id) DO NOTHING""",
                                   (stored["id"], evidence.observation_id))
            results.append(_row(stored))
    return results


def get_web_detection(detection_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM web_detections WHERE id = ?", (detection_id,)).fetchone()
    return _row(row)


def list_web_detections(sensor_id: int | None = None, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM web_detections WHERE (? IS NULL OR sensor_id = ?) ORDER BY id",
            (sensor_id, sensor_id),
        ).fetchall()
    return [_row(row) for row in rows]


def query_web_detections(*, limit=20, offset=0, db_path=DB_PATH):
    """Bounded, compact read projection for analyst review intake."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Web detection limit must be between 1 and 100.")
    if type(offset) is not int or not 0 <= offset <= 100000:
        raise ValueError("Web detection offset must be between 0 and 100000.")
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute("SELECT COUNT(*) FROM web_detections").fetchone()[0]
        rows = connection.execute(
            """SELECT id, detection_type, state, device_id, hostname, first_seen, last_seen
               FROM web_detections ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
    return {"total": total, "items": [dict(row) for row in rows]}
