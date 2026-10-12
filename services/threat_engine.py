"""Explicit bounded local threat evaluation; never invokes collection."""
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from database.threats import persist_threat
from services.detector import SSHDetector
from services.threat_evidence import SSH_COLUMNS, WEB_COLUMNS, ssh_from_row, web_from_row
from services.threat_models import EvidenceType, ThreatError, positive_id
from services.threat_rules import evaluate_ssh, evaluate_web, strengthens
from services.web_detection_models import utc

MAX_RELATED_EVIDENCE = 1000


def _bounded(rows):
    if len(rows) > MAX_RELATED_EVIDENCE:
        raise ThreatError("Threat evidence limit exceeded; evaluation was not persisted.")
    return rows


class ThreatEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def evaluate_evidence(self, evidence_type, evidence_id, *, evaluated_at=None):
        kind = EvidenceType(evidence_type)
        positive_id(evidence_id)
        if kind in {EvidenceType.CHANGE, EvidenceType.FINDING, EvidenceType.CVE_MATCH}:
            return []  # Assessments are deliberately not promoted to threats.
        now = utc(evaluated_at if evaluated_at is not None else datetime.now(timezone.utc))
        initialize_database(self.db_path)
        with get_connection(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            candidate = (self._ssh(connection, evidence_id, now) if kind == EvidenceType.SSH_EVENT
                         else self._web(connection, evidence_id, now))
            return [persist_threat(connection, candidate)] if candidate else []

    def evaluate_ssh_event(self, event_id, *, evaluated_at=None):
        return self.evaluate_evidence(EvidenceType.SSH_EVENT, event_id, evaluated_at=evaluated_at)

    def evaluate_web_detection(self, detection_id, *, evaluated_at=None):
        return self.evaluate_evidence(EvidenceType.WEB_DETECTION, detection_id, evaluated_at=evaluated_at)

    def _ssh(self, connection, event_id, now):
        row = connection.execute(f"SELECT {SSH_COLUMNS} FROM events WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            raise ThreatError("Persisted authentication event not found.")
        primary = ssh_from_row(row)
        if primary.event_type not in {"LOGIN_FAILED", "SSH_PREAUTH"}:
            return None
        rows = _bounded(connection.execute(
            f"""SELECT {SSH_COLUMNS} FROM events WHERE source_ip = ? AND event_type = ?
               AND julianday(timestamp) >= julianday(?) AND julianday(timestamp) <= julianday(?)
               ORDER BY julianday(timestamp), id LIMIT ?""",
            (row["source_ip"], primary.event_type, (primary.timestamp - SSHDetector().window).isoformat(),
             primary.timestamp.isoformat(), MAX_RELATED_EVIDENCE + 1),
        ).fetchall())
        return evaluate_ssh(primary, tuple(ssh_from_row(item) for item in rows), now)

    def _web(self, connection, detection_id, now):
        row = connection.execute(f"SELECT {WEB_COLUMNS} FROM web_detections WHERE id=?", (detection_id,)).fetchone()
        if row is None:
            raise ThreatError("Persisted web detection not found.")
        if row["detection_type"] not in {"CROSS_DOMAIN_LOGIN_REDIRECT", "SUSPICIOUS_DOWNLOAD_FLOW"}:
            return None
        current = web_from_row(row)
        anchor = current
        if current.detection_type == "SUSPICIOUS_DOWNLOAD_FLOW":
            ids = tuple(e.observation_id for e in current.observations if e.observation_id != current.primary_observation_id)
            if not ids or current.primary.context is None:
                return None
            slots = ",".join("?" for _ in ids)
            rows = _bounded(connection.execute(
                f"""SELECT {WEB_COLUMNS} FROM web_detections WHERE sensor_id=? AND device_id IS ?
                   AND detection_type='CROSS_DOMAIN_LOGIN_REDIRECT' AND primary_observation_id IN ({slots})
                   ORDER BY id LIMIT ?""", (current.sensor_id, current.device_id, *ids, MAX_RELATED_EVIDENCE + 1),
            ).fetchall())
            anchors = [web_from_row(item) for item in rows]
            anchors = [item for item in anchors if strengthens(item, current)]
            if not anchors:
                return None
            anchor = max(anchors, key=lambda e: (e.primary.observed_at, e.primary_observation_id, -e.evidence_id))
        rows = _bounded(connection.execute(
            f"""SELECT {WEB_COLUMNS} FROM web_detections WHERE sensor_id=? AND device_id IS ?
                AND detection_type='SUSPICIOUS_DOWNLOAD_FLOW' AND id IN (
                    SELECT detection_id FROM web_detection_observations WHERE observation_id=?)
                ORDER BY id LIMIT ?""",
            (anchor.sensor_id, anchor.device_id, anchor.primary_observation_id, MAX_RELATED_EVIDENCE + 1),
        ).fetchall())
        return evaluate_web(anchor, tuple(web_from_row(item) for item in rows), now)
