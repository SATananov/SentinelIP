"""Explicit bounded correlation of existing signals, without running detectors."""
import sqlite3
from datetime import datetime, timezone

from database.db import DB_PATH, get_connection, initialize_database
from database.correlations import persist_correlation
from services.correlation_evidence import load_entity
from services.correlation_models import CorrelationError, EntityType
from services.correlation_rules import SSH_WINDOW, correlate_ssh, correlate_web
from services.threat_models import positive_id
from services.web_detection_models import utc

MAX_RELATED_ENTITIES = 100


def _bounded(rows):
    if len(rows) > MAX_RELATED_ENTITIES:
        raise CorrelationError("Correlation context limit exceeded; no results were persisted.")
    return rows


class CorrelationEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def evaluate_entity(self, entity_type, entity_id, *, evaluated_at=None):
        kind = EntityType(entity_type)
        positive_id(entity_id)
        if kind not in {EntityType.THREAT, EntityType.WEB_DETECTION}:
            return []
        now = utc(evaluated_at if evaluated_at is not None else datetime.now(timezone.utc))
        initialize_database(self.db_path)
        with get_connection(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            entity = load_entity(connection, kind, entity_id)
            if kind == EntityType.WEB_DETECTION:
                ids = _bounded(connection.execute("""SELECT DISTINCT threat_id FROM threat_evidence
                    WHERE evidence_type='WEB_DETECTION' AND web_detection_id=? ORDER BY threat_id LIMIT ?""",
                    (entity_id, MAX_RELATED_ENTITIES+1)).fetchall())
                threats = tuple(load_entity(connection, EntityType.THREAT, row[0]) for row in ids)
            else:
                threats = (entity,)
            candidates = {}
            # All reads/rules finish before any writes; limits abort the complete invocation.
            for threat in threats:
                for candidate in self._evaluate(connection, threat, now):
                    candidates[candidate.stable_key] = candidate
                if len(candidates) > MAX_RELATED_ENTITIES:
                    raise CorrelationError("Correlation result limit exceeded.")
            return [persist_correlation(connection, candidates[key]) for key in sorted(candidates)]

    def evaluate_threat(self, threat_id, *, evaluated_at=None):
        return self.evaluate_entity(EntityType.THREAT, threat_id, evaluated_at=evaluated_at)

    def evaluate_web_detection(self, detection_id, *, evaluated_at=None):
        return self.evaluate_entity(EntityType.WEB_DETECTION, detection_id, evaluated_at=evaluated_at)

    def _evaluate(self, connection, threat, now):
        if threat.signal_type in {"SSH_BRUTE_FORCE_THREAT", "SUSPICIOUS_AUTH_ACTIVITY"}:
            opposite = "SSH_BRUTE_FORCE_THREAT" if threat.signal_type == "SUSPICIOUS_AUTH_ACTIVITY" else "SUSPICIOUS_AUTH_ACTIVITY"
            rows = _bounded(connection.execute("""SELECT t.id FROM threat_detections t JOIN threat_evidence e
                ON e.threat_id=t.id AND e.evidence_type=t.primary_evidence_type AND e.evidence_id=t.primary_evidence_id
                WHERE t.source_ip=? AND t.threat_type=? AND e.evidence_type='SSH_EVENT'
                AND julianday(json_extract(e.evidence_snapshot, '$.timestamp')) BETWEEN julianday(?) AND julianday(?)
                ORDER BY t.id LIMIT ?""",
                (threat.source_ip, opposite, (threat.entity_timestamp-SSH_WINDOW).isoformat(),
                 (threat.entity_timestamp+SSH_WINDOW).isoformat(), MAX_RELATED_ENTITIES+1)).fetchall())
            results = [correlate_ssh(threat, load_entity(connection, EntityType.THREAT, row[0]), now) for row in rows]
            return tuple(result for result in results if result is not None)
        if threat.signal_type != "WEB_CREDENTIAL_FLOW_THREAT" or threat.web_context is None:
            return ()
        rows = _bounded(connection.execute("""SELECT web_detection_id FROM threat_evidence
            WHERE threat_id=? AND evidence_type='WEB_DETECTION' AND web_detection_id IS NOT NULL
            ORDER BY web_detection_id LIMIT ?""", (threat.entity_id, MAX_RELATED_ENTITIES+1)).fetchall())
        web = tuple(load_entity(connection, EntityType.WEB_DETECTION, row[0]) for row in rows)
        candidate = correlate_web(threat, web, now)
        return (candidate,) if candidate is not None else ()
