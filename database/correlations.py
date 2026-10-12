"""Atomic correlation records with typed live references and immutable snapshots."""
import json
import sqlite3
from dataclasses import replace

from database.db import DB_PATH, get_connection, initialize_database
from services.correlation_evidence import load_entity
from services.correlation_models import Correlation, CorrelationError, EntityType
from services.correlation_rules import correlate_ssh, correlate_web


def _read(connection, correlation_id):
    row = connection.execute("SELECT * FROM correlations WHERE id=?", (correlation_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["entities"] = []
    for row in connection.execute("SELECT * FROM correlation_entities WHERE correlation_id=? ORDER BY entity_type, entity_id", (correlation_id,)):
        item = dict(row)
        item["snapshot"] = json.loads(item["snapshot"])
        result["entities"].append(item)
    return result


def persist_correlation(connection, candidate):
    """Validate provenance and rule output; caller owns the write transaction."""
    if not isinstance(candidate, Correlation):
        raise TypeError("Correlation is required.")
    for entity in candidate.entities:
        if load_entity(connection, entity.entity_type, entity.entity_id) != entity:
            raise CorrelationError("Entity projection no longer matches persisted evidence.")
    if candidate.correlation_type == "SSH_AUTH_ACTIVITY_PATTERN":
        if len(candidate.entities) != 2:
            raise CorrelationError("SSH version 1 correlates pairs of complementary threats.")
        expected = correlate_ssh(*candidate.entities, candidate.first_seen)
    else:
        web = tuple(e for e in candidate.entities if e.entity_type == EntityType.WEB_DETECTION)
        for entity in web:
            linked = connection.execute("""SELECT 1 FROM threat_evidence WHERE threat_id=?
                AND evidence_type='WEB_DETECTION' AND evidence_id=? AND web_detection_id=?""",
                (candidate.primary_entity_id, entity.entity_id, entity.entity_id)).fetchone()
            if linked is None:
                raise CorrelationError("Web entities require persisted threat evidence links.")
        expected = correlate_web(candidate.primary, web, candidate.first_seen)
    if expected is None or replace(expected, last_seen=candidate.last_seen) != candidate:
        raise CorrelationError("Candidate does not match the deterministic correlation rule.")
    first, last = candidate.first_seen.isoformat(), candidate.last_seen.isoformat()
    primary = candidate.primary
    connection.execute(
        """INSERT INTO correlations(stable_key, correlation_type, state, severity, confidence,
            device_id, sensor_id, source_ip, hostname, primary_entity_type, primary_entity_id,
            reason, rule_id, rule_version, first_seen, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(stable_key) DO UPDATE SET
                last_seen=MAX(correlations.last_seen, excluded.last_seen),
                updated_at=MAX(correlations.updated_at, excluded.updated_at)""",
        (candidate.stable_key, candidate.correlation_type.value, candidate.state.value, candidate.severity.value,
         candidate.confidence.value, primary.device_id, primary.sensor_id, primary.source_ip, primary.hostname,
         candidate.primary_entity_type.value, candidate.primary_entity_id, candidate.reason, candidate.rule_id,
         candidate.rule_version, first, last, first, last),
    )
    correlation_id = connection.execute("SELECT id FROM correlations WHERE stable_key=?", (candidate.stable_key,)).fetchone()[0]
    for entity in candidate.entities:
        snapshot = json.dumps(entity.snapshot(), sort_keys=True, separators=(",", ":"))
        old = connection.execute("""SELECT snapshot FROM correlation_entities
            WHERE correlation_id=? AND entity_type=? AND entity_id=?""",
            (correlation_id, *entity.identity)).fetchone()
        if old is not None and old[0] != snapshot:
            raise CorrelationError("Historical correlation snapshots cannot be overwritten.")
        connection.execute("""INSERT INTO correlation_entities(correlation_id, entity_type, entity_id,
            threat_id, web_detection_id, entity_timestamp, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(correlation_id, entity_type, entity_id) DO NOTHING""",
            (correlation_id, *entity.identity, entity.entity_id if entity.entity_type == EntityType.THREAT else None,
             entity.entity_id if entity.entity_type == EntityType.WEB_DETECTION else None,
             entity.entity_timestamp.isoformat(), snapshot))
    return _read(connection, correlation_id)


def upsert_correlation(candidate, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        return persist_correlation(connection, candidate)


def get_correlation(correlation_id, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _read(connection, correlation_id)


def list_correlations(db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        ids = connection.execute("SELECT id FROM correlations ORDER BY id").fetchall()
        return [_read(connection, row[0]) for row in ids]
