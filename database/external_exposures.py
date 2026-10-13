import hashlib
import json
import sqlite3

from database.db import DB_PATH, get_connection, initialize_database
from services.external_exposure_models import ExternalExposureObservation


def _row(row):
    return dict(row) if row is not None else None


def _observation_key(observation: ExternalExposureObservation) -> str:
    payload = {
        "stable_key": observation.stable_key,
        "observed_at": observation.observed_at.isoformat(timespec="seconds"),
        "source": observation.source,
        "scanner": observation.scanner,
        "service_name": observation.service_name,
        "product": observation.product,
        "version": observation.version,
        "extra_info": observation.extra_info,
        "service_confidence": observation.service_confidence,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def record_observation(observation: ExternalExposureObservation, db_path=DB_PATH):
    if not isinstance(observation, ExternalExposureObservation):
        raise ValueError("A normalized external exposure observation is required.")
    initialize_database(db_path)
    observed_at = observation.observed_at.isoformat(timespec="seconds")
    observation_key = _observation_key(observation)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            INSERT INTO external_exposures (
                stable_key, scope_id, scope_type, canonical_target, device_id,
                target_ip, port_number, transport,
                service_name, product, version, extra_info, service_confidence,
                first_seen, last_seen, last_observation_source, last_scanner,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(stable_key) DO UPDATE SET
                last_seen = CASE WHEN excluded.last_seen > external_exposures.last_seen
                                 THEN excluded.last_seen ELSE external_exposures.last_seen END,
                service_name = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                                    THEN excluded.service_name ELSE external_exposures.service_name END,
                product = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                               THEN excluded.product ELSE external_exposures.product END,
                version = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                               THEN excluded.version ELSE external_exposures.version END,
                extra_info = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                                  THEN excluded.extra_info ELSE external_exposures.extra_info END,
                service_confidence = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                                          THEN excluded.service_confidence ELSE external_exposures.service_confidence END,
                last_observation_source = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                                               THEN excluded.last_observation_source ELSE external_exposures.last_observation_source END,
                last_scanner = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                                    THEN excluded.last_scanner ELSE external_exposures.last_scanner END,
                updated_at = CASE WHEN excluded.last_seen >= external_exposures.last_seen
                                  THEN excluded.updated_at ELSE external_exposures.updated_at END
            """,
            (
                observation.stable_key, observation.scope_id, observation.scope_type,
                observation.canonical_target, observation.device_id, observation.target_ip,
                observation.port_number, observation.transport, observation.service_name,
                observation.product, observation.version, observation.extra_info,
                observation.service_confidence, observed_at, observed_at, observation.source,
                observation.scanner, observed_at, observed_at,
            ),
        )
        exposure = connection.execute(
            "SELECT * FROM external_exposures WHERE stable_key = ?", (observation.stable_key,)
        ).fetchone()
        connection.execute(
            """
            INSERT OR IGNORE INTO external_exposure_observations (
                observation_key, exposure_id, scope_id, device_id, target_ip,
                port_number, transport, service_name, product, version, extra_info,
                service_confidence, observed_at, source, scanner, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_key, exposure["id"], observation.scope_id, observation.device_id,
                observation.target_ip, observation.port_number, observation.transport,
                observation.service_name, observation.product, observation.version,
                observation.extra_info, observation.service_confidence, observed_at,
                observation.source, observation.scanner, observed_at,
            ),
        )
        observation_row = connection.execute(
            "SELECT * FROM external_exposure_observations WHERE observation_key = ?",
            (observation_key,),
        ).fetchone()
    return {"exposure": _row(exposure), "observation": _row(observation_row)}


def get_external_exposure(exposure_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return _row(connection.execute(
            "SELECT * FROM external_exposures WHERE id = ?", (exposure_id,)
        ).fetchone())


def query_external_exposures(*, scope_id=None, device_id=None, target_ip=None, port_number=None,
                             limit=100, offset=0, db_path=DB_PATH):
    initialize_database(db_path)
    clauses, params = [], []
    for column, value in (("scope_id", scope_id), ("device_id", device_id),
                          ("target_ip", target_ip), ("port_number", port_number)):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""SELECT * FROM external_exposures {where}
                ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
        total = connection.execute(
            f"SELECT COUNT(*) FROM external_exposures {where}", params
        ).fetchone()[0]
    return {"total": total, "items": [_row(row) for row in rows]}


def list_exposure_observations(exposure_id: int, *, limit=100, offset=0, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT * FROM external_exposure_observations
               WHERE exposure_id = ? ORDER BY observed_at DESC, id DESC LIMIT ? OFFSET ?""",
            (exposure_id, limit, offset),
        ).fetchall()
        total = connection.execute(
            "SELECT COUNT(*) FROM external_exposure_observations WHERE exposure_id = ?",
            (exposure_id,),
        ).fetchone()[0]
    return {"total": total, "items": [_row(row) for row in rows]}
