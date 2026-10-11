import json
import secrets
import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
from services.telemetry_auth import TOKEN_ITERATIONS, generate_sensor_token, hash_sensor_token
from services.telemetry_models import (
    DnsObservation,
    PrivacyMode,
    SensorType,
    TelemetrySensor,
    WebObservation,
    normalize_url,
)


def _metadata(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) if value is not None else None


def _sensor(row):
    if row is None:
        return None
    result = dict(row)
    result["enabled"] = bool(result["enabled"])
    result["privacy_mode"] = result["privacy_mode"]
    return result


def provision_sensor(
    sensor_key: str,
    name: str,
    sensor_type: str,
    device_id: int | None,
    privacy_mode: str,
    retention_days: int,
    db_path=DB_PATH,
):
    sensor_type = SensorType(sensor_type).value
    privacy_mode = PrivacyMode(privacy_mode).value
    TelemetrySensor(
        sensor_key,
        name,
        sensor_type,
        device_id,
        True,
        privacy_mode,
        retention_days,
        datetime.now().astimezone(),
        datetime.now().astimezone(),
    )
    token = generate_sensor_token()
    salt = secrets.token_bytes(16)
    token_hash = hash_sensor_token(token, salt)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO telemetry_sensors (
                sensor_key, name, sensor_type, device_id, token_salt,
                token_hash, token_iterations, enabled, privacy_mode,
                retention_days, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sensor_key,
                name,
                sensor_type,
                device_id,
                salt,
                token_hash,
                TOKEN_ITERATIONS,
                1,
                privacy_mode,
                retention_days,
                timestamp,
                timestamp,
            ),
        )
        row = connection.execute("SELECT * FROM telemetry_sensors WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _sensor(row), token


def get_sensor(sensor_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM telemetry_sensors WHERE id = ?", (sensor_id,)).fetchone()
    return _sensor(row)


def get_sensor_by_key(sensor_key: str, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM telemetry_sensors WHERE sensor_key = ?", (sensor_key,)).fetchone()
    return _sensor(row)


def list_sensors(db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM telemetry_sensors ORDER BY id ASC").fetchall()
    return [_sensor(row) for row in rows]


def update_sensor_enabled(sensor_id: int, enabled: bool, db_path=DB_PATH):
    initialize_database(db_path)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE telemetry_sensors SET enabled = ?, updated_at = ? WHERE id = ?", (int(enabled), timestamp, sensor_id))
        row = connection.execute("SELECT * FROM telemetry_sensors WHERE id = ?", (sensor_id,)).fetchone()
    return _sensor(row)


def touch_sensor_last_seen(sensor_id: int, timestamp: datetime, db_path=DB_PATH):
    initialize_database(db_path)
    value = timestamp.isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.execute("UPDATE telemetry_sensors SET last_seen_at = ?, updated_at = ? WHERE id = ?", (value, value, sensor_id))


def authenticate_sensor(sensor_id: int, token: str, db_path=DB_PATH):
    from services.telemetry_auth import verify_sensor_token

    sensor = get_sensor(sensor_id, db_path)
    if sensor is None:
        return None
    if not verify_sensor_token(token, sensor["token_salt"], sensor["token_hash"], sensor["token_iterations"]):
        return None
    return sensor


def create_web_observation(observation: WebObservation, db_path=DB_PATH):
    initialize_database(db_path)
    scheme, hostname, path = normalize_url(observation.url, observation.privacy_mode)
    received = observation.received_at.isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO web_observations (
                sensor_id, external_event_id, device_id, observed_at, received_at,
                event_type, scheme, hostname, path, referrer_domain,
                redirect_from_domain, redirect_to_domain, has_login_form,
                has_password_form, download_detected, source, retention_until,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(observation.sensor_id),
                observation.external_event_id,
                observation.device_id,
                observation.observed_at.isoformat(timespec="seconds"),
                received,
                observation.event_type.value,
                scheme,
                hostname,
                path,
                observation.referrer_domain,
                observation.redirect_from_domain,
                observation.redirect_to_domain,
                int(observation.has_login_form),
                int(observation.has_password_form),
                int(observation.download_detected),
                "browser",
                observation.retention_until.isoformat(timespec="seconds"),
                _metadata(observation.metadata),
            ),
        )
        row = connection.execute("SELECT * FROM web_observations WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)


def get_web_observation_by_event(sensor_id: int, external_event_id: str, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM web_observations WHERE sensor_id = ? AND external_event_id = ?", (sensor_id, external_event_id)).fetchone()
    return dict(row) if row else None


def list_web_observations(sensor_id: int | None = None, db_path=DB_PATH, device_id: int | None = None):
    initialize_database(db_path)
    conditions = []
    parameters = []
    if sensor_id is not None:
        conditions.append("sensor_id = ?")
        parameters.append(sensor_id)
    if device_id is not None:
        conditions.append("device_id = ?")
        parameters.append(device_id)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"SELECT * FROM web_observations {where} ORDER BY observed_at ASC, id ASC",
            parameters,
        ).fetchall()
    return [dict(row) for row in rows]


def create_dns_observation(observation: DnsObservation, db_path=DB_PATH):
    initialize_database(db_path)
    received = observation.received_at.isoformat(timespec="seconds")
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO dns_observations (
                sensor_id, external_event_id, device_id, observed_at, received_at,
                queried_domain, query_type, response_status, resolved_addresses_json,
                resolver, ttl, source, retention_until, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(observation.sensor_id),
                observation.external_event_id,
                observation.device_id,
                observation.observed_at.isoformat(timespec="seconds"),
                received,
                observation.queried_domain,
                observation.query_type.value,
                observation.response_status.value,
                json.dumps(observation.resolved_addresses, separators=(",", ":")),
                observation.resolver,
                observation.ttl,
                "dns",
                observation.retention_until.isoformat(timespec="seconds"),
                _metadata(observation.metadata),
            ),
        )
        row = connection.execute("SELECT * FROM dns_observations WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)


def get_dns_observation_by_event(sensor_id: int, external_event_id: str, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM dns_observations WHERE sensor_id = ? AND external_event_id = ?", (sensor_id, external_event_id)).fetchone()
    return dict(row) if row else None


def list_dns_observations(sensor_id: int | None = None, db_path=DB_PATH, device_id: int | None = None):
    initialize_database(db_path)
    conditions = []
    parameters = []
    if sensor_id is not None:
        conditions.append("sensor_id = ?")
        parameters.append(sensor_id)
    if device_id is not None:
        conditions.append("device_id = ?")
        parameters.append(device_id)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"SELECT * FROM dns_observations {where} ORDER BY observed_at ASC, id ASC",
            parameters,
        ).fetchall()
    return [dict(row) for row in rows]