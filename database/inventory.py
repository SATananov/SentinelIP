import sqlite3
from datetime import datetime

from database.db import DB_PATH, get_connection, initialize_database
from services.public_target_policy import PublicTargetPolicyError, normalize_public_ipv4


def _as_device(row):
    return dict(row) if row is not None else None


def _as_observation(row):
    return dict(row) if row is not None else None


def create_device(
    stable_key: str,
    network_id: int,
    mac_address: str | None,
    hostname: str | None,
    vendor: str | None,
    first_seen: str,
    last_seen: str,
    last_ip_address: str,
    status: str,
    identity_confidence: str,
    db_path=DB_PATH,
):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            INSERT INTO devices (
                stable_key,
                network_id,
                mac_address,
                hostname,
                vendor,
                first_seen,
                last_seen,
                last_ip_address,
                status,
                identity_confidence,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stable_key,
                network_id,
                mac_address,
                hostname,
                vendor,
                first_seen,
                last_seen,
                last_ip_address,
                status,
                identity_confidence,
                first_seen,
                last_seen,
            ),
        )
        row = connection.execute(
            "SELECT * FROM devices WHERE stable_key = ?",
            (stable_key,),
        ).fetchone()

    return _as_device(row)


def create_scope_device(
    scope_id: int,
    *,
    ip_address: str | None = None,
    first_seen: str,
    last_seen: str,
    status: str,
    db_path=DB_PATH,
):
    """Create or refresh the one inventory device belonging to a public scope."""
    if type(scope_id) is not int or scope_id <= 0:
        raise ValueError("Scope ID must be positive.")
    if status not in {"ONLINE", "OFFLINE"}:
        raise ValueError("Device status is invalid.")
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        scope = connection.execute(
            "SELECT * FROM authorized_scopes WHERE id = ?", (scope_id,)
        ).fetchone()
        if (
            scope is None
            or scope["scope_type"] not in {"PUBLIC_IPV4", "HOSTNAME"}
            or scope["authorized"] != 1
            or scope["enabled"] != 1
            or not all(
                scope[field]
                for field in (
                    "authorization_confirmed_at",
                    "authorization_confirmation_version",
                    "authorization_source",
                )
            )
        ):
            raise ValueError("An enabled, confirmed public target scope is required.")
        if scope["scope_type"] == "PUBLIC_IPV4":
            try:
                address = normalize_public_ipv4(scope["canonical_target"])
            except PublicTargetPolicyError as exc:
                raise ValueError("The public scope target is invalid.") from exc
            if ip_address is not None and normalize_public_ipv4(ip_address) != address:
                raise ValueError("Device address does not match the public scope.")
        else:
            if scope["resolution_status"] != "CURRENT":
                raise ValueError("Hostname resolution must be current before inventory is updated.")
            try:
                address = normalize_public_ipv4(ip_address)
            except PublicTargetPolicyError as exc:
                raise ValueError("A valid approved hostname address is required.") from exc
            approved = connection.execute(
                """SELECT 1 FROM scope_hostname_addresses
                   WHERE scope_id = ? AND ipv4_address = ? AND approved = 1""",
                (scope_id, address),
            ).fetchone()
            if approved is None:
                raise ValueError("Device address is not approved for this hostname scope.")
        stable_key = f"scope:{scope_id}:ipv4:{address}"
        existing = connection.execute(
            "SELECT id FROM devices WHERE stable_key = ?", (stable_key,)
        ).fetchone()
        if existing is None:
            cursor = connection.execute(
                """INSERT INTO devices (
                    stable_key, network_id, scope_id, mac_address, hostname, vendor,
                    first_seen, last_seen, last_ip_address, status,
                    identity_confidence, created_at, updated_at
                ) VALUES (?, NULL, ?, NULL, NULL, NULL, ?, ?, ?, ?, 'LOW', ?, ?)""",
                (
                    stable_key,
                    scope_id,
                    first_seen,
                    last_seen,
                    address,
                    status,
                    first_seen,
                    last_seen,
                ),
            )
            device_id = cursor.lastrowid
        else:
            device_id = existing["id"]
            connection.execute(
                """UPDATE devices
                   SET last_seen = ?, last_ip_address = ?, status = ?, updated_at = ?
                   WHERE id = ? AND scope_id = ? AND network_id IS NULL""",
                (last_seen, address, status, last_seen, device_id, scope_id),
            )
        row = connection.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
    return _as_device(row)


def list_scope_devices(scope_id: int, db_path=DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM devices WHERE scope_id = ? ORDER BY id ASC",
            (scope_id,),
        ).fetchall()
    return [_as_device(row) for row in rows]


def save_scope_device_observation(
    *, scope_id: int, device_id: int, ip_address: str, status: str,
    observed_at: str, source: str, db_path=DB_PATH,
):
    address = normalize_public_ipv4(ip_address)
    initialize_database(db_path)
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        owned_device = connection.execute(
            """SELECT 1 FROM devices d
               JOIN authorized_scopes s ON s.id = d.scope_id
               WHERE d.id = ? AND d.scope_id = ? AND d.network_id IS NULL
                 AND d.last_ip_address = ? AND s.authorized = 1 AND s.enabled = 1
                 AND (s.scope_type = 'PUBLIC_IPV4' AND s.canonical_target = ?
                      OR s.scope_type = 'HOSTNAME' AND EXISTS (
                          SELECT 1 FROM scope_hostname_addresses a
                          WHERE a.scope_id = s.id AND a.ipv4_address = ? AND a.approved = 1
                      ))""",
            (device_id, scope_id, address, address, address),
        ).fetchone()
        if owned_device is None:
            raise ValueError("Device does not belong to the public target scope.")
        cursor = connection.execute(
            """INSERT INTO scope_device_observations (
                scope_id, device_id, ip_address, status, observed_at, source
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (scope_id, device_id, address, status, observed_at, source),
        )
        row = connection.execute(
            "SELECT * FROM scope_device_observations WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    return dict(row)


def get_device(device_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()

    return _as_device(row)


def find_device_by_stable_key(stable_key: str, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM devices WHERE stable_key = ?",
            (stable_key,),
        ).fetchone()

    return _as_device(row)


def list_devices(network_id: int | None = None, db_path=DB_PATH):
    initialize_database(db_path)
    parameters = []
    where_clause = ""

    if network_id is not None:
        where_clause = "WHERE network_id = ?"
        parameters.append(network_id)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT *
            FROM devices
            {where_clause}
            ORDER BY id ASC
            """,
            parameters,
        ).fetchall()

    return [_as_device(row) for row in rows]


def update_device_state(
    device_id: int,
    *,
    last_seen: str,
    last_ip_address: str,
    status: str,
    mac_address: str | None,
    hostname: str | None,
    vendor: str | None,
    db_path=DB_PATH,
):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            UPDATE devices
            SET
                mac_address = COALESCE(?, mac_address),
                hostname = COALESCE(?, hostname),
                vendor = COALESCE(?, vendor),
                last_seen = ?,
                last_ip_address = ?,
                status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                mac_address,
                hostname,
                vendor,
                last_seen,
                last_ip_address,
                status,
                last_seen,
                device_id,
            ),
        )
        row = connection.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()

    return _as_device(row)


def save_observation(
    device_id: int,
    network_id: int,
    ip_address: str,
    mac_address: str | None,
    hostname: str | None,
    vendor: str | None,
    status: str,
    observed_at: str,
    source: str,
    db_path=DB_PATH,
):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO device_observations (
                device_id,
                network_id,
                ip_address,
                mac_address,
                hostname,
                vendor,
                status,
                observed_at,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                network_id,
                ip_address,
                mac_address,
                hostname,
                vendor,
                status,
                observed_at,
                source,
            ),
        )
        row = connection.execute(
            "SELECT * FROM device_observations WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return _as_observation(row)


def list_observations(device_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT *
            FROM device_observations
            WHERE device_id = ?
            ORDER BY observed_at ASC, id ASC
            """,
            (device_id,),
        ).fetchall()

    return [_as_observation(row) for row in rows]


def mark_devices_offline(
    network_id: int,
    observed_device_ids: set[int],
    observed_at: str,
    db_path=DB_PATH,
):
    initialize_database(db_path)
    parameters = [observed_at, network_id]
    exclusion = ""

    if observed_device_ids:
        placeholders = ", ".join("?" for _ in observed_device_ids)
        exclusion = f"AND id NOT IN ({placeholders})"
        parameters.extend(sorted(observed_device_ids))

    with get_connection(db_path) as connection:
        connection.execute(
            f"""
            UPDATE devices
            SET status = 'OFFLINE', updated_at = ?
            WHERE network_id = ?
              {exclusion}
              AND status != 'OFFLINE'
            """,
            parameters,
        )


def timestamp_text(value: datetime) -> str:
    return value.isoformat(timespec="seconds")
