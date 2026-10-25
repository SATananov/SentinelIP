import sqlite3

from database.db import DB_PATH, connection_context, get_connection, initialize_database


def _as_record(row):
    return dict(row) if row is not None else None


def create_port(
    device_id: int,
    port_number: int,
    transport: str,
    state: str,
    first_seen: str,
    last_seen: str,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        connection.execute(
            """
            INSERT INTO ports (
                device_id,
                port_number,
                transport,
                state,
                first_seen,
                last_seen,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                port_number,
                transport,
                state,
                first_seen,
                last_seen,
                first_seen,
                last_seen,
            ),
        )
        row = connection.execute(
            """
            SELECT * FROM ports
            WHERE device_id = ? AND port_number = ? AND transport = ?
            """,
            (device_id, port_number, transport),
        ).fetchone()

    return _as_record(row)


def find_port(
    device_id: int,
    port_number: int,
    transport: str,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT * FROM ports
            WHERE device_id = ? AND port_number = ? AND transport = ?
            """,
            (device_id, port_number, transport),
        ).fetchone()

    return _as_record(row)


def list_ports(device_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT * FROM ports
            WHERE device_id = ?
            ORDER BY port_number ASC, transport ASC
            """,
            (device_id,),
        ).fetchall()

    return [_as_record(row) for row in rows]


def update_port(
    port_id: int,
    last_seen: str,
    state: str,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        connection.execute(
            """
            UPDATE ports
            SET last_seen = ?, state = ?, updated_at = ?
            WHERE id = ?
            """,
            (last_seen, state, last_seen, port_id),
        )
        row = connection.execute(
            "SELECT * FROM ports WHERE id = ?",
            (port_id,),
        ).fetchone()

    return _as_record(row)


def save_port_observation(
    device_id: int,
    port_id: int,
    ip_address: str,
    port_number: int,
    transport: str,
    state: str,
    observed_at: str,
    source: str,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO port_observations (
                device_id,
                port_id,
                ip_address,
                port_number,
                transport,
                state,
                observed_at,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                port_id,
                ip_address,
                port_number,
                transport,
                state,
                observed_at,
                source,
            ),
        )
        row = connection.execute(
            "SELECT * FROM port_observations WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return _as_record(row)


def list_port_observations(port_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT * FROM port_observations
            WHERE port_id = ?
            ORDER BY observed_at ASC, id ASC
            """,
            (port_id,),
        ).fetchall()

    return [_as_record(row) for row in rows]


def create_service(
    device_id: int,
    port_id: int,
    service_name: str | None,
    product: str | None,
    version: str | None,
    extra_info: str | None,
    confidence: str,
    first_seen: str,
    last_seen: str,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        connection.execute(
            """
            INSERT INTO services (
                device_id,
                port_id,
                service_name,
                product,
                version,
                extra_info,
                confidence,
                first_seen,
                last_seen,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                port_id,
                service_name,
                product,
                version,
                extra_info,
                confidence,
                first_seen,
                last_seen,
                first_seen,
                last_seen,
            ),
        )
        row = connection.execute(
            "SELECT * FROM services WHERE port_id = ?",
            (port_id,),
        ).fetchone()

    return _as_record(row)


def find_service_by_port(
    port_id: int, db_path=DB_PATH, conn: sqlite3.Connection | None = None
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM services WHERE port_id = ?",
            (port_id,),
        ).fetchone()

    return _as_record(row)


def list_services(device_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT * FROM services
            WHERE device_id = ?
            ORDER BY port_id ASC
            """,
            (device_id,),
        ).fetchall()

    return [_as_record(row) for row in rows]


def update_service(
    service_id: int,
    service_name: str | None,
    product: str | None,
    version: str | None,
    extra_info: str | None,
    confidence: str,
    last_seen: str,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        connection.execute(
            """
            UPDATE services
            SET
                service_name = COALESCE(?, service_name),
                product = COALESCE(?, product),
                version = COALESCE(?, version),
                extra_info = COALESCE(?, extra_info),
                confidence = ?,
                last_seen = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                service_name,
                product,
                version,
                extra_info,
                confidence,
                last_seen,
                last_seen,
                service_id,
            ),
        )
        row = connection.execute(
            "SELECT * FROM services WHERE id = ?",
            (service_id,),
        ).fetchone()

    return _as_record(row)


def save_service_observation(
    service_id: int,
    device_id: int,
    port_id: int,
    service_name: str | None,
    product: str | None,
    version: str | None,
    extra_info: str | None,
    confidence: str,
    observed_at: str,
    source: str,
    db_path=DB_PATH,
    conn: sqlite3.Connection | None = None,
):
    with connection_context(db_path, conn=conn) as connection:
        if conn is None:
            connection.row_factory = sqlite3.Row
        cursor = connection.execute(
            """
            INSERT INTO service_observations (
                service_id,
                device_id,
                port_id,
                service_name,
                product,
                version,
                extra_info,
                confidence,
                observed_at,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                service_id,
                device_id,
                port_id,
                service_name,
                product,
                version,
                extra_info,
                confidence,
                observed_at,
                source,
            ),
        )
        row = connection.execute(
            "SELECT * FROM service_observations WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    return _as_record(row)


def list_service_observations(service_id: int, db_path=DB_PATH):
    initialize_database(db_path)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT * FROM service_observations
            WHERE service_id = ?
            ORDER BY observed_at ASC, id ASC
            """,
            (service_id,),
        ).fetchall()

    return [_as_record(row) for row in rows]
