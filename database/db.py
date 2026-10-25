from contextlib import contextmanager
import errno
import logging
import os
import stat
import sqlite3
from pathlib import Path

from database.migrations import apply_migrations
from services.ssh_input_limits import validate_ssh_username


DB_PATH = Path(__file__).resolve().parent / "sentinelip.db"
TOP_SOURCE_SAMPLE_SIZE = 10_000
_PLATFORM_NAME = os.name
_DATABASE_MODE = 0o600
_LOGGER = logging.getLogger(__name__)


class DatabaseSecurityError(PermissionError):
    """The SQLite database path could not be secured before opening it."""


def _database_security_error(path: str, reason: str) -> DatabaseSecurityError:
    return DatabaseSecurityError(
        f"Cannot securely open SQLite database {path!r}: {reason} "
        "Use a regular database file owned by the Core account in an existing "
        "trusted directory, and grant that account permission to set mode 0600."
    )


def _open_flags(*, creating: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if creating:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
    else:
        # A FIFO must never make startup wait for a writer.
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _mode_text(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def _secure_posix_database(path: str) -> None:
    parent = os.path.dirname(path) or os.curdir
    try:
        parent_stat = os.stat(parent)
    except OSError as exc:
        raise _database_security_error(
            path, f"parent directory is unavailable ({exc.strerror})."
        ) from exc
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise _database_security_error(path, "parent path is not a directory.")
    if parent_stat.st_uid != os.geteuid():
        raise _database_security_error(
            path, "parent directory is not owned by the Core account."
        )
    if parent_stat.st_mode & 0o022:
        raise _database_security_error(
            path, "parent directory is group- or world-writable."
        )

    flags = _open_flags()
    nofollow_supported = bool(getattr(os, "O_NOFOLLOW", 0))
    while True:
        try:
            descriptor = os.open(path, _open_flags(creating=True), _DATABASE_MODE)
        except FileExistsError:
            break
        except OSError as exc:
            # Another process may have won the exclusive-create race on a
            # platform that reports EEXIST as a generic OSError.
            if exc.errno == errno.EEXIST:
                break
            raise _database_security_error(
                path, f"secure creation failed ({exc.strerror})."
            ) from exc
        else:
            try:
                file_stat = os.fstat(descriptor)
                if not stat.S_ISREG(file_stat.st_mode):
                    raise _database_security_error(path, "new database path is not a regular file.")
                if file_stat.st_uid != os.geteuid():
                    raise _database_security_error(
                        path, "new database file is not owned by the Core account."
                    )
                if stat.S_IMODE(file_stat.st_mode) != _DATABASE_MODE:
                    os.fchmod(descriptor, _DATABASE_MODE)
                if stat.S_IMODE(os.fstat(descriptor).st_mode) != _DATABASE_MODE:
                    raise _database_security_error(
                        path, "new database file could not be set to mode 0600."
                    )
            except DatabaseSecurityError:
                raise
            except OSError as exc:
                raise _database_security_error(
                    path, f"secure creation could not be verified ({exc.strerror})."
                ) from exc
            finally:
                os.close(descriptor)
            return

    try:
        path_stat = os.lstat(path)
    except OSError as exc:
        raise _database_security_error(path, f"database path cannot be inspected ({exc.strerror}).") from exc
    if stat.S_ISLNK(path_stat.st_mode):
        raise _database_security_error(path, "symbolic links are not permitted.")
    if not stat.S_ISREG(path_stat.st_mode):
        raise _database_security_error(path, "database path must be a regular file.")
    if path_stat.st_uid != os.geteuid():
        raise _database_security_error(path, "database file is not owned by the Core account.")

    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        # An owner may chmod a mode-000 file without opening it. Keep that
        # recovery narrow and re-open with O_NOFOLLOW before SQLite sees it.
        if (exc.errno not in (errno.EACCES, errno.EPERM)
                or stat.S_IMODE(path_stat.st_mode) == _DATABASE_MODE):
            raise _database_security_error(
                path, f"database file cannot be securely opened ({exc.strerror})."
            ) from exc
        try:
            if not nofollow_supported and os.chmod not in os.supports_follow_symlinks:
                raise NotImplementedError("safe chmod of a path is unavailable")
            os.chmod(path, _DATABASE_MODE, follow_symlinks=False)
            descriptor = os.open(path, flags)
        except (OSError, NotImplementedError) as chmod_exc:
            detail = getattr(chmod_exc, "strerror", None) or str(chmod_exc)
            raise _database_security_error(
                path, f"database permissions could not be tightened ({detail})."
            ) from chmod_exc

    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise _database_security_error(path, "database path must be a regular file.")
        if (file_stat.st_dev, file_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise _database_security_error(path, "database path changed during validation.")
        if file_stat.st_uid != os.geteuid():
            raise _database_security_error(path, "database file is not owned by the Core account.")
        old_mode = stat.S_IMODE(file_stat.st_mode)
        if old_mode != _DATABASE_MODE:
            try:
                os.fchmod(descriptor, _DATABASE_MODE)
            except OSError as exc:
                raise _database_security_error(
                    path, f"database permissions could not be tightened ({exc.strerror})."
                ) from exc
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != _DATABASE_MODE:
                raise _database_security_error(
                    path, "database file could not be set to mode 0600."
                )
            _LOGGER.info(
                "Tightened SQLite database permissions path=%s old_mode=%s new_mode=0600",
                path,
                _mode_text(old_mode),
            )
    except DatabaseSecurityError:
        raise
    except OSError as exc:
        raise _database_security_error(
            path, f"database security could not be verified ({exc.strerror})."
        ) from exc
    finally:
        os.close(descriptor)


def _secure_database_path(db_path) -> str:
    if db_path == ":memory:":
        return ":memory:"
    try:
        path = os.path.abspath(os.fsdecode(os.fspath(db_path)))
    except (TypeError, ValueError, OSError) as exc:
        raise DatabaseSecurityError(
            "SQLite database path must be a filesystem path or ':memory:'."
        ) from exc

    if _PLATFORM_NAME != "posix":
        platform_name = "Windows" if _PLATFORM_NAME == "nt" else _PLATFORM_NAME
        raise _database_security_error(
            path,
            f"{platform_name} ACL hardening is not implemented; file-backed databases "
            "are refused until platform verification is complete.",
        )
    _secure_posix_database(path)
    return path


def get_connection(db_path=DB_PATH):
    secured_path = _secure_database_path(db_path)
    connection = sqlite3.connect(secured_path)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                event_count INTEGER NOT NULL
            )
            """
        )
        connection.commit()
        apply_migrations(connection)


@contextmanager
def connection_context(db_path=DB_PATH, *, conn: sqlite3.Connection | None = None):
    """Use a caller-owned connection or initialize and own a standalone one.

    With ``conn`` supplied, ``db_path`` is ignored and the caller retains
    responsibility for the transaction and connection lifecycle. The supplied
    connection must have foreign keys enabled and use ``sqlite3.Row`` results.
    """
    if conn is not None:
        yield conn
        return

    initialize_database(db_path)
    with get_connection(db_path) as connection:
        yield connection


def save_event(
    timestamp: str,
    source_ip: str,
    username: str | None,
    event_type: str,
    severity: str,
    message: str,
    event_count: int,
    db_path=DB_PATH,
):
    validate_ssh_username(username)
    with get_connection(db_path) as connection:
        connection.execute(
            """
            INSERT INTO events (
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count,
            ),
        )
        connection.commit()


def get_recent_events(limit: int = 20, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_alerts(limit: int = 20, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            WHERE severity = 'ALERT'
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_event_count(db_path=DB_PATH) -> int:
    with get_connection(db_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()

    return row[0]


def get_top_source_ips(limit: int = 10, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                source_ip,
                COUNT(*) AS event_total
            FROM events
            GROUP BY source_ip
            ORDER BY event_total DESC, source_ip ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def find_source_ip(source_ip: str, db_path=DB_PATH) -> str | None:
    """Return the exact stored source IP, if at least one event has it."""
    with get_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT source_ip
            FROM events
            WHERE source_ip = ?
            LIMIT 1
            """,
            (source_ip,),
        ).fetchone()

    return row[0] if row else None


def get_recent_top_source_ips(limit: int = 10, db_path=DB_PATH):
    """Return sample-local event totals for top sources in the newest events."""
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT source_ip, COUNT(*) AS event_total
            FROM (
                SELECT source_ip
                FROM events
                ORDER BY id DESC
                LIMIT ?
            )
            GROUP BY source_ip
            ORDER BY event_total DESC, source_ip ASC
            LIMIT ?
            """,
            (TOP_SOURCE_SAMPLE_SIZE, limit),
        ).fetchall()

    return [dict(row) for row in rows]


def get_severity_counts(db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                severity,
                COUNT(*) AS total
            FROM events
            GROUP BY severity
            ORDER BY severity ASC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def get_event_type_counts(db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                event_type,
                COUNT(*) AS total
            FROM events
            GROUP BY event_type
            ORDER BY total DESC, event_type ASC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def get_events_over_time(limit: int = 30, db_path=DB_PATH):
    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                substr(timestamp, 1, 16) AS minute,
                COUNT(*) AS total,
                SUM(
                    CASE
                        WHEN severity = 'INFO'
                        THEN 1
                        ELSE 0
                    END
                ) AS info,
                SUM(
                    CASE
                        WHEN severity = 'WARNING'
                        THEN 1
                        ELSE 0
                    END
                ) AS warning,
                SUM(
                    CASE
                        WHEN severity = 'ALERT'
                        THEN 1
                        ELSE 0
                    END
                ) AS alert
            FROM events
            GROUP BY substr(timestamp, 1, 16)
            ORDER BY minute DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in reversed(rows)]


def get_overview(db_path=DB_PATH):
    severity_counts = get_severity_counts(db_path=db_path)

    severity_map = {
        "INFO": 0,
        "WARNING": 0,
        "ALERT": 0,
    }

    for item in severity_counts:
        severity = item["severity"]

        if severity in severity_map:
            severity_map[severity] = item["total"]

    return {
        "total_events": get_event_count(db_path=db_path),
        "severity": severity_map,
        "top_ips": get_recent_top_source_ips(
            limit=5,
            db_path=db_path,
        ),
        "top_ips_basis": {
            "mode": "latest_events",
            "sample_size": TOP_SOURCE_SAMPLE_SIZE,
        },
        "event_types": get_event_type_counts(
            db_path=db_path,
        ),
    }


def get_paginated_events(
    limit: int = 20,
    offset: int = 0,
    severity: str | None = None,
    source_ip: str | None = None,
    since: str | None = None,
    db_path=DB_PATH,
):
    conditions = []
    parameters = []

    if severity is not None:
        conditions.append("severity = ?")
        parameters.append(severity)

    if source_ip is not None:
        conditions.append("source_ip = ?")
        parameters.append(source_ip)

    if since is not None:
        conditions.append("timestamp >= ?")
        parameters.append(since)

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            f"""
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            {where_clause}
            ORDER BY id DESC
            LIMIT ?
            OFFSET ?
            """,
            (*parameters, limit, offset),
        ).fetchall()

        total = connection.execute(
            f"""
            SELECT COUNT(*)
            FROM events
            {where_clause}
            """,
            parameters,
        ).fetchone()[0]

    return {
        "total": total,
        "items": [dict(row) for row in rows],
    }


def get_filtered_events(
    severity: str | None = None,
    source_ip: str | None = None,
    since: str | None = None,
    db_path=DB_PATH,
):
    conditions = []
    parameters = []

    if severity is not None:
        conditions.append("severity = ?")
        parameters.append(severity)

    if source_ip is not None:
        conditions.append("source_ip = ?")
        parameters.append(source_ip)

    if since is not None:
        conditions.append("timestamp >= ?")
        parameters.append(since)

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    with get_connection(db_path) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            f"""
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            {where_clause}
            ORDER BY id DESC
            """,
            parameters,
        ).fetchall()

    return [dict(row) for row in rows]
