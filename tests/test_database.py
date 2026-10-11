import sqlite3

from database.db import initialize_database, save_event


def test_initialize_database_creates_events_table(tmp_path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'events'
            """
        ).fetchone()

    assert row is not None
    assert row[0] == "events"


def test_save_event_persists_event(tmp_path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    save_event(
        timestamp="2026-10-11T08:34:35",
        source_ip="192.168.122.1",
        username="tanashi",
        event_type="SSH_PREAUTH",
        severity="WARNING",
        message="Repeated SSH pre-auth activity",
        event_count=3,
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT
                timestamp,
                source_ip,
                username,
                event_type,
                severity,
                message,
                event_count
            FROM events
            """
        ).fetchone()

    assert row == (
        "2026-10-11T08:34:35",
        "192.168.122.1",
        "tanashi",
        "SSH_PREAUTH",
        "WARNING",
        "Repeated SSH pre-auth activity",
        3,
    )


def test_save_multiple_events(tmp_path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    save_event(
        timestamp="2026-10-11T08:34:35",
        source_ip="192.168.122.1",
        username=None,
        event_type="SSH_PREAUTH",
        severity="INFO",
        message="SSH pre-auth activity",
        event_count=1,
        db_path=db_path,
    )

    save_event(
        timestamp="2026-10-11T08:34:36",
        source_ip="192.168.122.1",
        username=None,
        event_type="SSH_PREAUTH",
        severity="INFO",
        message="SSH pre-auth activity",
        event_count=2,
        db_path=db_path,
    )

    save_event(
        timestamp="2026-10-11T08:34:37",
        source_ip="192.168.122.1",
        username=None,
        event_type="SSH_PREAUTH",
        severity="WARNING",
        message="Repeated SSH pre-auth activity",
        event_count=3,
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

    assert count == 3


def test_username_can_be_null(tmp_path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    save_event(
        timestamp="2026-10-11T08:34:35",
        source_ip="192.168.122.1",
        username=None,
        event_type="CONNECTION_CLOSED",
        severity="INFO",
        message="CONNECTION_CLOSED",
        event_count=1,
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        username = connection.execute(
            "SELECT username FROM events"
        ).fetchone()[0]

    assert username is None
