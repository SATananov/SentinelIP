import sqlite3

from database.db import (
    get_overview,
    get_top_source_ips,
    initialize_database,
    save_event,
)


def add_event(
    db_path,
    source_ip,
    event_type,
    severity,
):
    save_event(
        timestamp="2026-10-11T10:00:00",
        source_ip=source_ip,
        username=None,
        event_type=event_type,
        severity=severity,
        message="test event",
        event_count=1,
        db_path=db_path,
    )


def test_get_overview(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(
        db_path,
        "10.0.0.1",
        "SSH_PREAUTH",
        "INFO",
    )

    add_event(
        db_path,
        "10.0.0.1",
        "SSH_PREAUTH",
        "WARNING",
    )

    add_event(
        db_path,
        "10.0.0.1",
        "SSH_PREAUTH",
        "ALERT",
    )

    add_event(
        db_path,
        "10.0.0.2",
        "LOGIN_SUCCESS",
        "INFO",
    )

    result = get_overview(db_path=db_path)

    assert result["total_events"] == 4

    assert result["severity"] == {
        "INFO": 2,
        "WARNING": 1,
        "ALERT": 1,
    }

    assert result["top_ips"] == [
        {
            "source_ip": "10.0.0.1",
            "event_total": 3,
        },
        {
            "source_ip": "10.0.0.2",
            "event_total": 1,
        },
    ]
    assert result["top_ips_basis"] == {
        "mode": "latest_events",
        "sample_size": 10_000,
    }

    assert result["event_types"] == [
        {
            "event_type": "SSH_PREAUTH",
            "total": 3,
        },
        {
            "event_type": "LOGIN_SUCCESS",
            "total": 1,
        },
    ]


def test_overview_top_ip_counts_use_sample_but_total_and_report_are_historical(tmp_path):
    from database.db import TOP_SOURCE_SAMPLE_SIZE

    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.executemany(
            """
            INSERT INTO events (
                timestamp, source_ip, event_type, severity, message, event_count
            ) VALUES (?, ?, 'SSH_PREAUTH', 'INFO', 'test', 1)
            """,
            [("2026-10-11T09:00:00", "192.0.2.1")] * (TOP_SOURCE_SAMPLE_SIZE + 5_000)
            + [("2026-10-11T09:00:01", "198.51.100.1")]
            * (TOP_SOURCE_SAMPLE_SIZE - 1)
            + [("2026-10-11T09:00:02", "192.0.2.1")],
        )

    overview = get_overview(db_path=db_path)
    assert overview["total_events"] == 25_000
    assert overview["top_ips"] == [
        {"source_ip": "198.51.100.1", "event_total": 9_999},
        {"source_ip": "192.0.2.1", "event_total": 1},
    ]
    assert get_top_source_ips(limit=5, db_path=db_path)[0] == {
        "source_ip": "192.0.2.1",
        "event_total": 15_001,
    }
