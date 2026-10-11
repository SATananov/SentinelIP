from database.db import (
    get_events_over_time,
    initialize_database,
    save_event,
)


def add_event(db_path, timestamp, severity):
    save_event(
        timestamp=timestamp,
        source_ip="10.0.0.1",
        username=None,
        event_type="SSH_PREAUTH",
        severity=severity,
        message="test event",
        event_count=1,
        db_path=db_path,
    )


def test_get_events_over_time_groups_by_minute(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(
        db_path,
        "2026-10-11T09:00:01",
        "INFO",
    )

    add_event(
        db_path,
        "2026-10-11T09:00:20",
        "WARNING",
    )

    add_event(
        db_path,
        "2026-10-11T09:01:10",
        "ALERT",
    )

    add_event(
        db_path,
        "2026-10-11T09:01:30",
        "ALERT",
    )

    result = get_events_over_time(
        db_path=db_path,
    )

    assert result == [
        {
            "minute": "2026-10-11T09:00",
            "total": 2,
            "info": 1,
            "warning": 1,
            "alert": 0,
        },
        {
            "minute": "2026-10-11T09:01",
            "total": 2,
            "info": 0,
            "warning": 0,
            "alert": 2,
        },
    ]
