from database.db import (
    get_alerts,
    get_event_count,
    get_recent_events,
    get_top_source_ips,
    initialize_database,
    save_event,
)


def add_event(
    db_path,
    timestamp,
    source_ip,
    severity="INFO",
    event_type="SSH_PREAUTH",
    event_count=1,
):
    save_event(
        timestamp=timestamp,
        source_ip=source_ip,
        username=None,
        event_type=event_type,
        severity=severity,
        message="test event",
        event_count=event_count,
        db_path=db_path,
    )


def test_get_event_count(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(db_path, "2026-10-11T09:00:00", "10.0.0.1")
    add_event(db_path, "2026-10-11T09:00:01", "10.0.0.1")
    add_event(db_path, "2026-10-11T09:00:02", "10.0.0.2")

    assert get_event_count(db_path) == 3


def test_get_recent_events_returns_newest_first(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(db_path, "2026-10-11T09:00:00", "10.0.0.1")
    add_event(db_path, "2026-10-11T09:00:01", "10.0.0.2")
    add_event(db_path, "2026-10-11T09:00:02", "10.0.0.3")

    events = get_recent_events(limit=2, db_path=db_path)

    assert len(events) == 2
    assert events[0]["source_ip"] == "10.0.0.3"
    assert events[1]["source_ip"] == "10.0.0.2"


def test_get_alerts_returns_only_alerts(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(
        db_path,
        "2026-10-11T09:00:00",
        "10.0.0.1",
        severity="INFO",
    )

    add_event(
        db_path,
        "2026-10-11T09:00:01",
        "10.0.0.2",
        severity="ALERT",
        event_count=5,
    )

    alerts = get_alerts(db_path=db_path)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "ALERT"
    assert alerts[0]["source_ip"] == "10.0.0.2"


def test_get_top_source_ips(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(db_path, "2026-10-11T09:00:00", "10.0.0.1")
    add_event(db_path, "2026-10-11T09:00:01", "10.0.0.1")
    add_event(db_path, "2026-10-11T09:00:02", "10.0.0.1")

    add_event(db_path, "2026-10-11T09:00:03", "10.0.0.2")
    add_event(db_path, "2026-10-11T09:00:04", "10.0.0.2")

    add_event(db_path, "2026-10-11T09:00:05", "10.0.0.3")

    result = get_top_source_ips(db_path=db_path)

    assert result == [
        {
            "source_ip": "10.0.0.1",
            "event_total": 3,
        },
        {
            "source_ip": "10.0.0.2",
            "event_total": 2,
        },
        {
            "source_ip": "10.0.0.3",
            "event_total": 1,
        },
    ]
