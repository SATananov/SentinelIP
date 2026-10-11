from database.db import (
    get_filtered_events,
    initialize_database,
    save_event,
)


def add_event(
    db_path,
    timestamp,
    source_ip,
    severity,
):
    save_event(
        timestamp=timestamp,
        source_ip=source_ip,
        username=None,
        event_type="SSH_PREAUTH",
        severity=severity,
        message="test event",
        event_count=1,
        db_path=db_path,
    )


def test_get_filtered_events_by_severity(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(
        db_path,
        "2026-10-11T10:00:00",
        "10.0.0.1",
        "INFO",
    )

    add_event(
        db_path,
        "2026-10-11T10:01:00",
        "10.0.0.1",
        "ALERT",
    )

    result = get_filtered_events(
        severity="ALERT",
        db_path=db_path,
    )

    assert len(result) == 1
    assert result[0]["severity"] == "ALERT"


def test_get_filtered_events_combined_filters(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(
        db_path,
        "2026-10-11T09:00:00",
        "10.0.0.1",
        "ALERT",
    )

    add_event(
        db_path,
        "2026-10-11T10:00:00",
        "10.0.0.2",
        "ALERT",
    )

    add_event(
        db_path,
        "2026-10-11T10:01:00",
        "10.0.0.2",
        "INFO",
    )

    result = get_filtered_events(
        severity="ALERT",
        source_ip="10.0.0.2",
        since="2026-10-11T09:30:00",
        db_path=db_path,
    )

    assert len(result) == 1
    assert result[0]["source_ip"] == "10.0.0.2"
    assert result[0]["severity"] == "ALERT"
