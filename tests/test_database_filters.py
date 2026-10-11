from database.db import (
    get_paginated_events,
    get_source_ips,
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


def test_filter_by_severity(tmp_path):
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

    result = get_paginated_events(
        severity="ALERT",
        db_path=db_path,
    )

    assert result["total"] == 1
    assert result["items"][0]["severity"] == "ALERT"


def test_filter_by_source_ip(tmp_path):
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
        "10.0.0.2",
        "INFO",
    )

    result = get_paginated_events(
        source_ip="10.0.0.2",
        db_path=db_path,
    )

    assert result["total"] == 1
    assert result["items"][0]["source_ip"] == "10.0.0.2"


def test_filter_by_since(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(
        db_path,
        "2026-10-11T09:00:00",
        "10.0.0.1",
        "INFO",
    )

    add_event(
        db_path,
        "2026-10-11T10:00:00",
        "10.0.0.1",
        "INFO",
    )

    result = get_paginated_events(
        since="2026-10-11T09:30:00",
        db_path=db_path,
    )

    assert result["total"] == 1
    assert result["items"][0]["timestamp"] == (
        "2026-10-11T10:00:00"
    )


def test_get_source_ips(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(
        db_path,
        "2026-10-11T10:00:00",
        "10.0.0.2",
        "INFO",
    )

    add_event(
        db_path,
        "2026-10-11T10:01:00",
        "10.0.0.1",
        "INFO",
    )

    assert get_source_ips(db_path=db_path) == [
        "10.0.0.1",
        "10.0.0.2",
    ]
