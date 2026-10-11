from database.db import (
    get_overview,
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
