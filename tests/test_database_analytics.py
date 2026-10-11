from database.db import (
    get_event_type_counts,
    get_severity_counts,
    initialize_database,
    save_event,
)


def add_event(
    db_path,
    severity,
    event_type,
    source_ip="10.0.0.1",
):
    save_event(
        timestamp="2026-10-11T09:00:00",
        source_ip=source_ip,
        username=None,
        event_type=event_type,
        severity=severity,
        message="test event",
        event_count=1,
        db_path=db_path,
    )


def test_get_severity_counts(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(db_path, "INFO", "SSH_PREAUTH")
    add_event(db_path, "INFO", "CONNECTION_CLOSED")
    add_event(db_path, "WARNING", "SSH_PREAUTH")
    add_event(db_path, "ALERT", "SSH_PREAUTH")

    result = get_severity_counts(db_path=db_path)

    assert result == [
        {"severity": "ALERT", "total": 1},
        {"severity": "INFO", "total": 2},
        {"severity": "WARNING", "total": 1},
    ]


def test_get_event_type_counts(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)

    add_event(db_path, "INFO", "SSH_PREAUTH")
    add_event(db_path, "INFO", "SSH_PREAUTH")
    add_event(db_path, "WARNING", "SSH_PREAUTH")
    add_event(db_path, "INFO", "CONNECTION_CLOSED")

    result = get_event_type_counts(db_path=db_path)

    assert result == [
        {"event_type": "SSH_PREAUTH", "total": 3},
        {"event_type": "CONNECTION_CLOSED", "total": 1},
    ]
