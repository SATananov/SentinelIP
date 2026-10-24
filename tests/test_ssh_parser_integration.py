import sqlite3
from datetime import datetime, timedelta

from collectors.ssh_logs import parse_ssh_line
from database.db import initialize_database, save_event
from services.detector import SSHDetector


def test_corrected_source_flows_to_detector_and_persisted_event(tmp_path):
    db_path = tmp_path / "ssh-parser.sqlite3"
    initialize_database(db_path)
    detector = SSHDetector(threshold=5, window_seconds=60)
    now = datetime(2026, 1, 1, 12, 0, 0)
    lines = [
        "Failed password for invalid user 192.0.2.99 from 203.0.113.7 "
        "port 55555 ssh2",
        "Failed password for 198.51.100.44 from 203.0.113.7 port 55556 ssh2",
    ]

    for index, line in enumerate(lines):
        event = parse_ssh_line(line)
        assert event is not None
        # Match app.py: detector receives event type/source/time, not username.
        result = detector.analyze(
            event_type=event.event_type,
            source_ip=event.source_ip,
            timestamp=now + timedelta(seconds=index),
        )
        save_event(
            timestamp=(now + timedelta(seconds=index)).isoformat(timespec="seconds"),
            source_ip=event.source_ip,
            username=event.username,
            event_type=event.event_type,
            severity=result.severity,
            message=result.message,
            event_count=result.count,
            db_path=db_path,
        )

    assert list(detector.failed_logins) == ["203.0.113.7"]
    assert list(detector.failed_logins["203.0.113.7"]) == [
        now,
        now + timedelta(seconds=1),
    ]

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT source_ip, username, event_type, severity, message, event_count "
            "FROM events ORDER BY id"
        ).fetchall()

    assert rows == [
        (
            "203.0.113.7",
            "192.0.2.99",
            "LOGIN_FAILED",
            "INFO",
            "SSH login failed",
            1,
        ),
        (
            "203.0.113.7",
            "198.51.100.44",
            "LOGIN_FAILED",
            "INFO",
            "SSH login failed",
            2,
        ),
    ]


def test_rejected_line_has_no_detector_or_database_side_effect(tmp_path):
    db_path = tmp_path / "ssh-parser-rejected.sqlite3"
    initialize_database(db_path)
    detector = SSHDetector(threshold=5, window_seconds=60)
    rejected = "Failed password for admin from 999.999.999.999 port 22 ssh2"

    event = parse_ssh_line(rejected)
    if event is not None:
        result = detector.analyze(
            event_type=event.event_type,
            source_ip=event.source_ip,
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
        )
        save_event(
            timestamp="2026-01-01T12:00:00",
            source_ip=event.source_ip,
            username=event.username,
            event_type=event.event_type,
            severity=result.severity,
            message=result.message,
            event_count=result.count,
            db_path=db_path,
        )

    assert not detector.failed_logins
    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
