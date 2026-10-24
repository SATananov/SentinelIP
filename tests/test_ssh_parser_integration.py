import sqlite3
from datetime import datetime, timedelta

from collectors.ssh_logs import parse_ssh_line
from database.db import initialize_database, save_event
from services.detector import SSHDetector


class FakeMonotonicClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def test_corrected_source_flows_to_detector_and_persisted_event(tmp_path):
    db_path = tmp_path / "ssh-parser.sqlite3"
    initialize_database(db_path)
    clock = FakeMonotonicClock()
    detector = SSHDetector(threshold=5, window_seconds=60, clock=clock)
    now = datetime(2026, 1, 1, 12, 0, 0)
    wall_times = [now, now - timedelta(days=1), now + timedelta(days=365)]
    lines = [
        "Failed password for invalid user 192.0.2.99 from 203.0.113.7 "
        "port 55555 ssh2",
        "Failed password for 198.51.100.44 from 203.0.113.7 port 55556 ssh2",
        "Failed password for admin from 203.0.113.7 port 55557 ssh2",
    ]

    for index, line in enumerate(lines):
        event = parse_ssh_line(line)
        assert event is not None
        # Match app.py: detector uses monotonic time, not persistence time or username.
        result = detector.analyze(
            event_type=event.event_type,
            source_ip=event.source_ip,
        )
        save_event(
            timestamp=wall_times[index].isoformat(timespec="seconds"),
            source_ip=event.source_ip,
            username=event.username,
            event_type=event.event_type,
            severity=result.severity,
            message=result.message,
            event_count=result.count,
            db_path=db_path,
        )
        clock.advance(1)

    assert detector.failed_logins == {"203.0.113.7": 3}

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT timestamp, source_ip, username, event_type, severity, message, event_count "
            "FROM events ORDER BY id"
        ).fetchall()

    assert rows == [
        (
            "2026-01-01T12:00:00",
            "203.0.113.7",
            "192.0.2.99",
            "LOGIN_FAILED",
            "INFO",
            "SSH login failed",
            1,
        ),
        (
            "2025-12-31T12:00:00",
            "203.0.113.7",
            "198.51.100.44",
            "LOGIN_FAILED",
            "INFO",
            "SSH login failed",
            2,
        ),
        (
            "2027-01-01T12:00:00",
            "203.0.113.7",
            "admin",
            "LOGIN_FAILED",
            "WARNING",
            "Repeated SSH login failures",
            3,
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
