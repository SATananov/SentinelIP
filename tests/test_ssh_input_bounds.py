import sqlite3

import pytest

import app
from database.db import initialize_database, save_event
from services.ssh_input_limits import (
    MAX_SSH_USERNAME_BYTES,
    SSHUsernameValidationError,
)


def save(db_path, username):
    save_event(
        timestamp="2026-01-01T00:00:00",
        source_ip="203.0.113.7",
        username=username,
        event_type="LOGIN_FAILED",
        severity="INFO",
        message="SSH login failed",
        event_count=1,
        db_path=db_path,
    )


def test_save_event_enforces_utf8_username_byte_limit_before_insert(tmp_path):
    db_path = tmp_path / "username.sqlite3"
    initialize_database(db_path)

    ascii_boundary = "a" * MAX_SSH_USERNAME_BYTES
    multibyte_boundary = "é" * (MAX_SSH_USERNAME_BYTES // 2)
    save(db_path, ascii_boundary)
    save(db_path, multibyte_boundary)
    save(db_path, None)

    for value in ("a" * (MAX_SSH_USERNAME_BYTES + 1), "é" * 129):
        with pytest.raises(SSHUsernameValidationError) as error:
            save(db_path, value)
        assert value not in str(error.value)
        assert "username" in str(error.value).lower()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("SELECT username FROM events ORDER BY id").fetchall() == [
            (ascii_boundary,),
            (multibyte_boundary,),
            (None,),
        ]


def test_live_app_rejects_oversized_username_before_detector_or_database(
    monkeypatch, capsys
):
    class Detector:
        calls = []

        def __init__(self, **_kwargs):
            pass

        def analyze(self, **kwargs):
            self.calls.append(kwargs)
            return type("Result", (), {"severity": "INFO", "count": 1, "message": "ok"})()

    detector = Detector()
    saved = []
    valid = "Failed password for " + "a" * 256 + " from 203.0.113.7 port 22 ssh2"
    oversized = "Failed password for " + "b" * 257 + " from 203.0.113.7 port 22 ssh2"

    monkeypatch.setattr(app, "initialize_database", lambda: None)
    monkeypatch.setattr(app, "SSHDetector", lambda **_kwargs: detector)
    monkeypatch.setattr(app, "stream_ssh_logs", lambda **_kwargs: iter([oversized, oversized, valid]))
    monkeypatch.setattr(app, "save_event", lambda **kwargs: saved.append(kwargs))

    app.main()
    output = capsys.readouterr().out

    assert len(detector.calls) == 1
    assert detector.calls[0]["source_ip"] == "203.0.113.7"
    assert len(saved) == 1
    assert saved[0]["username"] == "a" * 256
    assert output.count("username exceeded the byte limit") == 1
    assert "oversized_username=2" in output
    assert "b" * 257 not in output
