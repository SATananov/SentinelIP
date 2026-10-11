from datetime import datetime, timedelta

from services.detector import SSHDetector


def test_info_before_warning():
    detector = SSHDetector(threshold=5, window_seconds=60)
    now = datetime.now()

    result1 = detector.analyze("SSH_PREAUTH", "10.0.0.1", now)
    result2 = detector.analyze("SSH_PREAUTH", "10.0.0.1", now + timedelta(seconds=1))

    assert result1.severity == "INFO"
    assert result1.count == 1

    assert result2.severity == "INFO"
    assert result2.count == 2


def test_warning_at_three_events():
    detector = SSHDetector(threshold=5, window_seconds=60)
    now = datetime.now()

    detector.analyze("SSH_PREAUTH", "10.0.0.1", now)
    detector.analyze("SSH_PREAUTH", "10.0.0.1", now + timedelta(seconds=1))
    result = detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now + timedelta(seconds=2),
    )

    assert result.severity == "WARNING"
    assert result.count == 3


def test_alert_at_threshold():
    detector = SSHDetector(threshold=5, window_seconds=60)
    now = datetime.now()

    result = None

    for second in range(5):
        result = detector.analyze(
            "SSH_PREAUTH",
            "10.0.0.1",
            now + timedelta(seconds=second),
        )

    assert result is not None
    assert result.severity == "ALERT"
    assert result.count == 5
    assert result.message == "Possible SSH scan"


def test_old_events_leave_window():
    detector = SSHDetector(threshold=5, window_seconds=60)
    now = datetime.now()

    detector.analyze("SSH_PREAUTH", "10.0.0.1", now)
    detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now + timedelta(seconds=10),
    )

    result = detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now + timedelta(seconds=70),
    )

    assert result.severity == "INFO"
    assert result.count == 2


def test_different_ips_have_separate_counters():
    detector = SSHDetector(threshold=5, window_seconds=60)
    now = datetime.now()

    detector.analyze("SSH_PREAUTH", "10.0.0.1", now)
    detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now + timedelta(seconds=1),
    )

    result = detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.2",
        now + timedelta(seconds=2),
    )

    assert result.severity == "INFO"
    assert result.count == 1


def test_non_preauth_event_is_info():
    detector = SSHDetector(threshold=5, window_seconds=60)
    now = datetime.now()

    result = detector.analyze(
        "LOGIN_SUCCESS",
        "10.0.0.1",
        now,
    )

    assert result.severity == "INFO"
    assert result.count == 1
    assert result.message == "LOGIN_SUCCESS"
