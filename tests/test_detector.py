from datetime import datetime, timedelta

from services.detector import SSHDetector


def test_info_before_warning():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    result1 = detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now,
    )

    result2 = detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now + timedelta(seconds=1),
    )

    assert result1.severity == "INFO"
    assert result1.count == 1

    assert result2.severity == "INFO"
    assert result2.count == 2


def test_warning_at_three_events():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now,
    )

    detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now + timedelta(seconds=1),
    )

    result = detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now + timedelta(seconds=2),
    )

    assert result.severity == "WARNING"
    assert result.count == 3
    assert (
        result.message
        == "Repeated SSH pre-auth activity"
    )


def test_alert_at_threshold():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
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
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now,
    )

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
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    detector.analyze(
        "SSH_PREAUTH",
        "10.0.0.1",
        now,
    )

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
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    result = detector.analyze(
        "LOGIN_SUCCESS",
        "10.0.0.1",
        now,
    )

    assert result.severity == "INFO"
    assert result.count == 1
    assert result.message == "LOGIN_SUCCESS"


def test_first_failed_login_is_info():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    result = detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now,
        username="tanashi",
    )

    assert result.severity == "INFO"
    assert result.count == 1
    assert result.message == "SSH login failed"


def test_repeated_failed_logins_become_warning():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now,
        username="tanashi",
    )

    detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now + timedelta(seconds=1),
        username="tanashi",
    )

    result = detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now + timedelta(seconds=2),
        username="tanashi",
    )

    assert result.severity == "WARNING"
    assert result.count == 3
    assert (
        result.message
        == "Repeated SSH login failures"
    )


def test_failed_login_threshold_becomes_alert():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    result = None

    for second in range(5):
        result = detector.analyze(
            "LOGIN_FAILED",
            "10.0.0.1",
            now + timedelta(seconds=second),
            username="tanashi",
        )

    assert result is not None
    assert result.severity == "ALERT"
    assert result.count == 5
    assert (
        result.message
        == "Possible SSH brute-force attack"
    )


def test_old_failed_logins_leave_window():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now,
        username="tanashi",
    )

    detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now + timedelta(seconds=10),
        username="tanashi",
    )

    result = detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now + timedelta(seconds=70),
        username="tanashi",
    )

    assert result.severity == "INFO"
    assert result.count == 2


def test_failed_login_counters_are_separate_by_ip():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now,
        username="tanashi",
    )

    detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now + timedelta(seconds=1),
        username="tanashi",
    )

    result = detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.2",
        now + timedelta(seconds=2),
        username="tanashi",
    )

    assert result.severity == "INFO"
    assert result.count == 1


def test_suspicious_username_is_warning():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    result = detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now,
        username="root",
    )

    assert result.severity == "WARNING"
    assert result.count == 1
    assert (
        result.message
        == "Suspicious SSH username attempt"
    )


def test_suspicious_username_check_is_case_insensitive():
    detector = SSHDetector(
        threshold=5,
        window_seconds=60,
    )
    now = datetime.now()

    result = detector.analyze(
        "LOGIN_FAILED",
        "10.0.0.1",
        now,
        username="AdMiN",
    )

    assert result.severity == "WARNING"
    assert result.count == 1
    assert (
        result.message
        == "Suspicious SSH username attempt"
    )
