from services.detector import SSHDetector


class FakeMonotonicClock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def make_detector(**kwargs):
    clock = FakeMonotonicClock()
    return SSHDetector(clock=clock, **kwargs), clock


def test_info_before_warning():
    detector, clock = make_detector()
    result1 = detector.analyze("SSH_PREAUTH", "10.0.0.1")
    clock.advance(1)
    result2 = detector.analyze("SSH_PREAUTH", "10.0.0.1")

    assert (result1.severity, result1.count) == ("INFO", 1)
    assert (result2.severity, result2.count) == ("INFO", 2)


def test_warning_at_three_events():
    detector, clock = make_detector()
    for _ in range(2):
        detector.analyze("SSH_PREAUTH", "10.0.0.1")
        clock.advance(1)
    result = detector.analyze("SSH_PREAUTH", "10.0.0.1")

    assert result.severity == "WARNING"
    assert result.count == 3
    assert result.message == "Repeated SSH pre-auth activity"


def test_alert_at_threshold_and_exact_count_above_threshold():
    detector, clock = make_detector()
    results = []
    for _ in range(6):
        results.append(detector.analyze("SSH_PREAUTH", "10.0.0.1"))
        clock.advance(1)

    assert [result.count for result in results] == [1, 2, 3, 4, 5, 6]
    assert [result.severity for result in results] == [
        "INFO", "INFO", "WARNING", "WARNING", "ALERT", "ALERT"
    ]
    assert results[4].message == "Possible SSH scan"


def test_old_preauth_events_leave_window():
    detector, clock = make_detector()
    detector.analyze("SSH_PREAUTH", "10.0.0.1")
    clock.advance(10)
    detector.analyze("SSH_PREAUTH", "10.0.0.1")
    clock.advance(60)
    result = detector.analyze("SSH_PREAUTH", "10.0.0.1")

    assert result.severity == "INFO"
    assert result.count == 2


def test_different_ips_have_separate_preauth_counters():
    detector, clock = make_detector()
    detector.analyze("SSH_PREAUTH", "10.0.0.1")
    clock.advance(1)
    detector.analyze("SSH_PREAUTH", "10.0.0.1")
    clock.advance(1)
    result = detector.analyze("SSH_PREAUTH", "10.0.0.2")

    assert (result.severity, result.count) == ("INFO", 1)


def test_login_success_and_connection_closed_remain_stateless():
    detector, _clock = make_detector()
    for event_type in ("LOGIN_SUCCESS", "CONNECTION_CLOSED"):
        result = detector.analyze(event_type, "10.0.0.1")
        assert (result.severity, result.count, result.message) == (
            "INFO", 1, event_type
        )
    assert not detector.events
    assert not detector.failed_logins
    assert not detector._rolling_events


def test_first_failed_login_is_info_and_keeps_existing_message():
    detector, _clock = make_detector()
    result = detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")

    assert (result.severity, result.count, result.message) == (
        "INFO", 1, "SSH login failed"
    )


def test_repeated_failed_logins_become_warning():
    detector, clock = make_detector()
    for _ in range(2):
        detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")
        clock.advance(1)
    result = detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")

    assert result.severity == "WARNING"
    assert result.count == 3
    assert result.message == "Repeated SSH login failures"


def test_failed_login_threshold_becomes_alert_without_saturation():
    detector, clock = make_detector()
    results = []
    for _ in range(7):
        results.append(
            detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")
        )
        clock.advance(1)

    assert [result.count for result in results] == list(range(1, 8))
    assert results[4].severity == "ALERT"
    assert results[4].message == "Possible SSH brute-force attack"


def test_old_failed_logins_leave_window():
    detector, clock = make_detector()
    detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")
    clock.advance(10)
    detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")
    clock.advance(60)
    result = detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")

    assert result.severity == "INFO"
    assert result.count == 2


def test_failed_login_counters_are_separate_by_ip():
    detector, clock = make_detector()
    detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")
    clock.advance(1)
    detector.analyze("LOGIN_FAILED", "10.0.0.1", username="tanashi")
    clock.advance(1)
    result = detector.analyze("LOGIN_FAILED", "10.0.0.2", username="tanashi")

    assert (result.severity, result.count) == ("INFO", 1)


def test_suspicious_username_is_warning():
    detector, _clock = make_detector()
    result = detector.analyze("LOGIN_FAILED", "10.0.0.1", username="root")

    assert result.severity == "WARNING"
    assert result.count == 1
    assert result.message == "Suspicious SSH username attempt"


def test_suspicious_username_check_is_case_insensitive():
    detector, _clock = make_detector()
    result = detector.analyze("LOGIN_FAILED", "10.0.0.1", username="AdMiN")

    assert result.severity == "WARNING"
    assert result.count == 1
    assert result.message == "Suspicious SSH username attempt"


def test_expiry_boundary_is_inclusive_then_expires_after_one_microsecond():
    detector, clock = make_detector()
    detector.analyze("SSH_PREAUTH", "10.0.0.1")
    clock.advance(60)
    exact_boundary = detector.analyze("SSH_PREAUTH", "10.0.0.1")
    assert exact_boundary.count == 2

    clock.advance(0.000001)
    after_boundary = detector.analyze("SSH_PREAUTH", "10.0.0.1")
    assert after_boundary.count == 2  # t=60 remains; t=0 expired.
    assert detector.events["10.0.0.1"] == 2


def test_partial_expiry_and_source_key_removal():
    detector, clock = make_detector()
    detector.analyze("SSH_PREAUTH", "10.0.0.1")  # T
    clock.advance(30)
    detector.analyze("SSH_PREAUTH", "10.0.0.1")  # T+30
    clock.advance(30)
    detector.analyze("SSH_PREAUTH", "10.0.0.1")  # T+60: T is retained.
    assert detector.events["10.0.0.1"] == 3

    clock.advance(0.000001)
    detector.analyze("LOGIN_SUCCESS", "10.0.0.99")  # T is now expired.
    assert detector.events["10.0.0.1"] == 2

    clock.advance(30)
    detector.analyze("CONNECTION_CLOSED", "10.0.0.99")
    assert detector.events["10.0.0.1"] == 1

    clock.advance(30.000001)
    detector.analyze("LOGIN_SUCCESS", "10.0.0.99")
    assert "10.0.0.1" not in detector.events
    assert not detector._rolling_events


def test_same_time_events_are_individually_counted_and_expired():
    detector, clock = make_detector()
    preauth = [detector.analyze("SSH_PREAUTH", "10.0.0.1") for _ in range(3)]
    failed = [
        detector.analyze("LOGIN_FAILED", "10.0.0.1", username="ordinary")
        for _ in range(2)
    ]
    assert [item.count for item in preauth] == [1, 2, 3]
    assert [item.count for item in failed] == [1, 2]
    assert len(detector._rolling_events) == 5

    clock.advance(60)
    assert detector.analyze("SSH_PREAUTH", "10.0.0.1").count == 4
    clock.advance(0.000001)
    detector.analyze("LOGIN_SUCCESS", "10.0.0.99")
    assert detector.events == {"10.0.0.1": 1}
    assert "10.0.0.1" not in detector.failed_logins

    clock.advance(60.000001)
    detector.analyze("LOGIN_SUCCESS", "10.0.0.99")
    assert "10.0.0.1" not in detector.events


def test_global_expiry_reclaims_untouched_sources_in_both_event_classes():
    detector, clock = make_detector()
    source_count = 10_000
    for index in range(source_count):
        source = f"198.18.{index // 256}.{index % 256}"
        detector.analyze("LOGIN_FAILED", source, username="ordinary")
        detector.analyze("SSH_PREAUTH", source)

    assert len(detector.failed_logins) == source_count
    assert len(detector.events) == source_count
    assert len(detector._rolling_events) == source_count * 2
    old_failed_state = detector.failed_logins
    old_preauth_state = detector.events

    clock.advance(60.000001)
    current = detector.analyze("LOGIN_FAILED", "203.0.113.1", username="ordinary")
    assert (current.severity, current.count) == ("INFO", 1)
    assert detector.failed_logins == {"203.0.113.1": 1}
    assert detector.events == {}
    assert len(detector._rolling_events) == 1
    assert detector.failed_logins is old_failed_state
    assert detector.events is old_preauth_state


def test_cleared_maps_reuse_same_source_and_leave_no_stale_expiry_records():
    detector, clock = make_detector()
    failed_map = detector.failed_logins
    preauth_map = detector.events
    reused_source = "198.18.0.0"

    for index in range(1_000):
        source = f"198.18.{index // 256}.{index % 256}"
        detector.analyze("LOGIN_FAILED", source, username="ordinary")
        detector.analyze("SSH_PREAUTH", source)

    assert len(failed_map) == len(preauth_map) == 1_000
    assert len(detector._rolling_events) == 2_000

    clock.advance(60.000001)
    detector.analyze("LOGIN_SUCCESS", "203.0.113.1")
    assert failed_map == preauth_map == {}
    assert detector.failed_logins is failed_map
    assert detector.events is preauth_map
    assert not detector._rolling_events

    # Equal monotonic timestamps are independent events, including for a source
    # that existed before cleanup.
    assert detector.analyze("LOGIN_FAILED", reused_source).count == 1
    assert detector.analyze("LOGIN_FAILED", reused_source).count == 2
    assert detector.analyze("SSH_PREAUTH", reused_source).count == 1
    assert detector.analyze("SSH_PREAUTH", reused_source).count == 2
    assert detector.analyze("SSH_PREAUTH", reused_source).count == 3
    assert failed_map == {reused_source: 2}
    assert preauth_map == {reused_source: 3}
    assert len(detector._rolling_events) == 5

    clock.advance(60)
    assert detector.analyze("LOGIN_FAILED", reused_source).count == 3
    assert detector.analyze("SSH_PREAUTH", reused_source).count == 4
    clock.advance(0.000001)
    detector.analyze("CONNECTION_CLOSED", "203.0.113.1")
    assert failed_map == {reused_source: 1}
    assert preauth_map == {reused_source: 1}

    clock.advance(60.000001)
    detector.analyze("LOGIN_SUCCESS", "203.0.113.1")
    assert failed_map == preauth_map == {}
    assert not detector._rolling_events


def test_detector_uses_only_injected_monotonic_clock():
    detector, clock = make_detector()
    counts = []
    for _ in range(3):
        counts.append(detector.analyze("LOGIN_FAILED", "10.0.0.1").count)
        clock.advance(1)

    assert counts == [1, 2, 3]
