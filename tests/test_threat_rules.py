from dataclasses import replace
from datetime import datetime, timedelta, timezone
import pytest
from services.threat_models import SSHThreatEvidence
from services.threat_rules import evaluate_ssh, evaluate_web, strengthens
from services.detector import SSHDetector

AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ssh(number=1, seconds=0, **kwargs):
    values = dict(evidence_id=number, source_ip="192.0.2.10", username="ordinary", event_type="LOGIN_FAILED",
                  event_count=number, timestamp=AT + timedelta(seconds=seconds))
    values.update(kwargs)
    return SSHThreatEvidence(**values)


@pytest.mark.parametrize("count,kind", [(1, None), (2, None), (3, "SUSPICIOUS_AUTH_ACTIVITY"),
    (4, "SUSPICIOUS_AUTH_ACTIVITY"), (5, "SSH_BRUTE_FORCE_THREAT")])
def test_existing_threshold(count, kind):
    rows = tuple(ssh(i+1, i) for i in range(count))
    result = evaluate_ssh(rows[-1], rows, AT)
    assert (result.threat_type if result else None) == kind
    if kind == "SSH_BRUTE_FORCE_THREAT":
        assert (result.state, result.severity, result.confidence) == ("SUSPECTED", "MEDIUM", "HIGH")
        assert "repeated failed" in result.reason.lower()


@pytest.mark.parametrize("count,expected", [(1, False), (2, False), (3, True), (5, True)])
def test_preauth_is_not_brute_force(count, expected):
    rows = tuple(ssh(i+1, i, event_type="SSH_PREAUTH") for i in range(count))
    result = evaluate_ssh(rows[-1], rows, AT)
    assert bool(result) == expected
    if result:
        assert result.threat_type == "SUSPICIOUS_AUTH_ACTIVITY" and result.state == "ANOMALOUS"


def test_suspicious_username_reuses_policy():
    result = evaluate_ssh(ssh(username="AdMiN"), (), AT)
    assert result.threat_type == "SUSPICIOUS_AUTH_ACTIVITY" and result.severity == "LOW"
    assert evaluate_ssh(ssh(event_count=999), (), AT) is None


def test_sources_windows_future_and_clock_basis_stay_separate():
    primary = ssh(10, 60)
    old = tuple(ssh(i+1, 0) for i in range(4))
    assert evaluate_ssh(primary, old, AT).threat_type == "SSH_BRUTE_FORCE_THREAT"
    assert evaluate_ssh(replace(primary, timestamp=primary.timestamp+timedelta(seconds=1)), old, AT) is None
    assert evaluate_ssh(primary, tuple(replace(e, source_ip="192.0.2.11") for e in old), AT) is None
    assert evaluate_ssh(primary, tuple(replace(e, timestamp=AT.replace(tzinfo=None)) for e in old), AT) is None
    assert evaluate_ssh(ssh(), tuple(ssh(i+2, 1) for i in range(5)), AT) is None


def test_success_does_not_create_or_erase_pattern():
    assert evaluate_ssh(ssh(event_type="LOGIN_SUCCESS"), (), AT) is None
    rows = tuple(ssh(i+1, i) for i in range(5))
    assert evaluate_ssh(rows[-1], (*rows, ssh(9, 9, event_type="LOGIN_SUCCESS")), AT)


def test_detector_replay_agrees_with_existing_detector():
    detector = SSHDetector()
    rows = tuple(ssh(i+1, i*10) for i in range(8))
    for index, row in enumerate(rows):
        old = detector.analyze(row.event_type, row.source_ip, row.timestamp, row.username)
        result = evaluate_ssh(row, rows[:index], AT)
        assert (result is not None) == (old.severity != "INFO")
        assert (result is not None and result.threat_type == "SSH_BRUTE_FORCE_THREAT") == (old.severity == "ALERT")


def web_pair():
    from services.web_detection_models import WebEvidence
    from services.threat_models import WebThreatEvidence
    form = WebEvidence(2, 1, None, "login.example.test", "FORM_SIGNAL", AT, AT,
                       "session", "tab", has_password_form=True)
    redirect = WebEvidence(1, 1, None, "login.example.test", "REDIRECT", AT-timedelta(seconds=10), AT,
                           "session", "tab", "example.test", "login.example.test")
    download = replace(form, observation_id=3, event_type="DOWNLOAD_SIGNAL", observed_at=AT+timedelta(seconds=20),
                       has_password_form=False, download_detected=True)
    anchor = WebThreatEvidence(1, "CROSS_DOMAIN_LOGIN_REDIRECT", 1, None, 2, "login.example.test", "Review flow.",
                               (redirect, form), "web.cross_domain_login_redirect", "1", AT)
    follow = WebThreatEvidence(2, "SUSPICIOUS_DOWNLOAD_FLOW", 1, None, 3, "login.example.test", "Review download flow.",
                               (form, download), "web.suspicious_download_flow", "1", AT)
    return anchor, follow


def test_web_review_mapping_and_linked_strengthening():
    anchor, follow = web_pair()
    first = evaluate_web(anchor, (), AT)
    second = evaluate_web(anchor, (follow,), AT)
    assert first.stable_key == second.stable_key and len(second.evidence) == 2
    assert (second.state, second.severity, second.confidence) == ("SUSPECTED", "MEDIUM", "MEDIUM")
    assert evaluate_web(follow, (), AT) is None
    assert evaluate_web(replace(anchor, detection_type="LOGIN_DOMAIN_REVIEW"), (), AT) is None


@pytest.mark.parametrize("field,value", [("browser_session_id", "other"), ("tab_id", "other"),
    ("tab_id", None), ("sensor_id", 2), ("device_id", 2)])
def test_web_contexts_never_strengthen_across_boundaries(field, value):
    anchor, follow = web_pair()
    changes = {"observations": tuple(replace(e, **{field: value}) for e in follow.observations)}
    if field in {"sensor_id", "device_id"}:
        changes[field] = value
    other = replace(follow, **changes)
    assert not strengthens(anchor, other)
    assert len(evaluate_web(anchor, (other,), AT).evidence) == 1


@pytest.mark.parametrize("seconds,expected", [(300, True), (301, False), (-1, False)])
def test_web_strengthening_window(seconds, expected):
    anchor, follow = web_pair()
    follow = replace(follow, observations=(follow.observations[0], replace(follow.primary, observed_at=AT+timedelta(seconds=seconds))))
    assert strengthens(anchor, follow) == expected


def test_nearby_context_without_shared_observation_is_insufficient():
    anchor, follow = web_pair()
    unrelated = replace(follow, observations=(replace(follow.observations[0], observation_id=99), follow.primary))
    assert not strengthens(anchor, unrelated)


def test_missing_session_disables_strengthening():
    anchor, follow = web_pair()
    anchor = replace(anchor, observations=(replace(anchor.primary, browser_session_id=None),))
    follow = replace(follow, observations=(replace(follow.primary, browser_session_id=None),))
    assert not strengthens(anchor, follow)
