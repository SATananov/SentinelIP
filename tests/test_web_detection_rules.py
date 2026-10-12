from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from services.web_detection_models import WebEvidence
from services.web_detection_rules import evaluate_rules

AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def evidence(number=1, seconds=0, **kwargs):
    values = dict(observation_id=number, sensor_id=1, device_id=None, hostname="login.example.test",
                  event_type="NAVIGATION", observed_at=AT + timedelta(seconds=seconds), received_at=AT,
                  browser_session_id="session", tab_id="tab")
    values.update(kwargs)
    return WebEvidence(**values)


def kinds(primary, *history):
    return {d.detection_type.value for d in evaluate_rules(primary, history, AT)}


def redirect(number=1, seconds=0, start="example.test", end="login.example.test", **kwargs):
    return evidence(number, seconds, event_type="REDIRECT", hostname=end,
                    redirect_from_domain=start, redirect_to_domain=end, **kwargs)


@pytest.mark.parametrize("changes", [{}, {"event_type": "DOWNLOAD_SIGNAL", "download_detected": True},
    {"hostname": "xn--bcher-kva.test"}, {"event_type": "FORM_SIGNAL", "has_login_form": True}])
def test_ordinary_signals_have_no_verdict(changes):
    assert kinds(evidence(**changes)) == set()


def test_password_is_low_review_and_cross_rule_replaces_it():
    form = evidence(2, 10, event_type="FORM_SIGNAL", has_password_form=True)
    result, = evaluate_rules(form, (), AT)
    assert (result.state, result.severity, result.confidence) == ("REVIEW", "LOW", "MEDIUM")
    assert kinds(form, redirect()) == {"CROSS_DOMAIN_LOGIN_REDIRECT"}
    assert kinds(form, redirect(end="example.test")) == {"LOGIN_DOMAIN_REVIEW"}
    assert kinds(evidence(2, 10), redirect()) == set()


def test_single_observation_cross_rule_needs_no_session():
    assert kinds(redirect(has_login_form=True, browser_session_id=None)) == {"CROSS_DOMAIN_LOGIN_REDIRECT"}
    assert kinds(redirect(start="login.example.test", has_password_form=True)) == {"LOGIN_DOMAIN_REVIEW"}


@pytest.mark.parametrize("changes", [{"tab_id": "other"}, {"browser_session_id": "other"},
    {"browser_session_id": None}, {"sensor_id": 2}, {"device_id": 2}, {"tab_id": None}])
def test_context_boundaries(changes):
    first = redirect(**changes)
    form = evidence(2, 10, has_password_form=True)
    assert kinds(form, first) == {"LOGIN_DOMAIN_REVIEW"}
    assert kinds(redirect(2, 10, start="login.example.test", end="third.test"), first) == set()
    assert kinds(evidence(2, 10, event_type="DOWNLOAD_SIGNAL", download_detected=True), first) == set()


def test_session_only_requires_both_tabs_absent():
    assert kinds(evidence(2, 10, has_password_form=True, tab_id=None), redirect(tab_id=None)) == {"CROSS_DOMAIN_LOGIN_REDIRECT"}
    assert kinds(evidence(2, 10, has_password_form=True, browser_session_id=None), redirect(browser_session_id=None)) == {"LOGIN_DOMAIN_REVIEW"}


@pytest.mark.parametrize("seconds,expected", [(120, True), (121, False)])
def test_redirect_window(seconds, expected):
    first = redirect()
    last = redirect(2, seconds, start="login.example.test", end="third.test")
    assert ("REDIRECT_CHAIN_REVIEW" in kinds(last, first)) == expected
    assert ("CROSS_DOMAIN_LOGIN_REDIRECT" in kinds(evidence(2, seconds, has_password_form=True), first)) == expected


def test_chain_requires_linked_edges_and_threshold():
    first = redirect()
    assert kinds(first) == set()
    assert kinds(redirect(2, 1, start="login.example.test", end="third.test"), first) == {"REDIRECT_CHAIN_REVIEW"}
    assert kinds(redirect(2, 1, start="unrelated.test", end="third.test"), first) == set()
    assert kinds(redirect(2, 1, start="login.example.test", end="example.test"), first) == set()


@pytest.mark.parametrize("seconds,expected", [(300, True), (301, False)])
@pytest.mark.parametrize("first", [evidence(has_password_form=True), redirect()])
def test_download_window(seconds, expected, first):
    download = evidence(2, seconds, event_type="DOWNLOAD_SIGNAL", download_detected=True)
    assert ("SUSPICIOUS_DOWNLOAD_FLOW" in kinds(download, first)) == expected


def test_future_and_unrelated_navigation_not_linked():
    assert kinds(evidence(1, 0, has_password_form=True), redirect(2, 1)) == {"LOGIN_DOMAIN_REVIEW"}
    assert kinds(evidence(3, 20, has_password_form=True), redirect(), evidence(2, 10, hostname="away.test")) == {"LOGIN_DOMAIN_REVIEW"}


def test_rule_results_are_order_independent_and_review_only():
    history = (redirect(), redirect(2, 1, start="login.example.test", end="third.test"))
    last = redirect(3, 2, start="third.test", end="fourth.test")
    forward = evaluate_rules(last, history, AT)
    assert forward == evaluate_rules(last, tuple(reversed(history)), AT)
    assert all(d.state == "REVIEW" and d.confidence == "MEDIUM" for d in forward)
    assert all(d.detection_type not in {"PHISHING_CONFIRMED", "MALWARE", "COMPROMISED_DEVICE"} for d in forward)
