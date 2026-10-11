from datetime import datetime, timedelta, timezone

import pytest

from services.telemetry_models import (
    DnsObservation,
    PrivacyMode,
    TelemetryModelError,
    WebObservation,
    WebEventType,
    normalize_domain,
    normalize_url,
)


OBSERVED_AT = datetime.now(timezone.utc) - timedelta(minutes=1)


def test_domain_and_url_privacy_normalization():
    assert normalize_domain(" Login.Example.TEST. ") == "login.example.test"
    assert normalize_url(
        "https://Login.Example.test/account?secret=value#fragment",
        PrivacyMode.DOMAIN_ONLY,
    ) == ("https", "login.example.test", None)
    assert normalize_url(
        "https://Login.Example.test/account?secret=value#fragment",
        PrivacyMode.STANDARD,
    ) == ("https", "login.example.test", "/account")


def test_web_observation_accepts_structured_signals_only():
    observation = WebObservation(
        external_event_id="web-1",
        sensor_id="1",
        observed_at=OBSERVED_AT,
        event_type=WebEventType.NAVIGATION,
        url="https://example.test/login?secret=x#fragment",
        privacy_mode=PrivacyMode.DOMAIN_ONLY,
        has_login_form=True,
        has_password_form=True,
    )

    assert observation.has_login_form is True
    assert observation.metadata is None


def test_dns_observation_normalizes_addresses_and_rejects_invalid_values():
    observation = DnsObservation(
        external_event_id="dns-1",
        sensor_id="2",
        observed_at=OBSERVED_AT,
        queried_domain="Example.TEST",
        query_type="A",
        response_status="NOERROR",
        resolved_addresses=("192.0.2.10",),
    )

    assert observation.queried_domain == "example.test"
    assert observation.resolved_addresses == ("192.0.2.10",)

    with pytest.raises(TelemetryModelError):
        DnsObservation(
            external_event_id="dns-2",
            sensor_id="2",
            observed_at=OBSERVED_AT,
            queried_domain="example.test",
            query_type="A",
            response_status="NOERROR",
            resolved_addresses=("not-an-ip",),
        )


def test_sensitive_metadata_is_rejected():
    with pytest.raises(TelemetryModelError):
        WebObservation(
            external_event_id="web-sensitive",
            sensor_id="1",
            observed_at=OBSERVED_AT,
            event_type="NAVIGATION",
            url="https://example.test",
            privacy_mode="DOMAIN_ONLY",
            metadata={"password": "secret"},
        )