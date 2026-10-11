from datetime import datetime, timedelta, timezone

import pytest

from database.telemetry import list_dns_observations, list_web_observations, provision_sensor, update_sensor_enabled
from database.inventory import create_device
from database.networks import create_network
from services.telemetry_ingestion import TelemetryIngestionError, ingest_dns, ingest_web


OBSERVED_AT = datetime.now(timezone.utc) - timedelta(minutes=1)


def web_payload(event_id="web-1"):
    return {
        "external_event_id": event_id,
        "observed_at": OBSERVED_AT,
        "event_type": "NAVIGATION",
        "url": "https://Login.Example.test/account?secret=ignored#fragment",
        "has_login_form": True,
        "has_password_form": True,
    }


def create_test_device(db_path):
    network = create_network("192.168.1.0/24", "LAN", "", True, True, db_path)
    device = create_device(
        "network:1:mac:aa:bb:cc:dd:ee:ff",
        network["id"],
        "aa:bb:cc:dd:ee:ff",
        "test-device",
        "Vendor",
        "2026-10-11T11:59:00",
        "2026-10-11T11:59:00",
        "192.168.1.20",
        "ONLINE",
        "HIGH",
        db_path,
    )
    return device


def test_authenticated_web_ingestion_is_private_and_idempotent(tmp_path):
    db_path = tmp_path / "test.db"
    device = create_test_device(db_path)
    sensor, token = provision_sensor(
        "browser-test", "Browser", "BROWSER", device["id"], "DOMAIN_ONLY", 30, db_path
    )

    first = ingest_web(sensor["id"], token, web_payload(), db_path)
    second = ingest_web(sensor["id"], token, web_payload(), db_path)

    assert first["idempotent"] is False
    assert second["idempotent"] is True
    stored = list_web_observations(sensor["id"], db_path)[0]
    assert stored["hostname"] == "login.example.test"
    assert stored["path"] is None
    assert stored["device_id"] == device["id"]
    assert stored["retention_until"]


def test_wrong_credentials_type_and_disabled_sensor_are_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    browser, browser_token = provision_sensor(
        "browser-test", "Browser", "BROWSER", None, "DOMAIN_ONLY", 30, db_path
    )
    dns, dns_token = provision_sensor(
        "dns-test", "DNS", "DNS", None, "DOMAIN_ONLY", 30, db_path
    )

    with pytest.raises(TelemetryIngestionError) as invalid:
        ingest_web(browser["id"], "wrong", web_payload(), db_path)
    assert invalid.value.status_code == 401

    with pytest.raises(TelemetryIngestionError) as wrong_type:
        ingest_web(dns["id"], dns_token, web_payload(), db_path)
    assert wrong_type.value.status_code == 403

    update_sensor_enabled(browser["id"], False, db_path)
    with pytest.raises(TelemetryIngestionError) as disabled:
        ingest_web(browser["id"], browser_token, web_payload("web-disabled"), db_path)
    assert disabled.value.status_code == 403


def test_sensitive_fields_and_device_spoofing_are_rejected(tmp_path):
    db_path = tmp_path / "test.db"
    device = create_test_device(db_path)
    sensor, token = provision_sensor(
        "browser-test", "Browser", "BROWSER", device["id"], "STANDARD", 30, db_path
    )

    with pytest.raises(TelemetryIngestionError):
        ingest_web(
            sensor["id"],
            token,
            {**web_payload("web-sensitive"), "metadata": {"password": "secret"}},
            db_path,
        )

    with pytest.raises(TelemetryIngestionError):
        ingest_web(
            sensor["id"],
            token,
            {**web_payload("web-spoof"), "device_id": 999},
            db_path,
        )


def test_authenticated_dns_ingestion_is_separate(tmp_path):
    db_path = tmp_path / "test.db"
    device = create_test_device(db_path)
    sensor, token = provision_sensor(
        "dns-test", "DNS", "DNS", device["id"], "DOMAIN_ONLY", 30, db_path
    )
    payload = {
        "external_event_id": "dns-1",
        "observed_at": OBSERVED_AT,
        "queried_domain": "Login.Example.test",
        "query_type": "A",
        "response_status": "NOERROR",
        "resolved_addresses": ["192.0.2.10"],
    }

    result = ingest_dns(sensor["id"], token, payload, db_path)

    assert result["idempotent"] is False
    stored = list_dns_observations(sensor["id"], db_path)[0]
    assert stored["queried_domain"] == "login.example.test"
    assert stored["device_id"] == device["id"]
