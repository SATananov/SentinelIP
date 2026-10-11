from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app
from database.telemetry import provision_sensor


client = TestClient(app)


def sensor_key(prefix):
    return f"{prefix}-{uuid4().hex}"


def test_web_api_requires_authentication():
    response = client.post(
        "/telemetry/web",
        json={
            "external_event_id": "api-no-auth",
            "observed_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "event_type": "NAVIGATION",
            "url": "https://example.test",
        },
    )
    assert response.status_code == 401


def test_authenticated_web_api_accepts_and_deduplicates():
    sensor, token = provision_sensor(
        sensor_key("api-browser-test"), "API Browser", "BROWSER", None, "DOMAIN_ONLY", 30
    )
    payload = {
        "external_event_id": "api-web-1",
        "observed_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "event_type": "NAVIGATION",
        "url": "https://example.test/login?secret=value#fragment",
        "has_login_form": True,
    }
    headers = {
        "X-SentinelIP-Sensor-ID": str(sensor["id"]),
        "X-SentinelIP-Sensor-Token": token,
    }

    first = client.post("/telemetry/web", json=payload, headers=headers)
    second = client.post("/telemetry/web", json=payload, headers=headers)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["idempotent"] is False
    assert second.json()["idempotent"] is True


def test_dns_api_rejects_browser_sensor():
    sensor, token = provision_sensor(
        sensor_key("api-browser-dns-test"), "API Browser", "BROWSER", None, "DOMAIN_ONLY", 30
    )
    response = client.post(
        "/telemetry/dns",
        json={
            "external_event_id": "api-dns-wrong-type",
            "observed_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "queried_domain": "example.test",
            "query_type": "A",
            "response_status": "NOERROR",
            "resolved_addresses": ["192.0.2.10"],
        },
        headers={
            "X-SentinelIP-Sensor-ID": str(sensor["id"]),
            "X-SentinelIP-Sensor-Token": token,
        },
    )
    assert response.status_code == 403


def test_api_rejects_sensitive_unknown_fields():
    sensor, token = provision_sensor(
        sensor_key("api-sensitive-test"), "API Browser", "BROWSER", None, "DOMAIN_ONLY", 30
    )
    response = client.post(
        "/telemetry/web",
        json={
            "external_event_id": "api-sensitive",
            "observed_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "event_type": "NAVIGATION",
            "url": "https://example.test",
            "password": "secret",
        },
        headers={
            "X-SentinelIP-Sensor-ID": str(sensor["id"]),
            "X-SentinelIP-Sensor-Token": token,
        },
    )
    assert response.status_code == 422