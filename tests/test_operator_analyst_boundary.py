from fastapi.testclient import TestClient
import pytest

import api.main as api_main
from api.remote_sensors import local_management
from database.db import initialize_database
from local_operator_client import make_local_test_client


REVIEW_ROUTES = {
    ("GET", "/incident-review-operations"),
    ("GET", "/incident-review-operations/activity"),
    ("GET", "/incident-review-operations/trends"),
    ("GET", "/incident-review-operations/sites"),
    ("GET", "/incident-review-operations/scopes"),
    ("GET", "/incident-review-operations/devices"),
    ("GET", "/incident-reviews"),
    ("GET", "/incident-reviews/{incident_id}"),
    ("GET", "/incident-reviews/{incident_id}/report.json"),
    ("GET", "/incident-reviews/{incident_id}/report.html"),
    ("POST", "/incident-reviews"),
    ("POST", "/incident-reviews/from-evidence"),
    ("PATCH", "/incident-reviews/{incident_id}"),
    ("GET", "/incident-reviews/{incident_id}/timeline"),
    ("GET", "/incident-reviews/{incident_id}/notes"),
    ("POST", "/incident-reviews/{incident_id}/notes"),
    ("GET", "/incident-reviews/{incident_id}/evidence"),
    ("GET", "/incident-reviews/{incident_id}/related-evidence"),
    ("POST", "/incident-reviews/{incident_id}/evidence"),
    ("DELETE", "/incident-reviews/{incident_id}/evidence/{evidence_type}/{evidence_id}"),
}

ANALYST_ROUTES = {
    ("GET", "/investigation-lookup"),
    ("GET", "/networks/{network_id}/devices"),
    ("GET", "/devices/{device_id}"),
    ("GET", "/devices/{device_id}/ports"),
    ("GET", "/devices/{device_id}/services"),
    ("GET", "/devices/{device_id}/findings"),
    ("GET", "/devices/{device_id}/cve-matches"),
    ("GET", "/overview"), ("GET", "/events"), ("GET", "/source-ips"),
    ("GET", "/alerts"), ("GET", "/stats/severity"),
    ("GET", "/stats/event-types"), ("GET", "/stats/top-ips"),
    ("GET", "/stats/timeline"),
    ("GET", "/export/events.json"), ("GET", "/export/events.csv"),
    ("GET", "/export/report.pdf"),
    ("GET", "/threats"), ("GET", "/threats/{threat_id}"),
    ("GET", "/correlations"), ("GET", "/correlations/{correlation_id}"),
    ("GET", "/web-detections"),
    ("GET", "/incidents"), ("GET", "/incidents/{incident_id}"),
    ("GET", "/perimeter-events"), ("GET", "/perimeter-events/{event_id}"),
    ("GET", "/perimeter-detections"),
    ("GET", "/perimeter-detections/{detection_id}"),
    ("GET", "/perimeter-policy-correlations"),
    ("GET", "/perimeter-policy-correlations/{correlation_id}"),
    ("GET", "/perimeter-host-correlations"),
    ("GET", "/perimeter-host-correlations/{correlation_id}"),
    ("GET", "/perimeter-dashboard"),
    ("GET", "/external-exposures"),
    ("GET", "/external-exposures/{exposure_id}"),
    ("GET", "/external-exposures/{exposure_id}/observations"),
    ("GET", "/external-exposure-assessments"),
    ("GET", "/external-exposure-assessments/{assessment_id}"),
    ("GET", "/external-exposure-changes"),
    ("GET", "/external-exposure-changes/{change_id}"),
    ("GET", "/external-exposure-classifications"),
    ("GET", "/external-exposure-classifications/{classification_id}"),
    ("GET", "/external-exposure-dashboard"),
    ("GET", "/network-candidates"),
}

SENSOR_ROUTES = {
    ("POST", "/sensor-enrollment/register"), ("GET", "/sensor/self"),
    ("GET", "/sensor/grant"), ("POST", "/sensor/heartbeat"),
    ("POST", "/sensor/perimeter-events"), ("POST", "/sensor/tasks/claim"),
    ("POST", "/sensor/tasks/{task_id}/start"),
    ("POST", "/sensor/tasks/{task_id}/fail"),
    ("POST", "/sensor/tasks/{task_id}/result"),
    ("POST", "/telemetry/web"), ("POST", "/telemetry/dns"),
}


@pytest.fixture
def analyst_client(monkeypatch, tmp_path):
    path = tmp_path / "analyst-boundary.db"
    initialize_database(path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    return make_local_test_client(api_main.app), path


def _route_map():
    return {
        (method, route.path): route
        for route in api_main.app.routes
        if getattr(route, "methods", None)
        for method in route.methods
    }


def _has_local_guard(route):
    return any(dependency.call is local_management for dependency in route.dependant.dependencies)


def test_review_and_analyst_route_matrices_are_guarded():
    routes = _route_map()
    assert REVIEW_ROUTES <= routes.keys()
    assert ANALYST_ROUTES <= routes.keys()
    assert all(_has_local_guard(routes[key]) for key in REVIEW_ROUTES | ANALYST_ROUTES)


def test_sensor_routes_and_health_are_explicitly_excluded():
    routes = _route_map()
    assert SENSOR_ROUTES <= routes.keys()
    assert all(not _has_local_guard(routes[key]) for key in SENSOR_ROUTES)
    assert ("GET", "/health") in routes
    assert not _has_local_guard(routes[("GET", "/health")])


@pytest.mark.parametrize("path", [
    "/incident-reviews", "/devices/1", "/events", "/threats",
    "/perimeter-events", "/external-exposures", "/web-detections",
    "/export/events.json", "/network-candidates",
])
@pytest.mark.parametrize("denial", ["peer", "host", "origin"])
def test_analyst_route_families_reject_nonlocal_request_conditions(
        analyst_client, path, denial):
    _, _ = analyst_client
    base_url = "http://operator.example" if denial == "host" else "http://127.0.0.1:8000"
    peer = ("192.0.2.44", 5050) if denial == "peer" else ("127.0.0.1", 5050)
    headers = {"Origin": "https://operator.example"} if denial == "origin" else {}
    client = TestClient(api_main.app, base_url=base_url, client=peer)
    assert client.get(path, headers=headers).status_code == 403


@pytest.mark.parametrize("header,value", [
    ("Forwarded", "for=127.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1"),
    ("Authorization", "Bearer not-operator-auth"),
    ("X-Sensor-UUID", "sensor"),
    ("X-SentinelIP-Sensor-ID", "sensor"),
    ("X-SentinelIP-Sensor-Token", "token"),
])
def test_analyst_route_rejects_forbidden_header(analyst_client, header, value):
    client, _ = analyst_client
    response = client.get("/incident-reviews", headers={
        "Origin": "http://127.0.0.1:5173", header: value,
    })
    assert response.status_code == 403


def test_direct_local_reads_and_review_mutation_succeed_with_no_store(analyst_client):
    client, _ = analyst_client
    assert client.get("/events").status_code == 200
    assert client.get("/events").headers["cache-control"] == "no-store"
    for origin in ("http://127.0.0.1:5173", "http://localhost:5173"):
        assert client.get("/events", headers={"Origin": origin}).status_code == 200
    assert client.get("/incident-reviews").status_code == 200
    assert client.get("/incident-reviews").headers["cache-control"] == "no-store"

    created = client.post("/incident-reviews", json={
        "title": "Local boundary test", "summary": "Synthetic test only",
    })
    assert created.status_code == 201
    review_id = created.json()["id"]
    note = client.post(f"/incident-reviews/{review_id}/notes", json={"note_text": "local note"})
    assert note.status_code == 201
    assert client.get(f"/incident-reviews/{review_id}/report.json").status_code == 200
    html = client.get(f"/incident-reviews/{review_id}/report.html")
    assert html.status_code == 200
    assert html.headers["cache-control"] == "no-store"
    assert "text/html" in html.headers["content-type"]
