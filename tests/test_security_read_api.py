import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from database.db import get_connection, initialize_database
from services.correlation_engine import CorrelationEngine
from services.incident_engine import IncidentEngine
from test_correlation_engine import ssh_pair, web_chain
from test_correlation_rules import AT


client = TestClient(api_main.app)


@pytest.fixture
def api_db(tmp_path, monkeypatch):
    path = tmp_path / "security-api.db"
    initialize_database(path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    return path


def seed_security_pipeline(path):
    suspicious, brute = ssh_pair(path)
    observations, cross, web_threat = web_chain(path, download=True)

    correlation_engine = CorrelationEngine(path)

    ssh_correlation = correlation_engine.evaluate_threat(
        suspicious["id"],
        evaluated_at=AT,
    )[0]

    web_correlation = correlation_engine.evaluate_web_detection(
        cross["id"],
        evaluated_at=AT,
    )[0]

    incident = IncidentEngine(path).open_review(
        [ssh_correlation["id"], web_correlation["id"]],
        opened_at=AT,
    )

    return {
        "suspicious": suspicious,
        "brute": brute,
        "web_threat": web_threat,
        "ssh_correlation": ssh_correlation,
        "web_correlation": web_correlation,
        "incident": incident,
        "observations": observations,
        "cross": cross,
    }


def table_counts(path):
    with get_connection(path) as connection:
        return {
            "threats": connection.execute("SELECT COUNT(*) FROM threat_detections").fetchone()[0],
            "correlations": connection.execute("SELECT COUNT(*) FROM correlations").fetchone()[0],
            "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        }


def test_threats_collection_is_paginated(api_db):
    seed_security_pipeline(api_db)
    response = client.get("/threats?limit=2&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 3
    assert data["count"] == 2
    assert data["limit"] == 2
    assert data["offset"] == 0
    assert len(data["threats"]) == 2


def test_threats_support_deterministic_filters(api_db):
    seeded = seed_security_pipeline(api_db)
    response = client.get(
        "/threats?threat_type=SSH_BRUTE_FORCE_THREAT&confidence=HIGH"
        f"&source_ip={seeded['brute']['source_ip']}"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["count"] == 1
    item = data["threats"][0]
    assert item["threat_type"] == "SSH_BRUTE_FORCE_THREAT"
    assert item["confidence"] == "HIGH"
    assert item["source_ip"] == seeded["brute"]["source_ip"]
    assert item["evidence"]


def test_threat_detail_and_not_found(api_db):
    seeded = seed_security_pipeline(api_db)
    response = client.get(f"/threats/{seeded['web_threat']['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == seeded["web_threat"]["id"]
    assert client.get("/threats/999999").status_code == 404
    assert client.get("/threats/0").status_code == 422


def test_correlations_collection_is_paginated(api_db):
    seed_security_pipeline(api_db)
    response = client.get("/correlations?limit=1&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["count"] == 1
    assert len(data["correlations"]) == 1


def test_web_detections_are_bounded_compact_and_newest_first(api_db):
    seed_security_pipeline(api_db)
    before = table_counts(api_db)
    with get_connection(api_db) as connection:
        web_count_before = connection.execute("SELECT COUNT(*) FROM web_detections").fetchone()[0]
    response = client.get("/web-detections?limit=1&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 2
    assert data["count"] == 1
    assert data["limit"] == 1
    assert data["offset"] == 0
    assert set(data["detections"][0]) == {
        "id", "detection_type", "state", "device_id", "hostname", "first_seen", "last_seen",
    }
    assert "evidence" not in data["detections"][0]
    all_rows = client.get("/web-detections?limit=100&offset=0").json()["detections"]
    assert all_rows == sorted(all_rows, key=lambda row: (row["last_seen"], row["id"]), reverse=True)
    assert table_counts(api_db) == before
    with get_connection(api_db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM web_detections").fetchone()[0] == web_count_before


@pytest.mark.parametrize("url", [
    "/web-detections?limit=0",
    "/web-detections?limit=101",
    "/web-detections?offset=-1",
    "/web-detections?offset=100001",
])
def test_web_detections_reject_out_of_bounds_pagination(api_db, url):
    assert client.get(url).status_code == 422


def test_correlations_support_context_filters(api_db):
    seeded = seed_security_pipeline(api_db)
    ssh = client.get(
        "/correlations?correlation_type=SSH_AUTH_ACTIVITY_PATTERN"
        "&state=PATTERN&confidence=HIGH"
        f"&source_ip={seeded['ssh_correlation']['source_ip']}"
    )
    assert ssh.status_code == 200
    assert ssh.json()["total"] == 1
    assert ssh.json()["correlations"][0]["correlation_type"] == "SSH_AUTH_ACTIVITY_PATTERN"

    sensor_id = seeded["web_correlation"]["sensor_id"]
    web = client.get(
        "/correlations?correlation_type=WEB_CREDENTIAL_ACTIVITY_CHAIN"
        f"&sensor_id={sensor_id}"
    )
    assert web.status_code == 200
    assert web.json()["total"] == 1


def test_correlation_detail_and_not_found(api_db):
    seeded = seed_security_pipeline(api_db)
    response = client.get(f"/correlations/{seeded['web_correlation']['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == seeded["web_correlation"]["id"]
    assert response.json()["entities"]
    assert client.get("/correlations/999999").status_code == 404
    assert client.get("/correlations/0").status_code == 422


def test_incidents_collection_and_filters(api_db):
    seeded = seed_security_pipeline(api_db)
    response = client.get(
        "/incidents?incident_type=MULTI_SIGNAL_REVIEW&status=OPEN&priority=MEDIUM"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["count"] == 1
    assert data["incidents"][0]["id"] == seeded["incident"]["id"]


def test_incident_detail_and_not_found(api_db):
    seeded = seed_security_pipeline(api_db)
    response = client.get(f"/incidents/{seeded['incident']['id']}")
    assert response.status_code == 200
    assert response.json()["status"] == "OPEN"
    assert response.json()["priority"] == "MEDIUM"
    assert response.json()["correlations"]
    assert client.get("/incidents/999999").status_code == 404
    assert client.get("/incidents/0").status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "/threats?limit=0",
        "/threats?limit=101",
        "/threats?offset=-1",
        "/threats?state=CONFIRMED",
        "/threats?severity=CRITICAL",
        "/correlations?state=CONFIRMED_INCIDENT",
        "/correlations?severity=HIGH",
        "/correlations?sensor_id=0",
        "/incidents?status=CLOSED",
        "/incidents?priority=CRITICAL",
        "/incidents?limit=101",
    ],
)
def test_security_read_api_rejects_invalid_filters(api_db, url):
    assert client.get(url).status_code == 422


def test_security_routes_have_no_mutation_methods(api_db):
    for path in ("/threats", "/correlations", "/incidents"):
        assert client.post(path, json={}).status_code == 405
        assert client.patch(path + "/1", json={}).status_code == 405
        assert client.delete(path + "/1").status_code == 405


def test_security_reads_do_not_create_or_modify_records(api_db):
    seeded = seed_security_pipeline(api_db)
    before = table_counts(api_db)

    assert client.get("/threats").status_code == 200
    assert client.get("/correlations").status_code == 200
    assert client.get("/incidents").status_code == 200
    assert client.get(f"/threats/{seeded['brute']['id']}").status_code == 200
    assert client.get(f"/correlations/{seeded['ssh_correlation']['id']}").status_code == 200
    assert client.get(f"/incidents/{seeded['incident']['id']}").status_code == 200

    after = table_counts(api_db)
    assert after == before


def test_openapi_exposes_security_routes_as_get_only(api_db):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]

    for route in (
        "/threats",
        "/threats/{threat_id}",
        "/correlations",
        "/correlations/{correlation_id}",
        "/incidents",
        "/incidents/{incident_id}",
    ):
        assert set(paths[route]) == {"get"}
