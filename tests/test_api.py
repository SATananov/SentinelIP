from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "SentinelIP",
    }


def test_events():
    response = client.get("/events?limit=5")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "events" in data
    assert data["count"] == len(data["events"])
    assert len(data["events"]) <= 5


def test_events_rejects_zero_limit():
    response = client.get("/events?limit=0")

    assert response.status_code == 422


def test_events_rejects_limit_over_100():
    response = client.get("/events?limit=101")

    assert response.status_code == 422


def test_alerts():
    response = client.get("/alerts?limit=5")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "alerts" in data
    assert data["count"] == len(data["alerts"])


def test_severity_stats():
    response = client.get("/stats/severity")

    assert response.status_code == 200
    assert "items" in response.json()


def test_event_type_stats():
    response = client.get("/stats/event-types")

    assert response.status_code == 200
    assert "items" in response.json()


def test_top_ips():
    response = client.get("/stats/top-ips?limit=5")

    assert response.status_code == 200
    assert "items" in response.json()
    assert len(response.json()["items"]) <= 5
