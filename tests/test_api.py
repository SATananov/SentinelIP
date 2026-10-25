import pytest

from api.main import app
from fastapi import HTTPException
import api.main as api_main
from local_operator_client import make_local_test_client


client = make_local_test_client(app)


def test_source_ips_route_avoids_lookup_for_empty_queries(monkeypatch):
    def unexpected_lookup(_query):
        raise AssertionError("empty query must not access the source-IP database")

    monkeypatch.setattr(api_main, "find_source_ip", unexpected_lookup)
    assert api_main.source_ips(q=None) == {"items": []}
    assert api_main.source_ips(q="") == {"items": []}
    assert api_main.source_ips(q="  \t ") == {"items": []}


def test_source_ips_route_validates_canonical_ipv4_before_lookup(monkeypatch):
    queried = []

    def lookup(query):
        queried.append(query)
        return None if query == "192.0.2.2" else query

    monkeypatch.setattr(api_main, "find_source_ip", lookup)
    assert api_main.source_ips(q=" 192.0.2.1 ") == {"items": ["192.0.2.1"]}
    assert api_main.source_ips(q="10.0.0.1") == {"items": ["10.0.0.1"]}
    assert api_main.source_ips(q="255.255.255.255") == {
        "items": ["255.255.255.255"]
    }
    assert api_main.source_ips(q="0.0.0.0") == {"items": ["0.0.0.0"]}
    assert api_main.source_ips(q="192.0.2.2") == {"items": []}
    assert queried == [
        "192.0.2.1", "10.0.0.1", "255.255.255.255", "0.0.0.0", "192.0.2.2"
    ]

    for invalid in (
        "192.168.001.1",
        "192.168.1",
        "999.1.1.1",
        "1.2.3.4.5",
        "::1",
        "2001:db8::1",
        "abc",
        "1.2.3.4xyz",
        "1" * 16,
        "1" * 33,
    ):
        with pytest.raises(HTTPException) as error:
            api_main.source_ips(q=invalid)
        assert error.value.status_code == 422
    assert queried == [
        "192.0.2.1", "10.0.0.1", "255.255.255.255", "0.0.0.0", "192.0.2.2"
    ]


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
    assert response.json()["top_ips_basis"] == {
        "mode": "latest_events",
        "sample_size": 10_000,
    }


def test_overview():
    response = client.get("/overview")

    assert response.status_code == 200

    data = response.json()

    assert "total_events" in data
    assert "severity" in data
    assert "top_ips" in data
    assert "event_types" in data
    assert data["top_ips_basis"] == {
        "mode": "latest_events",
        "sample_size": 10_000,
    }

    assert "INFO" in data["severity"]
    assert "WARNING" in data["severity"]
    assert "ALERT" in data["severity"]


def test_events_pagination_metadata():
    response = client.get(
        "/events?limit=5&offset=0"
    )

    assert response.status_code == 200

    data = response.json()

    assert "total" in data
    assert "count" in data
    assert "limit" in data
    assert "offset" in data
    assert "events" in data

    assert data["limit"] == 5
    assert data["offset"] == 0
    assert data["count"] == len(data["events"])


def test_events_rejects_negative_offset():
    response = client.get(
        "/events?offset=-1"
    )

    assert response.status_code == 422


def test_events_accepts_server_side_filters():
    response = client.get(
        "/events"
        "?limit=5"
        "&offset=0"
        "&severity=ALERT"
        "&time_range=all"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["severity"] == "ALERT"
    assert data["time_range"] == "all"

    for event in data["events"]:
        assert event["severity"] == "ALERT"


def test_events_rejects_invalid_severity():
    response = client.get(
        "/events?severity=CRITICAL"
    )

    assert response.status_code == 422


def test_events_rejects_invalid_time_range():
    response = client.get(
        "/events?time_range=7d"
    )

    assert response.status_code == 422


def test_source_ips():
    response = client.get("/source-ips")

    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_export_events_json():
    response = client.get(
        "/export/events.json?time_range=all"
    )

    assert response.status_code == 200

    data = response.json()

    assert "generated_at" in data
    assert "count" in data
    assert "filters" in data
    assert "events" in data

    assert data["count"] == len(data["events"])


def test_export_events_json_accepts_filter():
    response = client.get(
        "/export/events.json"
        "?severity=ALERT"
        "&time_range=all"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["filters"]["severity"] == "ALERT"

    for event in data["events"]:
        assert event["severity"] == "ALERT"


def test_export_events_csv():
    response = client.get(
        "/export/events.csv?time_range=all"
    )

    assert response.status_code == 200

    assert response.headers[
        "content-type"
    ].startswith("text/csv")

    assert "attachment;" in response.headers[
        "content-disposition"
    ]

    assert "timestamp" in response.text
    assert "source_ip" in response.text
    assert "severity" in response.text


def test_export_rejects_invalid_severity():
    response = client.get(
        "/export/events.json?severity=CRITICAL"
    )

    assert response.status_code == 422
