from datetime import datetime, timedelta, timezone


import api.main as api_main
from database.inventory import create_device
from database.networks import create_network
from database.perimeter import persist_perimeter_event
from database.remote_sensors import RemoteSensorStore
from services.perimeter_dashboard import build_perimeter_dashboard
from services.perimeter_detection_engine import PerimeterDetectionEngine
from services.perimeter_host_engine import PerimeterHostCorrelationEngine
from services.perimeter_models import PerimeterEvent
from local_operator_client import make_local_test_client
from services.perimeter_policy_engine import PerimeterPolicyCorrelationEngine

AT = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=2)


def setup_inventory(path):
    network = create_network(cidr="192.168.50.0/24", name="LAN", description="", authorized=True, enabled=True, db_path=path)
    store = RemoteSensorStore(path)
    site = store.create_site("Edge Site")
    invitation = store.create_enrollment(site["id"])
    sensor = store.consume_enrollment(invitation.secret, name="sensor", platform="linux", version="1")
    from database.db import get_connection
    with get_connection(path) as connection:
        scope_id = connection.execute("SELECT scope_id FROM network_scope_links WHERE network_id=?", (network["id"],)).fetchone()[0]
    store.assign_scope(sensor.record["id"], scope_id)
    device = create_device(
        stable_key=f"network:{network['id']}:mac:aa:bb:cc:00:00:01", network_id=network["id"],
        mac_address="aa:bb:cc:00:00:01", hostname="edge-host", vendor="Lab", first_seen=AT.isoformat(),
        last_seen=AT.isoformat(), last_ip_address="192.168.50.10", status="ONLINE", identity_confidence="HIGH", db_path=path,
    )
    return site, device


def make_event(site_id, number, *, action="BLOCK", source_ip="203.0.113.10", port=22, when=None, source_type="FIREWALL"):
    return PerimeterEvent(
        external_event_id=f"evt-{number}", site_id=site_id, source_type=source_type, source_key="edge-fw",
        observed_at=when or (AT + timedelta(seconds=number)), event_type="POLICY_DECISION", direction="INBOUND",
        action=action, protocol="TCP", source_ip=source_ip, destination_ip="192.168.50.10",
        source_port=50000 + number, destination_port=port, interface="wan0", source_reference="rule:wan",
        raw_event_hash=f"{number:064x}", metadata=None,
    )


def test_dashboard_aggregates_inbound_evidence_and_host_links(tmp_path):
    path = tmp_path / "dashboard.db"
    site, device = setup_inventory(path)
    first = persist_perimeter_event(make_event(site["id"], 1), path)
    second = persist_perimeter_event(make_event(site["id"], 2, action="ALLOW", source_ip="203.0.113.11", port=443), path)
    PerimeterHostCorrelationEngine(path).evaluate_events([first["id"], second["id"]])
    result = build_perimeter_dashboard(site_id=site["id"], time_range="24h", db_path=path, now=AT + timedelta(hours=1))
    assert result["summary"] == {
        "inbound_total": 2, "allowed": 1, "blocked": 1, "rejected": 0, "unknown": 0,
        "unique_sources": 2, "host_linked": 2, "repeated_detections": 0, "policy_correlations": 0,
    }
    assert result["top_sources"][0]["total"] == 1
    assert {row["destination_port"] for row in result["top_ports"]} == {22, 443}
    assert result["recent_activity"][0]["device_id"] == device["id"]
    assert result["recent_activity"][0]["device_hostname"] == "edge-host"


def test_dashboard_counts_repeated_and_policy_review_signals(tmp_path):
    path = tmp_path / "signals.db"
    site, _ = setup_inventory(path)
    rows = []
    for number in range(1, 6):
        row = persist_perimeter_event(make_event(site["id"], number), path)
        rows.append(row)
        PerimeterDetectionEngine(path).evaluate_event(row["id"])
    allow = persist_perimeter_event(make_event(site["id"], 6, action="ALLOW"), path)
    PerimeterPolicyCorrelationEngine(path).evaluate_event(allow["id"])
    result = build_perimeter_dashboard(site_id=site["id"], db_path=path, now=AT + timedelta(hours=1))
    assert result["summary"]["repeated_detections"] == 1
    assert result["summary"]["policy_correlations"] == 1
    assert result["repeated_detections"][0]["event_count"] == 5
    assert result["policy_correlations"][0]["correlation_type"] == "BLOCK_THEN_ALLOW"


def test_dashboard_filters_site_source_and_time_window(tmp_path):
    path = tmp_path / "filters.db"
    first, _ = setup_inventory(path)
    second = RemoteSensorStore(path).create_site("Other Site")
    persist_perimeter_event(make_event(first["id"], 1, source_type="ROUTER"), path)
    persist_perimeter_event(make_event(first["id"], 2, source_type="FIREWALL"), path)
    persist_perimeter_event(make_event(second["id"], 3, source_type="FIREWALL"), path)
    persist_perimeter_event(make_event(first["id"], 4, when=AT - timedelta(days=2)), path)
    result = build_perimeter_dashboard(
        site_id=first["id"], source_type="FIREWALL", time_range="24h", db_path=path, now=AT + timedelta(hours=1)
    )
    assert result["summary"]["inbound_total"] == 1
    assert result["filters"] == {"site_id": first["id"], "source_type": "FIREWALL", "time_range": "24h"}


def test_dashboard_api_is_read_only_and_validates_site(tmp_path, monkeypatch):
    path = tmp_path / "api.db"
    site, _ = setup_inventory(path)
    persist_perimeter_event(make_event(site["id"], 1), path)
    monkeypatch.setattr(api_main, "DB_PATH", path)
    client = make_local_test_client(api_main.app)
    response = client.get(f"/perimeter-dashboard?site_id={site['id']}&time_range=24h")
    assert response.status_code == 200
    assert response.json()["summary"]["inbound_total"] == 1
    assert client.get("/perimeter-dashboard?site_id=999999").status_code == 404
    assert client.get("/perimeter-dashboard?time_range=bogus").status_code == 422
    assert client.post("/perimeter-dashboard", json={}).status_code == 405
