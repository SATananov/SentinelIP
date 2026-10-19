from datetime import datetime, timezone


import api.main as api
from database.db import initialize_database
from database.inventory import create_scope_device
from database.scopes import create_scope
from services.external_exposure_dashboard import build_external_exposure_dashboard
from services.public_target_policy import PUBLIC_IPV4_CONFIRMATION_VERSION
from services.service_inventory import ServiceInventoryService
from local_operator_client import make_local_test_client
from services.service_models import PortObservation, ServiceDiscoveryResult, ServiceObservation


def _public_scope_device(path):
    scope = create_scope(
        scope_type="PUBLIC_IPV4",
        canonical_target="8.8.8.8",
        name="12E target",
        description="fixture",
        authorized=True,
        enabled=True,
        authorization_confirmed_at="2026-10-13T14:00:00",
        authorization_confirmation_version=PUBLIC_IPV4_CONFIRMATION_VERSION,
        authorization_source="test_explicit_authorization",
        db_path=path,
    )
    device = create_scope_device(
        scope["id"],
        first_seen="2026-10-13T14:00:00",
        last_seen="2026-10-13T14:00:00",
        status="ONLINE",
        db_path=path,
    )
    return scope, device


def _result(at, port=443, service_name="https", product="nginx", version="1.0"):
    return ServiceDiscoveryResult(
        target_ip="8.8.8.8",
        scanner="bounded-test-scanner",
        started_at=at,
        completed_at=at,
        ports=(PortObservation("8.8.8.8", port, "tcp", "open", at, "12e-test"),),
        services=(ServiceObservation(
            "8.8.8.8", port, "tcp", service_name, product, version, None,
            "HIGH", at, "12e-test",
        ),),
    )


def test_dashboard_aggregates_existing_external_exposure_layers(tmp_path):
    path = tmp_path / "dashboard.db"
    initialize_database(path)
    scope, device = _public_scope_device(path)
    at = datetime(2026, 10, 13, 14, 10, 0)
    ServiceInventoryService(path).process_public_result(scope, device, _result(at))

    dashboard = build_external_exposure_dashboard(
        scope_id=scope["id"], time_range="all", db_path=path,
        now=datetime(2026, 10, 13, 15, 0, 0, tzinfo=timezone.utc),
    )

    assert dashboard["summary"] == {
        "total_exposures": 1,
        "present": 1,
        "absent": 0,
        "expected": 0,
        "unexpected": 0,
        "review": 1,
        "sensitive_admin": 0,
        "internal_style": 0,
        "public_targets": 1,
        "recent_changes": 1,
    }
    assert dashboard["service_roles"] == [{"label": "WEB", "total": 1}]
    assert dashboard["exposure_profiles"] == [{"label": "COMMON_PUBLIC_SERVICE", "total": 1}]
    assert dashboard["change_counts"] == [{"label": "NEW_EXPOSURE", "total": 1}]
    assert dashboard["top_ports"][0]["port_number"] == 443
    assert dashboard["top_targets"][0]["target_ip"] == "8.8.8.8"
    assert dashboard["recent_changes"][0]["classification"] == "REVIEW"
    assert dashboard["recent_exposures"][0]["presence_state"] == "PRESENT"


def test_dashboard_change_window_does_not_hide_current_inventory(tmp_path):
    path = tmp_path / "window.db"
    initialize_database(path)
    scope, device = _public_scope_device(path)
    at = datetime(2026, 10, 1, 12, 0, 0)
    ServiceInventoryService(path).process_public_result(scope, device, _result(at))

    dashboard = build_external_exposure_dashboard(
        scope_id=scope["id"], time_range="24h", db_path=path,
        now=datetime(2026, 10, 13, 15, 0, 0, tzinfo=timezone.utc),
    )
    assert dashboard["summary"]["total_exposures"] == 1
    assert dashboard["summary"]["recent_changes"] == 0
    assert dashboard["change_counts"] == []
    assert len(dashboard["recent_exposures"]) == 1


def test_dashboard_rejects_private_scope(tmp_path):
    path = tmp_path / "private.db"
    initialize_database(path)
    scope = create_scope(
        scope_type="PRIVATE_NETWORK",
        canonical_target="192.168.50.0/24",
        name="private",
        description="fixture",
        authorized=True,
        enabled=True,
        authorization_confirmed_at="2026-10-13T14:00:00",
        authorization_confirmation_version="test-private-v1",
        authorization_source="test_explicit_authorization",
        db_path=path,
    )
    try:
        build_external_exposure_dashboard(scope_id=scope["id"], db_path=path)
    except ValueError as exc:
        assert "public scope" in str(exc)
    else:
        raise AssertionError("Private scope must not be accepted by external exposure dashboard.")


def test_dashboard_api_is_read_only_filterable_and_bounded(monkeypatch, tmp_path):
    path = tmp_path / "dashboard-api.db"
    initialize_database(path)
    scope, device = _public_scope_device(path)
    ServiceInventoryService(path).process_public_result(
        scope, device, _result(datetime(2026, 10, 13, 14, 10, 0)),
    )
    monkeypatch.setattr(api, "DB_PATH", path)
    client = make_local_test_client(api.app)

    response = client.get(
        f"/external-exposure-dashboard?scope_id={scope['id']}&time_range=all&recent_limit=5"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["filters"] == {"scope_id": scope["id"], "time_range": "all"}
    assert body["summary"]["total_exposures"] == 1
    assert len(body["recent_exposures"]) == 1

    assert client.get("/external-exposure-dashboard?time_range=1h").status_code == 422
    assert client.get("/external-exposure-dashboard?recent_limit=51").status_code == 422
    assert client.get("/external-exposure-dashboard?scope_id=999999").status_code == 404
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/external-exposure-dashboard"].keys()) == {"get"}
