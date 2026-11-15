import asyncio
from datetime import datetime, timezone
import json
import sqlite3

import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from starlette.responses import Response

from api.http_fingerprint import HttpFingerprintRequest, register_http_fingerprint_routes
from api.remote_sensors import local_management
from database.db import get_connection, initialize_database
from services.http_endpoint_observations import persist_http_endpoint_observation
from services.http_endpoint_history import list_http_endpoint_history
from services.http_endpoint_fingerprint import HttpEndpointError
from tests.test_http_endpoint_history_api import _add_target, _http_result
from tests.test_http_endpoint_observations import _tls_result


@pytest.fixture
def integration_db(tmp_path):
    path = tmp_path / "fingerprint-persistence-integration.db"
    initialize_database(path)
    target = _add_target(path, "fingerprint-integration", "192.168.61.0/24", "192.168.61.10")
    return path, target


def _fresh_result(target, scheme="http", outcome="RESPONSE_RECEIVED"):
    scope, device, port = target
    observed = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if scheme == "https":
        result = _tls_result(scope, device, port, outcome=outcome,
                             verification="FAILED" if outcome == "TLS_VERIFICATION_FAILED" else "VERIFIED")
        result["observed_at"] = observed
        target_ip = device["last_ip_address"]
        result["target_ip"] = target_ip
        result["host"] = f"{target_ip}:8080"
        result["tls"]["verification_name"] = target_ip
        result["tls"]["subject_alt_names"] = (
            [{"type": "IP Address", "value": target_ip}]
            if outcome == "RESPONSE_RECEIVED" else []
        )
        return result
    result = _http_result(target, observed_at=observed, scheme=scheme, outcome=outcome)
    return result


def _handler(path, target, monkeypatch, inspector, persister=None, *, scheme="http"):
    import api.http_fingerprint as api_module

    class InspectorFactory:
        def __init__(self, _db_path):
            pass

        async def inspect(self, scope_id, device_id, port_id, *, scheme):
            return await inspector(scope_id, device_id, port_id, scheme)

    monkeypatch.setattr(api_module, "HttpEndpointFingerprintService", InspectorFactory)
    if persister is not None:
        monkeypatch.setattr(api_module, "persist_http_endpoint_observation", persister)
    app = FastAPI()
    register_http_fingerprint_routes(app, lambda: path)
    route = next(item for item in app.routes if item.path.endswith("/fingerprint-http"))
    scope, device, port = target
    url_path = f"/scopes/{scope['id']}/devices/{device['id']}/ports/{port['id']}/fingerprint-http"
    request = Request({
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": url_path,
        "raw_path": url_path.encode("ascii"), "query_string": b"", "headers": [],
        "client": ("127.0.0.1", 4391), "server": ("127.0.0.1", 80),
    })
    response = Response()
    local_management(request, response)
    return route.endpoint(scope["id"], device["id"], port["id"], HttpFingerprintRequest(scheme=scheme))


def _counts(path):
    connection = get_connection(path)
    try:
        return tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM recon_scan_runs),"
            "(SELECT COUNT(*) FROM recon_scan_targets),"
            "(SELECT COUNT(*) FROM http_endpoint_observations),"
            "(SELECT COUNT(*) FROM http_tls_observations)"
        ).fetchone())
    finally:
        connection.close()


def test_api_persists_http_and_verified_https_for_history_readback(integration_db, monkeypatch):
    path, target = integration_db
    async def inspector(scope_id, device_id, port_id, scheme):
        result = _fresh_result(target, scheme=scheme)
        result.update({"scope_id": scope_id, "device_id": device_id, "port_id": port_id})
        return result

    response = asyncio.run(_handler(path, target, monkeypatch, inspector))
    assert response["persistence"]["status"] == "PERSISTED"
    http_page = list_http_endpoint_history(target[0]["id"], target[1]["id"], target[2]["id"], db_path=path)
    assert http_page["items"][0]["id"] == response["persistence"]["observation_id"]
    assert http_page["items"][0]["scan"]["run_id"] == response["persistence"]["scan_run_id"]

    https_target = target
    async def https_inspector(scope_id, device_id, port_id, scheme):
        https_result = _fresh_result(https_target, scheme="https")
        https_result.update({"scope_id": scope_id, "device_id": device_id, "port_id": port_id})
        return https_result

    response = asyncio.run(_handler(path, https_target, monkeypatch, https_inspector, scheme="https"))
    tls_page = list_http_endpoint_history(target[0]["id"], target[1]["id"], target[2]["id"], db_path=path)
    https_item = next(item for item in tls_page["items"] if item["id"] == response["persistence"]["observation_id"])
    assert https_item["outcome"] == "RESPONSE_RECEIVED"
    assert https_item["tls"]["verification_status"] == "VERIFIED"
    assert https_item["tls"]["sha256_fingerprint"] == "a" * 64
    connection = get_connection(path)
    try:
        run_times = connection.execute(
            "SELECT started_at,completed_at FROM recon_scan_runs WHERE id=?",
            (response["persistence"]["scan_run_id"],),
        ).fetchone()
    finally:
        connection.close()
    assert run_times[0] <= run_times[1]
    assert run_times[1] >= https_item["observed_at"]
    assert _counts(path) == (2, 2, 2, 1)


def test_failed_tls_is_persisted_without_certificate_facts(integration_db, monkeypatch):
    path, target = integration_db
    async def inspector(scope_id, device_id, port_id, scheme):
        result = _fresh_result(target, scheme="https", outcome="TLS_VERIFICATION_FAILED")
        result.update({"scope_id": scope_id, "device_id": device_id, "port_id": port_id})
        return result

    response = asyncio.run(_handler(path, target, monkeypatch, inspector, scheme="https"))
    assert response["outcome"] == "TLS_VERIFICATION_FAILED"
    assert response["persistence"]["status"] == "PERSISTED"
    item = list_http_endpoint_history(target[0]["id"], target[1]["id"], target[2]["id"], db_path=path)["items"][0]
    assert item["id"] == response["persistence"]["observation_id"]
    assert item["tls"]["verification_status"] == "FAILED"
    assert item["tls"]["certificate_subject"] is None
    assert item["tls"]["sha256_fingerprint"] is None


@pytest.mark.parametrize("outcome", ["TIMEOUT", "CONNECTION_FAILED"])
def test_failed_http_transport_outcomes_are_persisted_as_failed_runs(integration_db, monkeypatch, outcome):
    path, target = integration_db
    async def inspector(scope_id, device_id, port_id, scheme):
        result = _fresh_result(target, outcome=outcome)
        result.update({"scope_id": scope_id, "device_id": device_id, "port_id": port_id})
        return result

    response = asyncio.run(_handler(path, target, monkeypatch, inspector))
    assert response["outcome"] == outcome
    assert response["persistence"]["status"] == "PERSISTED"
    item = list_http_endpoint_history(target[0]["id"], target[1]["id"], target[2]["id"], db_path=path)["items"][0]
    assert item["id"] == response["persistence"]["observation_id"]
    assert item["scan"]["status"] == "FAILED"
    assert item["scan"]["target_outcome"] == "FAILED"


def test_capacity_rejection_skips_persistence(integration_db, monkeypatch):
    path, target = integration_db
    async def inspector(scope_id, device_id, port_id, scheme):
        result = _fresh_result(target)
        result.update({"scope_id": scope_id, "device_id": device_id, "port_id": port_id,
                       "outcome": "CAPACITY_REJECTED", "error_category": "capacity"})
        return result
    def forbidden_persist(*args, **kwargs):
        raise AssertionError("Capacity rejection must not be persisted.")

    response = asyncio.run(_handler(path, target, monkeypatch, inspector, forbidden_persist))
    assert response["outcome"] == "CAPACITY_REJECTED"
    assert response["persistence"] == {"status": "NOT_ATTEMPTED", "reason": "capacity_rejected"}
    assert _counts(path) == (0, 0, 0, 0)


def test_persistence_failure_is_bounded_and_does_not_repeat_inspection(integration_db, monkeypatch):
    path, target = integration_db
    calls = []
    async def inspector(scope_id, device_id, port_id, scheme):
        calls.append((scope_id, device_id, port_id, scheme))
        result = _fresh_result(target)
        result.update({"scope_id": scope_id, "device_id": device_id, "port_id": port_id})
        return result
    def failing_persist(*args, **kwargs):
        raise sqlite3.OperationalError("/private/customer/sentinelip.db is unavailable")

    with pytest.raises(HTTPException) as raised:
        asyncio.run(_handler(path, target, monkeypatch, inspector, failing_persist))
    assert raised.value.status_code == 503
    detail = raised.value.detail
    assert detail["code"] == "observation_persistence_failed"
    assert detail["persistence_status"] == "FAILED"
    assert "observation_id" not in detail and "sentinelip.db" not in json.dumps(detail)
    assert len(calls) == 1
    assert _counts(path) == (0, 0, 0, 0)


def test_persistence_rechecks_authorization_before_atomic_write(integration_db, monkeypatch):
    path, target = integration_db
    async def inspector(scope_id, device_id, port_id, scheme):
        connection = get_connection(path)
        try:
            connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (scope_id,))
            connection.commit()
        finally:
            connection.close()
        result = _fresh_result(target)
        result.update({"scope_id": scope_id, "device_id": device_id, "port_id": port_id})
        return result

    with pytest.raises(HTTPException) as raised:
        asyncio.run(_handler(path, target, monkeypatch, inspector))
    assert raised.value.status_code == 503
    assert raised.value.detail["inspection_outcome"] == "RESPONSE_RECEIVED"
    assert _counts(path) == (0, 0, 0, 0)


def test_authorization_exception_is_not_persisted(integration_db, monkeypatch):
    path, target = integration_db
    async def inspector(*args):
        raise HttpEndpointError("An enabled authorized scope is required.", 403)
    def forbidden_persist(*args, **kwargs):
        raise AssertionError("Authorization failures must not be persisted.")

    with pytest.raises(HTTPException) as raised:
        asyncio.run(_handler(path, target, monkeypatch, inspector, forbidden_persist))
    assert raised.value.status_code == 403
    assert _counts(path) == (0, 0, 0, 0)


def test_cancellation_before_result_skips_persistence(integration_db, monkeypatch):
    path, target = integration_db
    entered = asyncio.Event()
    async def inspector(*args):
        entered.set()
        await asyncio.Event().wait()
    def forbidden_persist(*args, **kwargs):
        raise AssertionError("Cancelled inspection must not be persisted.")

    async def scenario():
        task = asyncio.create_task(_handler(path, target, monkeypatch, inspector, forbidden_persist))
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert _counts(path) == (0, 0, 0, 0)
