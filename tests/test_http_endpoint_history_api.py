import json
import sqlite3
from urllib.parse import parse_qs

import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from starlette.responses import Response

from api.http_fingerprint import register_http_fingerprint_routes
from api.remote_sensors import local_management
from database.db import get_connection, initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.scopes import get_scope_for_network
from database.services import create_port, save_port_observation
from services.http_endpoint_observations import persist_http_endpoint_observation
from services.http_endpoint_history import MAX_HISTORY_RESPONSE_BYTES


class DirectResponse:
    def __init__(self, status_code, body, headers):
        self.status_code = status_code
        self._body = body
        self.headers = headers
        self.content = json.dumps(body, ensure_ascii=True).encode("ascii")

    def json(self):
        return self._body


def _add_target(path, stable_key, cidr, ip):
    network = create_network(cidr, stable_key, "", True, True, path)
    scope = get_scope_for_network(network["id"], path)
    device = create_device(
        stable_key=stable_key, network_id=network["id"], mac_address=None, hostname=None,
        vendor=None, first_seen="2026-10-01T00:00:00+00:00",
        last_seen="2026-10-01T00:00:00+00:00", last_ip_address=ip,
        status="ONLINE", identity_confidence="LOW", db_path=path,
    )
    port = create_port(device["id"], 8080, "tcp", "open", "2026-10-01T00:00:00+00:00",
                       "2026-10-01T00:00:00+00:00", path)
    save_port_observation(
        device_id=device["id"], port_id=port["id"], ip_address=ip,
        port_number=8080, transport="tcp", state="open",
        observed_at="2026-10-01T00:00:00+00:00", source="nmap", db_path=path,
    )
    return scope, device, port


@pytest.fixture
def history_db(tmp_path):
    path = tmp_path / "http-history-api.db"
    initialize_database(path)
    first = _add_target(path, "history-first", "192.168.41.0/24", "192.168.41.10")
    second = _add_target(path, "history-second", "192.168.42.0/24", "192.168.42.10")
    return path, first, second


def _http_result(target, *, observed_at="2026-11-01T12:00:00+00:00", scheme="http", outcome="RESPONSE_RECEIVED"):
    scope, device, port = target
    result = {
        "scope_id": scope["id"], "device_id": device["id"], "port_id": port["id"],
        "scheme": scheme, "target_ip": device["last_ip_address"], "host": f"{device['last_ip_address']}:8080",
        "observed_at": observed_at, "source": "http-head-v1", "status_code": 200,
        "response_headers": {"date": "Sun, 01 Nov 2026 12:00:00 GMT"},
        "content_type": "text/plain", "content_length": 0,
        "server_identifier": {"value": "fixture-server", "confidence": "LOW", "source": "http_response_header"},
        "redirect_location": None, "outcome": outcome, "error_category": None,
    }
    if outcome != "RESPONSE_RECEIVED":
        result.update({"status_code": None, "response_headers": {}, "content_type": None,
                       "content_length": None, "server_identifier": None,
                       "error_category": "untrusted_certificate"})
    if scheme == "https":
        verified = outcome == "RESPONSE_RECEIVED"
        result["source"] = "https-tls-head-v1"
        result["tls"] = {
            "protocol_version": "TLSv1.3" if verified else None,
            "cipher": ({"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256} if verified else None),
            "certificate_subject": ([{"name": "commonName", "value": "fixture"}] if verified else []),
            "certificate_issuer": ([{"name": "commonName", "value": "fixture-ca"}] if verified else []),
            "not_before": "Nov 01 00:00:00 2026 GMT" if verified else None,
            "not_after": "Nov 01 00:00:00 2027 GMT" if verified else None,
            "subject_alt_names": ([{"type": "IP Address", "value": device["last_ip_address"]}] if verified else []),
            "sha256_fingerprint": "b" * 64 if verified else None,
            "certificate_verification": "VERIFIED" if verified else "FAILED",
            "hostname_verification": None,
            "ip_address_verification": "MATCHED" if verified else "NOT_COMPLETED",
            "verification_name": device["last_ip_address"],
            "error_category": None if verified else "untrusted_certificate",
        }
    return result


def _store(path, target, **kwargs):
    return persist_http_endpoint_observation(_http_result(target, **kwargs), path)


def _url(target):
    scope, device, port = target
    return f"/scopes/{scope['id']}/devices/{device['id']}/ports/{port['id']}/http-observations"


def _dispatch(path, target, query="", *, address="127.0.0.1", headers=None):
    app = FastAPI()
    register_http_fingerprint_routes(app, lambda: path)
    route = next(route for route in app.routes if route.path.endswith("/http-observations"))
    scope, device, port = target
    request = Request({
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "GET", "scheme": "http", "path": _url(target),
        "raw_path": _url(target).encode("ascii"), "query_string": query.encode("ascii"),
        "headers": [(key.lower().encode("ascii"), value.encode("latin-1")) for key, value in (headers or {}).items()],
        "client": (address, 4317), "server": ("127.0.0.1", 80),
    })
    response = Response()
    try:
        local_management(request, response)
        values = parse_qs(query, keep_blank_values=True)
        raw_limit = values.get("limit", ["20"])[0]
        try:
            limit = int(raw_limit)
        except ValueError as exc:
            raise HTTPException(422, "Invalid page size.") from exc
        body = route.endpoint(
            request, scope_id=scope["id"], device_id=device["id"], port_id=port["id"],
            limit=limit, cursor=values.get("cursor", [None])[0],
            scan_run_id=values.get("scan_run_id", [None])[0],
        )
        return DirectResponse(200, body, response.headers)
    except HTTPException as exc:
        return DirectResponse(exc.status_code, {"detail": exc.detail}, response.headers)
    except Exception:
        return DirectResponse(500, {"detail": "Internal server error."}, response.headers)


def test_empty_history_and_single_http_projection_are_bounded_and_read_only(history_db):
    path, first, _ = history_db
    assert _dispatch(path, first).json() == {"items": [], "limit": 20, "returned": 0, "next_cursor": None}
    _store(path, first)
    with get_connection(path) as connection:
        before = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM recon_scan_runs),(SELECT COUNT(*) FROM http_endpoint_observations)"
        ).fetchone())
    response = _dispatch(path, first)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["limit"] == 20 and body["returned"] == 1 and body["next_cursor"] is None
    item = body["items"][0]
    assert item["outcome"] == "RESPONSE_RECEIVED" and item["status_code"] == 200
    assert item["server_identifier"] == {"value": "fixture-server", "confidence": "LOW", "source": "http_response_header"}
    assert item["tls"] is None and item["scan"]["profile"] == "http_endpoint_fingerprint"
    assert not any(any(secret in key.lower() for secret in ("cookie", "authorization", "credential", "token", "body"))
                   for key in item)
    with get_connection(path) as connection:
        after = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM recon_scan_runs),(SELECT COUNT(*) FROM http_endpoint_observations)"
        ).fetchone())
    assert before == after
    assert len(response.content) <= MAX_HISTORY_RESPONSE_BYTES


def test_https_verified_and_failed_tls_projections_do_not_invent_certificate_facts(history_db):
    path, first, _ = history_db
    _store(path, first, scheme="https")
    _store(path, first, scheme="https", outcome="TLS_VERIFICATION_FAILED", observed_at="2026-11-02T12:00:00+00:00")
    items = _dispatch(path, first).json()["items"]
    failed = next(item for item in items if item["outcome"] == "TLS_VERIFICATION_FAILED")
    verified = next(item for item in items if item["outcome"] == "RESPONSE_RECEIVED")
    assert failed["tls"]["verification_status"] == "FAILED"
    assert failed["tls"]["sha256_fingerprint"] is None
    assert failed["tls"]["certificate_subject"] is None
    assert verified["tls"]["verification_status"] == "VERIFIED"
    assert verified["tls"]["sha256_fingerprint"] == "b" * 64
    assert verified["tls"]["certificate_subject"][0]["value"] == "fixture"


def test_keyset_pages_are_stable_for_equal_timestamps_and_newer_inserts(history_db):
    path, first, _ = history_db
    stored = [_store(path, first) for _ in range(5)]
    page1 = _dispatch(path, first, "limit=2")
    assert page1.status_code == 200
    page1 = page1.json()
    assert page1["returned"] == 2 and page1["next_cursor"]
    _store(path, first, observed_at="2026-11-03T12:00:00+00:00")
    page2 = _dispatch(path, first, "limit=2&cursor=" + page1["next_cursor"]).json()
    page3 = _dispatch(path, first, "limit=2&cursor=" + page2["next_cursor"]).json()
    ids = [row["id"] for page in (page1, page2, page3) for row in page["items"]]
    assert len(ids) == 5 and len(set(ids)) == 5
    assert set(ids) == {item["observation_id"] for item in stored}
    assert page3["next_cursor"] is None


def test_page_size_bounds_and_cursor_validation(history_db):
    path, first, _ = history_db
    for _ in range(3):
        _store(path, first)
    assert _dispatch(path, first).json()["limit"] == 20
    assert _dispatch(path, first, "limit=1").json()["limit"] == 1
    assert _dispatch(path, first, "limit=100").json()["limit"] == 100
    for query in ("limit=0", "limit=101", "limit=-1", "limit=abc"):
        assert _dispatch(path, first, query).status_code == 422
    cursor = _dispatch(path, first, "limit=1").json()["next_cursor"]
    assert cursor
    bad_digest = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
    assert _dispatch(path, first, "cursor=" + bad_digest).status_code == 422
    assert _dispatch(path, first, "cursor=" + ("A" * 513)).status_code == 422
    assert _dispatch(path, first, "cursor=broken").status_code == 422
    assert _dispatch(path, first, "cursor=" + cursor + "&scan_run_id=00000000-0000-0000-0000-000000000000").status_code == 422


def test_maximum_page_fetch_is_capped_at_one_hundred(history_db):
    path, first, _ = history_db
    for _ in range(101):
        _store(path, first)
    page = _dispatch(path, first, "limit=100").json()
    assert page["limit"] == 100 and page["returned"] == 100
    assert page["next_cursor"] is not None
    assert len(page["items"]) <= 100
    assert len(json.dumps(page, ensure_ascii=True).encode("ascii")) <= MAX_HISTORY_RESPONSE_BYTES


def test_run_filter_is_scope_bound_and_filters_the_result_set(history_db):
    path, first, second = history_db
    first_run = _store(path, first)["scan_run_id"]
    _store(path, first)
    second_run = _store(path, second)["scan_run_id"]
    filtered = _dispatch(path, first, "scan_run_id=" + first_run).json()
    assert filtered["returned"] == 1 and filtered["items"][0]["scan"]["run_id"] == first_run
    assert _dispatch(path, first, "scan_run_id=" + second_run).status_code == 404
    assert _dispatch(path, first, "scan_run_id=not-a-uuid").status_code == 404
    assert _dispatch(path, first, "scan_run_id=" + first_run + "&scan_run_id=" + first_run).status_code == 422


def test_scope_device_port_authorization_and_local_management_boundary(history_db):
    path, first, second = history_db
    assert _dispatch(path, (first[0], second[1], second[2])).status_code == 404
    with get_connection(path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (first[0]["id"],))
    assert _dispatch(path, first).status_code == 403
    with get_connection(path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=1,authorization_source=' ' WHERE id=?", (first[0]["id"],))
    assert _dispatch(path, first).status_code == 403
    app = FastAPI()
    register_http_fingerprint_routes(app, lambda: path)
    route = next(route for route in app.routes if route.path.endswith("/http-observations"))
    assert any(dependency.call is local_management for dependency in route.dependant.dependencies)
    assert _dispatch(path, first, address="192.0.2.10").status_code == 403
    assert _dispatch(path, first, headers={"Authorization": "Bearer secret"}).status_code == 403


def test_wrong_transport_and_unknown_query_parameters_are_rejected(history_db):
    path, first, _ = history_db
    scope, device, _ = first
    udp = create_port(device["id"], 5353, "udp", "open", "2026-10-01T00:00:00+00:00",
                      "2026-10-01T00:00:00+00:00", path)
    save_port_observation(device_id=device["id"], port_id=udp["id"], ip_address=device["last_ip_address"],
                          port_number=5353, transport="udp", state="open",
                          observed_at="2026-10-01T00:00:00+00:00", source="fixture", db_path=path)
    assert _dispatch(path, (scope, device, udp)).status_code == 404
    assert _dispatch(path, first, "unexpected=x").status_code == 422


def test_connection_is_closed_after_success_authorization_failure_and_projection_failure(history_db, monkeypatch):
    path, first, _ = history_db
    _store(path, first)
    import services.http_endpoint_history as history_service
    real_get_connection = history_service.get_connection
    opened = []
    def tracked(db_path):
        connection = real_get_connection(db_path)
        opened.append(connection)
        return connection
    monkeypatch.setattr(history_service, "get_connection", tracked)
    assert _dispatch(path, first).status_code == 200
    with pytest.raises(sqlite3.ProgrammingError):
        opened[-1].execute("SELECT 1")
    with get_connection(path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (first[0]["id"],))
    assert _dispatch(path, first).status_code == 403
    with pytest.raises(sqlite3.ProgrammingError):
        opened[-1].execute("SELECT 1")
    with get_connection(path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=1 WHERE id=?", (first[0]["id"],))
        connection.execute("UPDATE http_endpoint_observations SET response_headers_json='[]'")
    assert _dispatch(path, first).status_code == 500
    with pytest.raises(sqlite3.ProgrammingError):
        opened[-1].execute("SELECT 1")


def test_connection_is_closed_when_authorization_query_fails(tmp_path, monkeypatch):
    import services.http_endpoint_history as history_service
    connection = sqlite3.connect(tmp_path / "missing-schema.db")
    connection.execute("PRAGMA foreign_keys=ON")
    monkeypatch.setattr(history_service, "get_connection", lambda _path: connection)
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        history_service.list_http_endpoint_history(1, 1, 1, db_path=tmp_path / "missing-schema.db")
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
