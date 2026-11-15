import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.http_fingerprint import register_http_fingerprint_routes
from api.sensor_enrollment import SensorBodyLimitMiddleware
from database.db import get_connection, initialize_database
from services.http_endpoint_observations import persist_http_endpoint_observation
from tests.test_http_endpoint_history_api import _add_target, _http_result, _store


@contextmanager
def _database_connection(path):
    connection = get_connection(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def create_app():
    database_path = os.environ["SENTINELIP_DATABASE_PATH"]
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["*"],
    )
    app.add_middleware(SensorBodyLimitMiddleware)
    register_http_fingerprint_routes(app, lambda: database_path)
    return app


class LocalApi:
    def __init__(self, database_path):
        self.database_path = database_path
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        self.port = listener.getsockname()[1]
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "tests.test_http_endpoint_history_asgi:create_app",
             "--factory", "--fd", str(listener.fileno()), "--log-level", "warning",
             "--timeout-graceful-shutdown", "2"],
            cwd=os.getcwd(), env={**os.environ, "SENTINELIP_DATABASE_PATH": str(database_path)},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            pass_fds=(listener.fileno(),),
        )
        listener.close()
        self._wait_ready()

    def _wait_ready(self):
        deadline = time.monotonic() + 10
        last_error = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                error = self.process.stderr.read().decode("utf-8", "replace")[-4096:]
                raise RuntimeError(
                    f"Uvicorn exited during startup with status {self.process.returncode}: {error}"
                )
            try:
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.5)
                connection.request("GET", "/openapi.json")
                response = connection.getresponse()
                response.read(4096)
                connection.close()
                if response.status == 200:
                    return
                last_error = RuntimeError(f"OpenAPI readiness returned {response.status}.")
            except OSError as exc:
                last_error = exc
            time.sleep(0.05)
        self.close()
        raise TimeoutError(f"Uvicorn did not become ready within 10 seconds: {last_error}")

    def request(self, path, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        body = response.read(2_200_000)
        connection.close()
        if len(body) >= 2_200_000:
            raise AssertionError("Response exceeded the test client read bound.")
        return response.status, response.getheaders(), json.loads(body) if body else None

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        assert self.process.poll() is not None


@pytest.fixture
def asgi_fixture(tmp_path):
    database_path = tmp_path / "http-history-asgi.db"
    initialize_database(database_path)
    first = _add_target(database_path, "asgi-first", "192.168.51.0/24", "192.168.51.10")
    second = _add_target(database_path, "asgi-second", "192.168.52.0/24", "192.168.52.10")
    server = LocalApi(database_path)
    try:
        yield database_path, first, second, server
    finally:
        server.close()


def _path(target):
    scope, device, port = target
    return f"/scopes/{scope['id']}/devices/{device['id']}/ports/{port['id']}/http-observations"


def test_real_uvicorn_http_history_authorization_pagination_and_no_side_effects(asgi_fixture):
    database_path, first, second, server = asgi_fixture
    equal_time = "2026-11-01T12:00:00+00:00"
    initial = [_store(database_path, first, observed_at=equal_time) for _ in range(4)]
    https = _store(database_path, first, scheme="https", observed_at="2026-11-02T12:00:00+00:00")
    failed_tls = _store(database_path, first, scheme="https", outcome="TLS_VERIFICATION_FAILED",
                        observed_at="2026-11-03T12:00:00+00:00")
    other_run = _store(database_path, second)
    with _database_connection(database_path) as connection:
        before = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM recon_scan_runs),"
            "(SELECT COUNT(*) FROM recon_scan_targets),"
            "(SELECT COUNT(*) FROM http_endpoint_observations),"
            "(SELECT COUNT(*) FROM http_tls_observations)"
        ).fetchone())

    status, headers, body = server.request(_path(first))
    assert status == 200
    assert dict((key.lower(), value) for key, value in headers)["cache-control"] == "no-store"
    assert body["returned"] == 6 and body["limit"] == 20 and body["next_cursor"] is None
    assert all({"id", "scope_id", "device_id", "port_id", "target_ip", "scheme", "tls", "scan"} <= item.keys()
               for item in body["items"])
    by_id = {item["id"]: item for item in body["items"]}
    assert by_id[https["observation_id"]]["tls"]["sha256_fingerprint"] == "b" * 64
    failed = by_id[failed_tls["observation_id"]]
    assert failed["tls"]["verification_status"] == "FAILED"
    assert failed["tls"]["sha256_fingerprint"] is None
    assert failed["tls"]["certificate_subject"] is None
    assert not any("secret" in json.dumps(item).lower() for item in body["items"])

    first_page_status, _, page1 = server.request(_path(first) + "?limit=2")
    assert first_page_status == 200 and page1["returned"] == 2
    newer_result = _http_result(first, observed_at="2026-11-04T12:00:00+00:00")
    newer = persist_http_endpoint_observation(newer_result, database_path)
    cursor = page1["next_cursor"]
    page2_status, _, page2 = server.request(_path(first) + f"?limit=2&cursor={cursor}")
    page3_status, _, page3 = server.request(_path(first) + f"?limit=2&cursor={page2['next_cursor']}")
    paged_ids = [row["id"] for page in (page1, page2, page3) for row in page["items"]]
    assert page2_status == page3_status == 200
    assert len(paged_ids) == 6 and len(set(paged_ids)) == 6
    assert set(paged_ids) == {item["observation_id"] for item in initial} | {
        https["observation_id"], failed_tls["observation_id"]
    }
    assert newer["observation_id"] not in paged_ids
    assert server.request(_path(first) + "?limit=1")[2]["returned"] == 1
    assert server.request(_path(first) + "?limit=100")[2]["returned"] == 7
    assert server.request(_path(first) + f"?scan_run_id={initial[0]['scan_run_id']}")[2]["returned"] == 1
    assert server.request(_path(first) + f"?scan_run_id={other_run['scan_run_id']}")[0] == 404
    assert server.request(_path(first) + "?cursor=broken")[0] == 422
    tampered = page1["next_cursor"][:-1] + ("0" if page1["next_cursor"][-1] != "0" else "1")
    assert server.request(_path(first) + f"?limit=2&cursor={tampered}")[0] == 422

    wrong_device = f"/scopes/{first[0]['id']}/devices/{second[1]['id']}/ports/{second[2]['id']}/http-observations"
    wrong_scope = f"/scopes/{second[0]['id']}/devices/{first[1]['id']}/ports/{first[2]['id']}/http-observations"
    assert server.request(wrong_device)[0] == 404
    assert server.request(wrong_scope)[0] == 404
    wrong_port = f"/scopes/{first[0]['id']}/devices/{first[1]['id']}/ports/{first[2]['id'] + 999}/http-observations"
    missing_device = f"/scopes/{first[0]['id']}/devices/99999999/ports/{first[2]['id']}/http-observations"
    assert server.request(wrong_port)[0] == 404
    assert server.request(missing_device)[0] == 404
    assert server.request(_path(first), {"X-Forwarded-For": "127.0.0.1"})[0] == 403
    assert server.request(_path(first), {"Forwarded": "for=127.0.0.1"})[0] == 403
    assert server.request(_path(first), {"Authorization": "Bearer fixture"})[0] == 403
    assert server.request(_path(first), {"X-SentinelIP-Sensor-Token": "fixture"})[0] == 403
    with _database_connection(database_path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (first[0]["id"],))
    assert server.request(_path(first))[0] == 403
    with _database_connection(database_path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=1,authorization_confirmation_version='' WHERE id=?",
                           (first[0]["id"],))
    assert server.request(_path(first))[0] == 403
    with _database_connection(database_path) as connection:
        connection.execute("UPDATE authorized_scopes SET authorization_confirmation_version='1' WHERE id=?",
                           (first[0]["id"],))
        after = tuple(connection.execute(
            "SELECT (SELECT COUNT(*) FROM recon_scan_runs),"
            "(SELECT COUNT(*) FROM recon_scan_targets),"
            "(SELECT COUNT(*) FROM http_endpoint_observations),"
            "(SELECT COUNT(*) FROM http_tls_observations)"
        ).fetchone())
    assert after == (before[0] + 1, before[1] + 1, before[2] + 1, before[3])


def test_real_uvicorn_denies_sensor_and_forwarded_headers_before_history_reads(asgi_fixture):
    database_path, first, _, server = asgi_fixture
    _store(database_path, first)
    for headers in (
        {"X-Sensor-UUID": "fixture"},
        {"X-SentinelIP-Sensor-ID": "1"},
        {"X-SentinelIP-Sensor-Token": "fixture"},
        {"X-Forwarded-Host": "localhost"},
        {"Host": "example.invalid"},
    ):
        assert server.request(_path(first), headers)[0] == 403
