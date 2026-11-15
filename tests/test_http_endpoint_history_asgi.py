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
from database.services import create_port, save_port_observation
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
    from services import http_endpoint_fingerprint as fingerprint

    class FixtureChannel:
        def __init__(self, port):
            self.port = port
            self.response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n"
                b"Server: fixture/1\r\nDate: Sun, 15 Nov 2026 12:00:00 GMT\r\n"
                b"Set-Cookie: secret=fixture\r\n\r\nBODY-SECRET"
            )
            self.sent = bytearray()
            self.closed = False

        async def sendall(self, data, deadline):
            self.sent.extend(data)

        async def recv(self, size, deadline):
            result = self.response[:size]
            self.response = self.response[size:]
            return result

        def close(self):
            self.closed = True

    class FixtureConnector:
        async def connect(self, target_ip, port, deadline):
            if port == 9444:
                raise ConnectionRefusedError("fixture refusal")
            return FixtureChannel(port)

    async def establish_fixture_tls(cls, channel, context, server_hostname, deadline):
        if channel.port == 9443:
            raise fingerprint._TLSHandshakeFailure("untrusted_certificate", verification_failed=True)
        return type("FixtureTLSChannel", (), {
            "ssl_object": object(),
            "sendall": channel.sendall,
            "recv": channel.recv,
            "close": channel.close,
        })()

    def verified_fixture_tls(ssl_object, endpoint):
        return {
            "protocol_version": "TLSv1.3",
            "cipher": {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
            "certificate_subject": [{"name": "commonName", "value": "fixture.local"}],
            "certificate_issuer": [{"name": "commonName", "value": "fixture CA"}],
            "not_before": "2026-11-15T00:00:00+00:00",
            "not_after": "2027-11-15T00:00:00+00:00",
            "subject_alt_names": [{"type": "IP Address", "value": endpoint["target_ip"]}],
            "sha256_fingerprint": "c" * 64,
            "certificate_verification": "VERIFIED",
            "hostname_verification": None,
            "ip_address_verification": "MATCHED",
            "verification_name": endpoint["target_ip"],
            "error_category": None,
        }

    fingerprint.DirectIPv4Connector = FixtureConnector
    fingerprint._TLSChannel.establish = classmethod(establish_fixture_tls)
    fingerprint._verified_tls_observation = verified_fixture_tls
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

    def request(self, path, headers=None, *, method="GET", body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        request_headers = dict(headers or {})
        payload = None if body is None else json.dumps(body)
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=payload, headers=request_headers)
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
    extra_ports = {}
    for number in (8443, 9443, 9444):
        port = create_port(first[1]["id"], number, "tcp", "open", "2026-10-01T00:00:00+00:00",
                           "2026-10-01T00:00:00+00:00", database_path)
        save_port_observation(
            device_id=first[1]["id"], port_id=port["id"], ip_address=first[1]["last_ip_address"],
            port_number=number, transport="tcp", state="open",
            observed_at="2026-10-01T00:00:00+00:00", source="nmap", db_path=database_path,
        )
        extra_ports[number] = port
    server = LocalApi(database_path)
    try:
        yield database_path, first, second, extra_ports, server
    finally:
        server.close()


def _path(target):
    scope, device, port = target
    return f"/scopes/{scope['id']}/devices/{device['id']}/ports/{port['id']}/http-observations"


def test_real_uvicorn_http_history_authorization_pagination_and_no_side_effects(asgi_fixture):
    database_path, first, second, _, server = asgi_fixture
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
    database_path, first, _, _, server = asgi_fixture
    _store(database_path, first)
    for headers in (
        {"X-Sensor-UUID": "fixture"},
        {"X-SentinelIP-Sensor-ID": "1"},
        {"X-SentinelIP-Sensor-Token": "fixture"},
        {"X-Forwarded-Host": "localhost"},
        {"Host": "example.invalid"},
    ):
        assert server.request(_path(first), headers)[0] == 403


def test_real_uvicorn_inspection_persists_http_https_failures_and_history_readback(asgi_fixture):
    database_path, first, _, extra_ports, server = asgi_fixture

    def inspect_path(port):
        return (f"/scopes/{first[0]['id']}/devices/{first[1]['id']}/ports/"
                f"{port['id']}/fingerprint-http")

    http_status, _, http_body = server.request(
        inspect_path(first[2]), method="POST", body={"scheme": "http"},
    )
    assert http_status == 200
    assert http_body["outcome"] == "RESPONSE_RECEIVED"
    assert http_body["persistence"]["status"] == "PERSISTED"
    http_id = http_body["persistence"]["observation_id"]
    http_run = http_body["persistence"]["scan_run_id"]
    assert server.request(_path(first) + f"?scan_run_id={http_run}")[2]["items"][0]["id"] == http_id
    assert "BODY-SECRET" not in json.dumps(http_body)
    assert "secret" not in json.dumps(http_body).lower()

    https_status, _, https_body = server.request(
        inspect_path(extra_ports[8443]), method="POST", body={"scheme": "https"},
    )
    assert https_status == 200 and https_body["outcome"] == "RESPONSE_RECEIVED"
    https_id = https_body["persistence"]["observation_id"]
    https_run = https_body["persistence"]["scan_run_id"]
    history = server.request(
        _path((first[0], first[1], extra_ports[8443])) + f"?scan_run_id={https_run}"
    )[2]
    assert history["returned"] == 1
    assert history["items"][0]["id"] == https_id
    assert history["items"][0]["tls"]["verification_status"] == "VERIFIED"
    assert history["items"][0]["tls"]["sha256_fingerprint"] == "c" * 64

    failed_status, _, failed_body = server.request(
        inspect_path(extra_ports[9443]), method="POST", body={"scheme": "https"},
    )
    assert failed_status == 200
    assert failed_body["outcome"] == "TLS_VERIFICATION_FAILED"
    assert failed_body["persistence"]["status"] == "PERSISTED"
    failed_history = server.request(
        _path((first[0], first[1], extra_ports[9443]))
        + f"?scan_run_id={failed_body['persistence']['scan_run_id']}"
    )[2]["items"][0]
    assert failed_history["id"] == failed_body["persistence"]["observation_id"]
    assert failed_history["tls"]["verification_status"] == "FAILED"
    assert failed_history["tls"]["certificate_subject"] is None
    assert failed_history["tls"]["sha256_fingerprint"] is None

    refused_status, _, refused_body = server.request(
        inspect_path(extra_ports[9444]), method="POST", body={"scheme": "http"},
    )
    assert refused_status == 200 and refused_body["outcome"] == "CONNECTION_FAILED"
    assert refused_body["persistence"]["status"] == "PERSISTED"
    assert server.request(
        _path((first[0], first[1], extra_ports[9444]))
        + f"?scan_run_id={refused_body['persistence']['scan_run_id']}"
    )[2]["items"][0]["outcome"] == "CONNECTION_FAILED"

    with _database_connection(database_path) as connection:
        rows = connection.execute(
            "SELECT COUNT(*) FROM http_endpoint_observations WHERE device_id=?",
            (first[1]["id"],),
        ).fetchone()[0]
        stored_tls = connection.execute(
            "SELECT verification_status,sha256_fingerprint FROM http_tls_observations "
            "WHERE endpoint_observation_id=?", (failed_body["persistence"]["observation_id"],),
        ).fetchone()
    assert rows == 4
    assert tuple(stored_tls) == ("FAILED", None)
