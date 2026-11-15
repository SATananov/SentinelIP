import asyncio
import json
import os
import sqlite3
import threading

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from api.http_fingerprint import (
    HttpFingerprintRequest,
    register_http_fingerprint_routes,
)
from api.remote_sensors import local_management
from database.db import get_connection, initialize_database
from database.inventory import create_device, create_scope_device
from database.networks import create_network
from database.scopes import create_hostname_scope, get_scope_for_network
from database.services import create_port, save_port_observation
from services.hostname_resolution import HostnameResolution
from services.http_endpoint_fingerprint import (
    HTTP_MAX_HEADER_BYTES,
    HTTP_MAX_METADATA_BYTES,
    HttpEndpointError,
    HttpEndpointFingerprintService,
)
import services.http_endpoint_fingerprint as http_fingerprint_service


class ScriptedChannel:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nBODY-SECRET"):
        self.response = response
        self.sent = bytearray()
        self.closed = False
        self.block = None

    async def sendall(self, data, deadline):
        self.sent.extend(data)

    async def recv(self, size, deadline):
        if self.block is not None:
            await self.block.wait()
        chunk, self.response = self.response[:size], self.response[size:]
        return chunk

    def close(self):
        self.closed = True
        if self.block is not None:
            self.block.set()


class ScriptedConnector:
    def __init__(self, channel=None, error=None):
        self.channel = channel or ScriptedChannel()
        self.error = error
        self.calls = []

    async def connect(self, target_ip, port, deadline):
        self.calls.append((target_ip, port))
        if self.error:
            raise self.error
        return self.channel


class FixedResolver:
    def __init__(self, addresses):
        self.addresses = tuple(addresses)
        self.calls = []

    def resolve(self, hostname):
        self.calls.append(hostname)
        return HostnameResolution(hostname, self.addresses)


@pytest.fixture
def private_endpoint(tmp_path):
    db_path = tmp_path / "http-endpoint.db"
    initialize_database(db_path)
    network = create_network(
        "192.168.1.0/24", "Authorized test network", "", True, True, db_path,
    )
    scope = get_scope_for_network(network["id"], db_path)
    device = create_device(
        stable_key="http-endpoint-test-device",
        network_id=network["id"],
        mac_address=None,
        hostname=None,
        vendor=None,
        first_seen="2026-10-01T00:00:00",
        last_seen="2026-10-01T00:00:00",
        last_ip_address="192.168.1.20",
        status="ONLINE",
        identity_confidence="LOW",
        db_path=db_path,
    )
    port = create_port(
        device["id"], 8080, "tcp", "open", "2026-10-01T00:00:00",
        "2026-10-01T00:00:00", db_path,
    )
    save_port_observation(
        device_id=device["id"], port_id=port["id"], ip_address="192.168.1.20",
        port_number=8080, transport="tcp", state="open",
        observed_at="2026-10-01T00:00:00", source="nmap", db_path=db_path,
    )
    return db_path, scope, device, port


def test_http_fingerprint_pins_ip_sends_one_head_and_filters_metadata(private_endpoint, monkeypatch):
    db_path, scope, device, port = private_endpoint
    channel = ScriptedChannel(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: 123\r\nServer: example/9.9\r\nDate: Tue, 01 Jan 2030 00:00:00 GMT\r\n"
        b"Set-Cookie: secret=do-not-store\r\nAuthorization: secret-token\r\n\r\nBODY-SECRET"
    )
    connector = ScriptedConnector(channel)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    service = HttpEndpointFingerprintService(db_path, connector=connector)

    result = asyncio.run(service.inspect(scope["id"], device["id"], port["id"], scheme="http"))

    assert connector.calls == [("192.168.1.20", 8080)]
    assert channel.sent.count(b"HEAD ") == 1
    assert channel.sent.startswith(b"HEAD / HTTP/1.1\r\n")
    assert b"Host: 192.168.1.20:8080\r\n" in channel.sent
    assert result["status_code"] == 200
    assert result["content_type"] == "text/html; charset=utf-8"
    assert result["content_length"] == 123
    assert result["server_identifier"] == {
        "value": "example/9.9", "confidence": "LOW", "source": "http_response_header",
    }
    assert "set-cookie" not in result["response_headers"]
    assert "authorization" not in result["response_headers"]
    assert "BODY-SECRET" not in json.dumps(result)
    assert "secret-token" not in json.dumps(result)
    assert len(json.dumps(result).encode()) <= HTTP_MAX_METADATA_BYTES
    assert channel.closed


def test_redirect_is_sanitized_and_never_followed(private_endpoint):
    db_path, scope, device, port = private_endpoint
    connector = ScriptedConnector(ScriptedChannel(
        b"HTTP/1.1 302 Found\r\nLocation: https://user:pass@redirect.invalid/a/b?token=secret#frag\r\n\r\n"
    ))
    result = asyncio.run(HttpEndpointFingerprintService(db_path, connector=connector).inspect(
        scope["id"], device["id"], port["id"],
    ))
    assert result["status_code"] == 302
    assert result["redirect_location"] == "https://redirect.invalid/a/b"
    assert connector.calls == [("192.168.1.20", 8080)]
    assert "secret" not in json.dumps(result)


def test_hostname_scope_uses_confirmed_hostname_and_revalidates_dns(tmp_path):
    path = tmp_path / "hostname.db"
    initialize_database(path)
    scope = create_hostname_scope(
        canonical_hostname="authorized.example.test",
        approved_addresses=["8.8.8.8"],
        authorization_confirmed_at="2026-10-01T00:00:00",
        authorization_confirmation_version="hostname_authorization_v1",
        authorization_source="test",
        resolution_version="hostname-a-resolution-v1",
        db_path=path,
    )
    device = create_scope_device(
        scope["id"], ip_address="8.8.8.8", first_seen="2026-10-01T00:00:00",
        last_seen="2026-10-01T00:00:00", status="ONLINE", db_path=path,
    )
    port = _add_observed_port(path, device["id"], "8.8.8.8")
    resolver = FixedResolver(["8.8.8.8"])
    connector = ScriptedConnector()
    result = asyncio.run(HttpEndpointFingerprintService(
        path, resolver=resolver, connector=connector,
    ).inspect(scope["id"], device["id"], port["id"]))
    assert resolver.calls == ["authorized.example.test"]
    assert connector.calls == [("8.8.8.8", 8080)]
    assert b"Host: authorized.example.test:8080\r\n" in connector.channel.sent
    assert result["host"] == "authorized.example.test:8080"


def test_hostname_dns_rebinding_prevents_connection(tmp_path):
    path = tmp_path / "rebind.db"
    initialize_database(path)
    scope = create_hostname_scope(
        canonical_hostname="authorized.example.test", approved_addresses=["8.8.8.8"],
        authorization_confirmed_at="2026-10-01T00:00:00",
        authorization_confirmation_version="hostname_authorization_v1",
        authorization_source="test", resolution_version="hostname-a-resolution-v1", db_path=path,
    )
    device = create_scope_device(scope["id"], ip_address="8.8.8.8", first_seen="2026-10-01",
                                last_seen="2026-10-01", status="ONLINE", db_path=path)
    port = _add_observed_port(path, device["id"], "8.8.8.8")
    connector = ScriptedConnector()
    with pytest.raises(Exception, match="DNS results changed"):
        asyncio.run(HttpEndpointFingerprintService(
            path, resolver=FixedResolver(["1.1.1.1"]), connector=connector,
        ).inspect(scope["id"], device["id"], port["id"]))
    assert connector.calls == []


@pytest.mark.parametrize("change", ["unauthorized", "disabled", "out_of_scope", "ipv6", "loopback", "closed_port"])
def test_scope_device_address_and_port_are_revalidated(private_endpoint, change):
    db_path, scope, device, port = private_endpoint
    with get_connection(db_path) as connection:
        if change == "unauthorized":
            connection.execute("UPDATE authorized_scopes SET authorized=0 WHERE id=?", (scope["id"],))
        elif change == "disabled":
            connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (scope["id"],))
        elif change in {"out_of_scope", "ipv6", "loopback"}:
            target = {"out_of_scope": "192.168.2.20", "ipv6": "::1", "loopback": "127.0.0.1"}[change]
            connection.execute("UPDATE devices SET last_ip_address=? WHERE id=?", (target, device["id"]))
        elif change == "closed_port":
            connection.execute("UPDATE ports SET state='closed' WHERE id=?", (port["id"],))
    connector = ScriptedConnector()
    with pytest.raises(HttpEndpointError):
        asyncio.run(HttpEndpointFingerprintService(db_path, connector=connector).inspect(
            scope["id"], device["id"], port["id"],
        ))
    assert connector.calls == []


def test_nonexistent_or_other_device_port_is_rejected(private_endpoint):
    db_path, scope, device, port = private_endpoint
    connector = ScriptedConnector()
    with pytest.raises(HttpEndpointError):
        asyncio.run(HttpEndpointFingerprintService(db_path, connector=connector).inspect(
            scope["id"], device["id"], port["id"] + 100,
        ))
    assert connector.calls == []


def test_owned_port_query_connection_is_closed_after_success(private_endpoint, monkeypatch):
    db_path, scope, device, port = private_endpoint
    opened = []

    class TrackedConnection(sqlite3.Connection):
        explicitly_closed = False

        def close(self):
            self.explicitly_closed = True
            return super().close()

    def tracked_connection(path):
        connection = sqlite3.connect(path, factory=TrackedConnection)
        opened.append(connection)
        return connection

    monkeypatch.setattr(http_fingerprint_service, "get_connection", tracked_connection)
    endpoint = HttpEndpointFingerprintService(db_path)._authorized_endpoint(
        scope["id"], device["id"], port["id"],
    )

    assert endpoint["port"] == 8080
    assert len(opened) == 1
    assert opened[0].explicitly_closed
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        opened[0].execute("SELECT 1")


def test_owned_port_query_connection_closes_with_retained_authorization_traceback(
    private_endpoint, monkeypatch,
):
    db_path, scope, device, port = private_endpoint
    opened = []

    class TrackedConnection(sqlite3.Connection):
        explicitly_closed = False

        def close(self):
            self.explicitly_closed = True
            return super().close()

    def tracked_connection(path):
        connection = sqlite3.connect(path, factory=TrackedConnection)
        opened.append(connection)
        return connection

    monkeypatch.setattr(http_fingerprint_service, "get_connection", tracked_connection)
    service = HttpEndpointFingerprintService(db_path)

    with pytest.raises(HttpEndpointError) as captured:
        service._authorized_endpoint(scope["id"], device["id"], port["id"] + 500)

    retained_error = captured.value
    assert "An open, observed TCP port" in str(retained_error)
    assert retained_error.__traceback__ is not None
    assert len(opened) == 1
    assert opened[0].explicitly_closed
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        opened[0].execute("SELECT 1")


def test_oversized_headers_are_stopped_at_the_read_limit(private_endpoint):
    db_path, scope, device, port = private_endpoint
    channel = ScriptedChannel(b"X" * (HTTP_MAX_HEADER_BYTES + 1))
    connector = ScriptedConnector(channel)
    result = asyncio.run(HttpEndpointFingerprintService(db_path, connector=connector).inspect(
        scope["id"], device["id"], port["id"],
    ))
    assert result["outcome"] == "HEADER_LIMIT_EXCEEDED"
    assert len(channel.response) == 1
    assert channel.closed


def test_metadata_cap_and_malformed_response(private_endpoint):
    db_path, scope, device, port = private_endpoint
    fields = b"".join(f"X-{index}: ".encode() + b"a" * 500 + b"\r\n" for index in range(10))
    channel = ScriptedChannel(b"HTTP/1.1 200 OK\r\n" + fields + b"\r\n")
    result = asyncio.run(HttpEndpointFingerprintService(db_path, connector=ScriptedConnector(channel)).inspect(
        scope["id"], device["id"], port["id"],
    ))
    assert result["outcome"] == "RESPONSE_RECEIVED"
    assert len(json.dumps(result).encode()) <= HTTP_MAX_METADATA_BYTES
    bad = ScriptedConnector(ScriptedChannel(b"NOT HTTP\r\n\r\n"))
    malformed = asyncio.run(HttpEndpointFingerprintService(db_path, connector=bad).inspect(
        scope["id"], device["id"], port["id"],
    ))
    assert malformed["outcome"] == "MALFORMED_RESPONSE"


def test_connection_failure_and_timeout_close_channel_and_release_slot(private_endpoint):
    db_path, scope, device, port = private_endpoint
    refused = ScriptedConnector(error=ConnectionRefusedError("offline"))
    result = asyncio.run(HttpEndpointFingerprintService(db_path, connector=refused).inspect(
        scope["id"], device["id"], port["id"],
    ))
    assert result["outcome"] == "CONNECTION_FAILED"
    channel = ScriptedChannel()
    channel.block = asyncio.Event()
    slots = threading.BoundedSemaphore(1)
    service = HttpEndpointFingerprintService(db_path, connector=ScriptedConnector(channel),
                                             operation_slots=slots, total_timeout_seconds=0.5)
    timed = asyncio.run(service.inspect(scope["id"], device["id"], port["id"]))
    assert timed["outcome"] == "TIMEOUT"
    assert channel.closed
    assert slots.acquire(blocking=False)
    slots.release()


def test_cancellation_closes_channel_and_releases_permit(private_endpoint):
    db_path, scope, device, port = private_endpoint

    async def scenario():
        channel = ScriptedChannel()
        channel.block = asyncio.Event()
        slots = threading.BoundedSemaphore(1)
        service = HttpEndpointFingerprintService(db_path, connector=ScriptedConnector(channel), operation_slots=slots)
        task = asyncio.create_task(service.inspect(scope["id"], device["id"], port["id"]))
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert channel.closed
        assert slots.acquire(blocking=False)
        slots.release()

    asyncio.run(scenario())


def test_channel_cleanup_failure_still_releases_permit(private_endpoint):
    db_path, scope, device, port = private_endpoint
    channel = ScriptedChannel()
    channel.close = lambda: (_ for _ in ()).throw(OSError("close failed"))
    slots = threading.BoundedSemaphore(1)
    service = HttpEndpointFingerprintService(
        db_path, connector=ScriptedConnector(channel), operation_slots=slots,
    )
    result = asyncio.run(service.inspect(scope["id"], device["id"], port["id"]))
    assert result["outcome"] == "RESPONSE_RECEIVED"
    assert slots.acquire(blocking=False)
    slots.release()


def test_concurrency_saturation_rejects_without_waiting_and_releases(private_endpoint):
    db_path, scope, device, port = private_endpoint

    async def scenario():
        channel = ScriptedChannel()
        channel.block = asyncio.Event()
        slots = threading.BoundedSemaphore(1)
        connector = ScriptedConnector(channel)
        service = HttpEndpointFingerprintService(db_path, connector=connector, operation_slots=slots)
        first = asyncio.create_task(service.inspect(scope["id"], device["id"], port["id"]))
        await asyncio.sleep(0.02)
        second = await service.inspect(scope["id"], device["id"], port["id"])
        assert second["outcome"] == "CAPACITY_REJECTED"
        assert connector.calls == [("192.168.1.20", 8080)]
        channel.block.set()
        assert (await first)["outcome"] == "RESPONSE_RECEIVED"
        assert slots.acquire(blocking=False)
        slots.release()

    asyncio.run(scenario())


def test_request_contract_and_route_are_local_management_only():
    with pytest.raises(ValidationError):
        HttpFingerprintRequest(scheme="https")
    with pytest.raises(ValidationError):
        HttpFingerprintRequest(scheme="http", url="http://outside.invalid/")
    app = FastAPI()
    register_http_fingerprint_routes(app, lambda: "/tmp/not-opened.db")
    route = next(item for item in app.routes if getattr(item, "path", "").endswith("/fingerprint-http"))
    assert route.methods == {"POST"}
    assert any(dependency.call is local_management for dependency in route.dependant.dependencies)


def _add_observed_port(db_path, device_id, target_ip):
    port = create_port(device_id, 8080, "tcp", "open", "2026-10-01", "2026-10-01", db_path)
    save_port_observation(
        device_id=device_id, port_id=port["id"], ip_address=target_ip,
        port_number=8080, transport="tcp", state="open", observed_at="2026-10-01",
        source="nmap", db_path=db_path,
    )
    return port
