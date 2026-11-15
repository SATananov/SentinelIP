import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import ssl
import subprocess
import time
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


class MemoryTLSChannel:
    def __init__(self):
        self.incoming = asyncio.Queue()
        self.buffer = bytearray()
        self.peer = None
        self.closed = False

    async def sendall(self, data, deadline):
        if self.closed or self.peer.closed:
            raise OSError("TLS fixture channel is closed")
        await self.peer.incoming.put(bytes(data))

    async def recv(self, size, deadline):
        while not self.buffer:
            block = await self.incoming.get()
            if block is None:
                return b""
            self.buffer.extend(block)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def close(self):
        if not self.closed:
            self.closed = True
            self.peer.incoming.put_nowait(None)


class MemoryTLSConnector:
    def __init__(self, certificate, private_key, *, response=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"):
        self.client = MemoryTLSChannel()
        self.server = MemoryTLSChannel()
        self.client.peer = self.server
        self.server.peer = self.client
        self.response = response
        self.calls = []
        self.request = bytearray()
        self.sni = []
        self.server_error = None
        self.server_task = None
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(str(certificate), str(private_key))
        self.server_context.sni_callback = lambda ssl_socket, server_name, context: self.sni.append(server_name)

    async def _flush(self, ssl_object, outgoing, deadline):
        while outgoing.pending:
            await self.server.sendall(outgoing.read(min(outgoing.pending, 16_384)), deadline)

    async def _receive(self, incoming, deadline):
        block = await self.server.recv(16_384, deadline)
        if block:
            incoming.write(block)
        else:
            incoming.write_eof()

    async def _serve(self):
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        ssl_object = self.server_context.wrap_bio(incoming, outgoing, server_side=True)
        deadline = time.monotonic() + 8
        try:
            while True:
                try:
                    ssl_object.do_handshake()
                    await self._flush(ssl_object, outgoing, deadline)
                    break
                except ssl.SSLWantReadError:
                    await self._flush(ssl_object, outgoing, deadline)
                    await self._receive(incoming, deadline)
                except ssl.SSLWantWriteError:
                    await self._flush(ssl_object, outgoing, deadline)
            while b"\r\n\r\n" not in self.request and len(self.request) <= 8192:
                try:
                    self.request.extend(ssl_object.read(1024))
                except ssl.SSLWantReadError:
                    await self._flush(ssl_object, outgoing, deadline)
                    await self._receive(incoming, deadline)
            view = memoryview(self.response)
            while view:
                try:
                    written = ssl_object.write(view)
                    view = view[written:]
                    await self._flush(ssl_object, outgoing, deadline)
                except ssl.SSLWantReadError:
                    await self._flush(ssl_object, outgoing, deadline)
                    await self._receive(incoming, deadline)
                except ssl.SSLWantWriteError:
                    await self._flush(ssl_object, outgoing, deadline)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            self.server_error = exc

    async def connect(self, target_ip, port, deadline):
        self.calls.append((target_ip, port))
        self.server_task = asyncio.create_task(self._serve())
        return self.client

    def close(self):
        self.client.close()
        self.server.close()

    async def finish(self):
        if self.server_task is not None:
            try:
                await asyncio.wait_for(self.server_task, timeout=2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self.server_task.cancel()


class StalledTLSConnector:
    def __init__(self):
        self.client = MemoryTLSChannel()
        self.peer = MemoryTLSChannel()
        self.client.peer = self.peer
        self.peer.peer = self.client
        self.calls = []

    async def connect(self, target_ip, port, deadline):
        self.calls.append((target_ip, port))
        return self.client

    def close(self):
        self.client.close()
        self.peer.close()


class ConnectTimeoutConnector:
    def __init__(self):
        self.started = False

    async def connect(self, target_ip, port, deadline):
        self.started = True
        await asyncio.Event().wait()


class MalformedTLSConnector:
    def __init__(self):
        self.client = MemoryTLSChannel()
        self.server = MemoryTLSChannel()
        self.client.peer = self.server
        self.server.peer = self.client
        self.calls = []

    async def connect(self, target_ip, port, deadline):
        self.calls.append((target_ip, port))
        await self.server.sendall(b"not a TLS record", deadline)
        return self.client


async def _inspect_https(service, scope, device, port, connector):
    try:
        return await service.inspect(scope["id"], device["id"], port["id"], scheme="https")
    finally:
        finish = getattr(connector, "finish", None)
        if finish is not None:
            await finish()
        connector.server.close()


@pytest.fixture(scope="session")
def tls_certificates(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL executable is required for local TLS fixtures.")
    root = tmp_path_factory.mktemp("sentinelip-tls-certs")

    def run(*args):
        subprocess.run([openssl, *map(str, args)], check=True, capture_output=True, timeout=15)

    def make_ca(label):
        key = root / f"{label}-ca.key"
        certificate = root / f"{label}-ca.pem"
        config = root / f"{label}-ca.cnf"
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca_ext\n"
            "[dn]\nCN=SentinelIP Local Test CA\n"
            "[ca_ext]\nbasicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        )
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
            "-out", certificate, "-days", "2", "-sha256", "-config", config,
            "-extensions", "ca_ext")
        return certificate, key

    ca_a, ca_a_key = make_ca("trusted")
    ca_b, ca_b_key = make_ca("untrusted")

    def make_leaf(label, ca, ca_key, *, dns_name="authorized.example.test", days="2"):
        key = root / f"{label}.key"
        csr = root / f"{label}.csr"
        certificate = root / f"{label}.pem"
        ext = root / f"{label}.ext"
        ext.write_text(
            "[server_ext]\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName=DNS:{dns_name},IP:192.168.1.20,IP:8.8.8.8\n"
        )
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
            "-out", csr, "-subj", f"/CN={dns_name}")
        run("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
            "-CAcreateserial", "-out", certificate, "-days", days, "-sha256",
            "-extfile", ext, "-extensions", "server_ext")
        return certificate, key

    valid = make_leaf("valid", ca_a, ca_a_key)
    mismatch = make_leaf("mismatch", ca_a, ca_a_key, dns_name="wrong.example.test")
    expired = make_leaf("expired", ca_a, ca_a_key, days="0")
    untrusted = make_leaf("untrusted-leaf", ca_b, ca_b_key)
    self_key = root / "self-signed.key"
    self_cert = root / "self-signed.pem"
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", self_key,
        "-out", self_cert, "-days", "2", "-sha256", "-subj", "/CN=authorized.example.test",
        "-addext", "subjectAltName=DNS:authorized.example.test,IP:192.168.1.20,IP:8.8.8.8")
    return {
        "ca": ca_a,
        "valid": valid,
        "mismatch": mismatch,
        "expired": expired,
        "untrusted": untrusted,
        "self_signed": (self_cert, self_key),
        "root": root,
    }


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
    assert "tls" not in result
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


def _hostname_endpoint(path):
    initialize_database(path)
    scope = create_hostname_scope(
        canonical_hostname="authorized.example.test", approved_addresses=["8.8.8.8"],
        authorization_confirmed_at="2026-10-01T00:00:00",
        authorization_confirmation_version="hostname_authorization_v1",
        authorization_source="test", resolution_version="hostname-a-resolution-v1", db_path=path,
    )
    device = create_scope_device(
        scope["id"], ip_address="8.8.8.8", first_seen="2026-10-01T00:00:00",
        last_seen="2026-10-01T00:00:00", status="ONLINE", db_path=path,
    )
    port = _add_observed_port(path, device["id"], "8.8.8.8")
    return scope, device, port


def _install_trusted_client_context(monkeypatch, ca_path):
    calls = []

    def create_context(*, purpose):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cafile=str(ca_path))
        calls.append((purpose, context.verify_mode, context.check_hostname))
        return context

    monkeypatch.setattr(http_fingerprint_service.ssl, "create_default_context", create_context)
    return calls


def test_https_verified_hostname_pins_ip_uses_sni_and_returns_bounded_metadata(
    tmp_path, tls_certificates, monkeypatch,
):
    path = tmp_path / "verified-host.db"
    scope, device, port = _hostname_endpoint(path)
    context_calls = _install_trusted_client_context(monkeypatch, tls_certificates["ca"])
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    connector = MemoryTLSConnector(*tls_certificates["valid"])
    service = HttpEndpointFingerprintService(path, resolver=FixedResolver(["8.8.8.8"]), connector=connector)
    result = asyncio.run(_inspect_https(service, scope, device, port, connector))

    assert context_calls == [(ssl.Purpose.SERVER_AUTH, ssl.CERT_REQUIRED, True)]
    assert connector.calls == [("8.8.8.8", 8080)]
    assert connector.client.closed
    assert connector.sni == ["authorized.example.test"]
    assert bytes(connector.request).startswith(b"HEAD / HTTP/1.1\r\n")
    assert b"Host: authorized.example.test:8080\r\n" in connector.request
    assert result["outcome"] == "RESPONSE_RECEIVED"
    assert result["scheme"] == "https"
    assert result["source"] == "https-tls-head-v1"
    tls = result["tls"]
    assert tls["protocol_version"].startswith("TLSv")
    assert tls["cipher"]["name"]
    assert tls["certificate_verification"] == "VERIFIED"
    assert tls["hostname_verification"] == "MATCHED"
    assert tls["ip_address_verification"] is None
    assert tls["verification_name"] == "authorized.example.test"
    assert tls["not_before"] and tls["not_after"]
    assert any(item["type"] == "DNS" for item in tls["subject_alt_names"])
    certificate_der = ssl.PEM_cert_to_DER_cert(tls_certificates["valid"][0].read_text())
    assert tls["sha256_fingerprint"] == hashlib.sha256(certificate_der).hexdigest()
    assert len(json.dumps(result).encode()) <= HTTP_MAX_METADATA_BYTES


def test_https_ip_scope_matches_ip_san_without_sni(private_endpoint, tls_certificates, monkeypatch):
    db_path, scope, device, port = private_endpoint
    _install_trusted_client_context(monkeypatch, tls_certificates["ca"])
    connector = MemoryTLSConnector(*tls_certificates["valid"])
    service = HttpEndpointFingerprintService(db_path, connector=connector)
    result = asyncio.run(_inspect_https(service, scope, device, port, connector))

    assert connector.calls == [("192.168.1.20", 8080)]
    assert connector.client.closed
    assert connector.sni == [None]
    assert b"Host: 192.168.1.20:8080\r\n" in connector.request
    assert result["tls"]["certificate_verification"] == "VERIFIED"
    assert result["tls"]["hostname_verification"] is None
    assert result["tls"]["ip_address_verification"] == "MATCHED"
    assert result["tls"]["verification_name"] == "192.168.1.20"


@pytest.mark.parametrize(
    ("certificate_key", "expected_category"),
    [
        ("expired", "certificate_expired"),
        ("self_signed", "self_signed_certificate"),
        ("untrusted", "untrusted_certificate"),
        ("mismatch", "hostname_mismatch"),
    ],
)
def test_https_certificate_failures_never_send_http_request(
    tmp_path, tls_certificates, monkeypatch, certificate_key, expected_category,
):
    path = tmp_path / f"{certificate_key}.db"
    scope, device, port = _hostname_endpoint(path)
    _install_trusted_client_context(monkeypatch, tls_certificates["ca"])
    connector = MemoryTLSConnector(*tls_certificates[certificate_key])
    service = HttpEndpointFingerprintService(path, resolver=FixedResolver(["8.8.8.8"]), connector=connector)
    result = asyncio.run(_inspect_https(service, scope, device, port, connector))

    assert result["outcome"] == "TLS_VERIFICATION_FAILED"
    assert result["error_category"] == expected_category
    assert result["tls"]["certificate_verification"] == "FAILED"
    assert result["tls"]["sha256_fingerprint"] is None
    assert result["tls"]["subject_alt_names"] == []
    assert bytes(connector.request) == b""
    assert connector.calls == [("8.8.8.8", 8080)]
    assert connector.client.closed
    if expected_category == "hostname_mismatch":
        assert result["tls"]["hostname_verification"] == "FAILED"


def test_https_handshake_timeout_cleans_socket_and_releases_permit(private_endpoint):
    db_path, scope, device, port = private_endpoint
    slots = threading.BoundedSemaphore(1)
    connector = StalledTLSConnector()
    service = HttpEndpointFingerprintService(
        db_path, connector=connector, operation_slots=slots, total_timeout_seconds=0.2,
    )
    async def run_timeout():
        return await service.inspect(scope["id"], device["id"], port["id"], scheme="https")

    result = asyncio.run(run_timeout())
    assert result["outcome"] == "TIMEOUT"
    assert result["tls"]["error_category"] == "handshake_timeout"
    assert connector.client.closed
    assert slots.acquire(blocking=False)
    slots.release()
    connector.close()


def test_https_connect_timeout_is_bounded_and_releases_permit(private_endpoint):
    db_path, scope, device, port = private_endpoint
    slots = threading.BoundedSemaphore(1)
    connector = ConnectTimeoutConnector()
    service = HttpEndpointFingerprintService(
        db_path, connector=connector, operation_slots=slots, total_timeout_seconds=0.5,
    )
    result = asyncio.run(service.inspect(scope["id"], device["id"], port["id"], scheme="https"))
    assert connector.started
    assert result["outcome"] == "TIMEOUT"
    assert result["tls"]["error_category"] == "connection_timeout"
    assert slots.acquire(blocking=False)
    slots.release()


def test_https_handshake_cancellation_cleans_socket_and_releases_permit(private_endpoint):
    db_path, scope, device, port = private_endpoint

    async def scenario():
        connector = StalledTLSConnector()
        slots = threading.BoundedSemaphore(1)
        service = HttpEndpointFingerprintService(db_path, connector=connector, operation_slots=slots)
        task = asyncio.create_task(service.inspect(scope["id"], device["id"], port["id"], scheme="https"))
        for _ in range(50):
            if connector.calls:
                break
            await asyncio.sleep(0.01)
        assert connector.calls == [("192.168.1.20", 8080)]
        second = await service.inspect(scope["id"], device["id"], port["id"], scheme="https")
        assert second["outcome"] == "CAPACITY_REJECTED"
        assert connector.calls == [("192.168.1.20", 8080)]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert connector.client.closed
        assert slots.acquire(blocking=False)
        slots.release()
        connector.close()

    asyncio.run(scenario())


def test_https_redirect_is_metadata_only_and_scope_rejection_precedes_connect(
    private_endpoint, tls_certificates, monkeypatch,
):
    db_path, scope, device, port = private_endpoint
    _install_trusted_client_context(monkeypatch, tls_certificates["ca"])
    connector = MemoryTLSConnector(
        *tls_certificates["valid"],
        response=b"HTTP/1.1 302 Found\r\nLocation: https://next.invalid/path?token=secret\r\n\r\n",
    )
    service = HttpEndpointFingerprintService(db_path, connector=connector)
    result = asyncio.run(_inspect_https(service, scope, device, port, connector))
    assert result["outcome"] == "RESPONSE_RECEIVED"
    assert result["redirect_location"] == "https://next.invalid/path"
    assert connector.calls == [("192.168.1.20", 8080)]
    assert bytes(connector.request).count(b"HEAD ") == 1
    assert "secret" not in json.dumps(result)

    with get_connection(db_path) as connection:
        connection.execute("UPDATE authorized_scopes SET authorized=0 WHERE id=?", (scope["id"],))
    blocked = ScriptedConnector()
    with pytest.raises(HttpEndpointError):
        asyncio.run(HttpEndpointFingerprintService(db_path, connector=blocked).inspect(
            scope["id"], device["id"], port["id"], scheme="https",
        ))
    assert blocked.calls == []


def test_tls_error_categories_cover_malformed_and_unsupported_protocol():
    malformed = ssl.SSLError("[SSL: BAD_CERTIFICATE] malformed certificate")
    unsupported = ssl.SSLError("[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol")
    assert http_fingerprint_service._tls_error_category(malformed) == "malformed_certificate"
    assert http_fingerprint_service._tls_error_category(unsupported) == "unsupported_protocol"


def test_malformed_tls_handshake_never_sends_http_request(private_endpoint):
    db_path, scope, device, port = private_endpoint
    connector = MalformedTLSConnector()
    service = HttpEndpointFingerprintService(db_path, connector=connector)
    result = asyncio.run(_inspect_https(service, scope, device, port, connector))
    assert result["outcome"] == "TLS_HANDSHAKE_FAILED"
    assert result["tls"]["error_category"] == "handshake_failure"
    assert connector.client.closed
    assert connector.calls == [("192.168.1.20", 8080)]


@pytest.mark.parametrize(
    ("handshake_error", "expected_outcome", "expected_category"),
    [
        (ssl.SSLCertVerificationError(1, "malformed certificate"), "TLS_VERIFICATION_FAILED", "malformed_certificate"),
        (ssl.SSLError("[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol"), "TLS_HANDSHAKE_FAILED", "unsupported_protocol"),
    ],
)
def test_malformed_certificate_and_unsupported_protocol_never_send_http(
    private_endpoint, monkeypatch, handshake_error, expected_outcome, expected_category,
):
    db_path, scope, device, port = private_endpoint

    class FailingSSLObject:
        def do_handshake(self):
            raise handshake_error

    class StrictContext:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def wrap_bio(self, *args, **kwargs):
            return FailingSSLObject()

    monkeypatch.setattr(http_fingerprint_service.ssl, "create_default_context", lambda **_: StrictContext())
    channel = ScriptedChannel()
    connector = ScriptedConnector(channel)
    result = asyncio.run(HttpEndpointFingerprintService(
        db_path, connector=connector,
    ).inspect(scope["id"], device["id"], port["id"], scheme="https"))

    assert result["outcome"] == expected_outcome
    assert result["tls"]["error_category"] == expected_category
    assert channel.sent == b""


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
    assert HttpFingerprintRequest(scheme="https").scheme == "https"
    with pytest.raises(ValidationError):
        HttpFingerprintRequest(scheme="ftp")
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
