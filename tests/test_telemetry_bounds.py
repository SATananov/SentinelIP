import asyncio
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from pydantic import ValidationError

from api.main import (
    _telemetry_error,
    _telemetry_internal_error,
    telemetry_safe_parse_error,
    telemetry_safe_validation_error,
)
from api.schemas import DnsTelemetryCreate, WebTelemetryCreate
from api.sensor_enrollment import SensorBodyLimitMiddleware
from database.telemetry import (
    list_dns_observations,
    list_web_observations,
    provision_sensor,
)
from database.db import get_connection
from services.telemetry_ingestion import TelemetryIngestionError, ingest_dns, ingest_web
from services.telemetry_models import (
    DnsObservation,
    PrivacyMode,
    TelemetryModelError,
    WebObservation,
    _validate_metadata,
    normalize_url,
    validate_utf8_text,
)


OBSERVED_AT = datetime.now(timezone.utc) - timedelta(minutes=1)


def web_payload(event_id="web-bounds"):
    return {
        "external_event_id": event_id,
        "observed_at": OBSERVED_AT,
        "event_type": "NAVIGATION",
        "url": "https://example.test/path",
    }


def dns_payload(event_id="dns-bounds"):
    return {
        "external_event_id": event_id,
        "observed_at": OBSERVED_AT,
        "queried_domain": "example.test",
        "query_type": "A",
        "response_status": "NOERROR",
    }


def test_web_text_limits_measure_utf8_bytes():
    assert WebTelemetryCreate.model_validate({**web_payload("é" * 64), "event_type": "N" * 32})
    assert WebTelemetryCreate.model_validate(web_payload("a" * 128))
    with pytest.raises(ValidationError):
        WebTelemetryCreate.model_validate(web_payload("é" * 65))
    with pytest.raises(ValidationError):
        WebTelemetryCreate.model_validate({**web_payload(), "event_type": "N" * 33})
    with pytest.raises(ValidationError):
        WebTelemetryCreate.model_validate({**web_payload(), "url": "https://example.test/" + "x" * 32_768})


def test_standard_url_at_browser_client_byte_boundary():
    prefix = "https://example.test"
    boundary_url = prefix + "/" + "x" * (32_768 - len(prefix) - 1)
    assert len(boundary_url.encode("utf-8")) == 32_768
    assert WebTelemetryCreate.model_validate({**web_payload(), "url": boundary_url})


def test_field_byte_validator_rejects_multibyte_overflow():
    # Character count is below 128, but UTF-8 byte count is above it.
    payload = web_payload("é" * 65)
    with pytest.raises(ValidationError):
        WebTelemetryCreate.model_validate(payload)


def test_invalid_unicode_is_rejected_without_echoing_value():
    with pytest.raises(ValidationError):
        WebTelemetryCreate.model_validate(web_payload("\ud800"))
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"value": "\udfff"})


def test_pathological_metadata_depth_is_rejected_before_json_serialization(monkeypatch):
    import services.telemetry_models as telemetry_models

    nested = "leaf"
    for _ in range(10_000):
        nested = {"child": nested}

    def serialization_must_not_run(*args, **kwargs):
        raise AssertionError("serialization ran before the structural depth check")

    monkeypatch.setattr(telemetry_models.json, "dumps", serialization_must_not_run)
    with pytest.raises(TelemetryModelError, match="nested too deeply"):
        _validate_metadata(nested)


def test_deep_raw_json_under_body_cap_reaches_bounded_metadata_validator():
    prefix = (
        b'{"external_event_id":"deep","observed_at":"2026-10-24T00:00:00Z",'
        b'"queried_domain":"example.test","query_type":"A",'
        b'"response_status":"NOERROR","metadata":'
    )
    raw_body = prefix + b'{"x":' * 2_000 + b"0" + b"}" * 2_000 + b"}"
    assert len(raw_body) < 16_384
    parsed = json.loads(raw_body)
    with pytest.raises(ValidationError, match="nested too deeply"):
        DnsTelemetryCreate.model_validate(parsed)
    # FastAPI converts an exception from JSON parsing to HTTP 400; the route-scoped
    # handler maps parser failures to the telemetry contract's fixed 422 response.
    request = Request({
        "type": "http", "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/telemetry/dns", "raw_path": b"/telemetry/dns", "query_string": b"",
        "headers": [], "server": ("localhost", 80), "client": ("127.0.0.1", 1234), "root_path": "",
    })
    response = asyncio.run(telemetry_safe_parse_error(
        request,
        HTTPException(status_code=400, detail="There was an error parsing the body"),
    ))
    assert response.status_code == 422
    assert response.body == b'{"detail":"Invalid telemetry request."}'


def test_telemetry_api_error_helpers_use_fixed_safe_details():
    scope = {
        "type": "http", "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/telemetry/web", "raw_path": b"/telemetry/web", "query_string": b"",
        "headers": [], "server": ("localhost", 80), "client": ("127.0.0.1", 1234), "root_path": "",
    }
    request = Request(scope)
    response = asyncio.run(telemetry_safe_validation_error(
        request,
        RequestValidationError([], body={"password": "private-value"}),
    ))
    assert response.status_code == 422
    assert response.body == b'{"detail":"Invalid telemetry request."}'
    parser_error = asyncio.run(telemetry_safe_parse_error(
        request,
        HTTPException(status_code=400, detail="There was an error parsing the body"),
    ))
    assert parser_error.status_code == 422
    assert parser_error.body == b'{"detail":"Invalid telemetry request."}'
    unrelated_request = Request({**scope, "path": "/other", "raw_path": b"/other"})
    unrelated_validation = RequestValidationError(
        [{"type": "missing", "loc": ("body", "field"), "msg": "Field required", "input": None}],
        body={"field": None},
    )
    scoped_validation = asyncio.run(telemetry_safe_validation_error(unrelated_request, unrelated_validation))
    default_validation = asyncio.run(request_validation_exception_handler(unrelated_request, unrelated_validation))
    assert (scoped_validation.status_code, scoped_validation.body) == (default_validation.status_code, default_validation.body)
    unrelated_http_error = HTTPException(status_code=400, detail="Existing route error")
    scoped_http = asyncio.run(telemetry_safe_parse_error(unrelated_request, unrelated_http_error))
    default_http = asyncio.run(http_exception_handler(unrelated_request, unrelated_http_error))
    assert (scoped_http.status_code, scoped_http.body) == (default_http.status_code, default_http.body)
    with pytest.raises(HTTPException) as invalid:
        _telemetry_error(TelemetryIngestionError("private-value", 422))
    assert invalid.value.status_code == 422
    assert invalid.value.detail == "Invalid telemetry request."
    with pytest.raises(HTTPException) as internal:
        _telemetry_internal_error(RuntimeError("private SQL details"))
    assert internal.value.status_code == 500
    assert internal.value.detail == "Telemetry ingestion failed."


def test_dns_byte_fields_and_cardinality():
    assert DnsTelemetryCreate.model_validate({**dns_payload(), "ttl": True}).ttl == 1
    with pytest.raises(ValidationError):
        DnsTelemetryCreate.model_validate({**dns_payload(), "resolved_addresses": ["1.1.1.1"] * 257})


def test_legacy_telemetry_enum_timestamp_privacy_and_ip_semantics():
    at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    payload = WebTelemetryCreate.model_validate({
        "external_event_id": "legacy-valid",
        "observed_at": at,
        "event_type": "NAVIGATION",
        "url": "https://EXAMPLE.TEST/private/path?token=ignored",
        "has_login_form": "yes",
    })
    assert payload.event_type == "NAVIGATION"
    assert payload.has_login_form is True
    assert payload.observed_at == datetime.fromisoformat(at)
    web = WebObservation(
        external_event_id=payload.external_event_id,
        sensor_id="1",
        observed_at=payload.observed_at,
        event_type=payload.event_type,
        url=payload.url,
        privacy_mode=PrivacyMode.STANDARD,
        has_login_form=payload.has_login_form,
    )
    assert normalize_url(web.url, web.privacy_mode) == ("https", "example.test", "/private/path")
    dns = DnsTelemetryCreate.model_validate({
        **dns_payload(),
        "query_type": "A",
        "response_status": "NOERROR",
        "resolved_addresses": ["2001:0db8::1"],
        "resolver": "127.0.0.53",
    })
    normalized_dns = DnsObservation(
        external_event_id=dns.external_event_id,
        sensor_id="2",
        observed_at=dns.observed_at,
        queried_domain=dns.queried_domain,
        query_type=dns.query_type,
        response_status=dns.response_status,
        resolved_addresses=tuple(dns.resolved_addresses),
        resolver=dns.resolver,
        ttl=dns.ttl,
    )
    assert normalized_dns.resolved_addresses == ("2001:db8::1",)
    assert normalized_dns.resolver == "127.0.0.53"


def test_dns_producer_sized_payload_fits_endpoint_body_cap():
    domain = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
    addresses = [f"2001:db80:1000:2000:3000:4000:5000:{index:04x}" for index in range(1, 257)]
    payload = DnsTelemetryCreate.model_validate({
        **dns_payload(),
        "queried_domain": domain,
        "resolved_addresses": addresses,
        "resolver": "2001:db8::53",
        "ttl": 2_147_483_647,
        "metadata": {"source": "fixture-jsonl"},
    })
    assert len(payload.queried_domain.encode("ascii")) == 253
    encoded = json.dumps(payload.model_dump(mode="json"), separators=(",", ":")).encode("utf-8")
    assert len(encoded) <= 16_384


def test_metadata_bounds_and_supported_json_values():
    assert _validate_metadata(None) is None
    assert _validate_metadata({}) == {}
    assert _validate_metadata({"null": None, "bool": True, "number": 1.25, "nested": [{"ok": "✓"}]})
    assert _validate_metadata({"a": {"b": {"c": {"d": "depth-four"}}}})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"a": {"b": {"c": {"d": {"e": 1}}}}})
    assert _validate_metadata({str(i): i for i in range(64)})
    assert _validate_metadata({"k" * 64: 1})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({str(i): i for i in range(65)})
    assert _validate_metadata({"items": list(range(256))})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"items": list(range(257))})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"x" * 65: 1})
    assert _validate_metadata({"x": "a" * 4096})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"x": "a" * 4097})
    assert validate_utf8_text("é" * 2048, "value", 4096) == "é" * 2048
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"x": "é" * 2049})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"x": float("nan")})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"password": "hidden"})
    with pytest.raises(TelemetryModelError, match="nested too deeply"):
        _validate_metadata({"password": "hidden", "child": {"a": {"b": {"c": {"d": 1}}}}})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"bad": (1, 2)})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({1: "bad-key"})


def test_metadata_node_and_serialized_byte_bounds():
    # Root + 1023 scalar children is the exact node boundary.
    assert _validate_metadata({"x": [None] * 256, "y": [None] * 256, "z": [None] * 256, "w": [None] * 251})
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"x": [None] * 256, "y": [None] * 256, "z": [None] * 256, "w": [None] * 252})
    at_limit = {"a": "x" * 4096, "b": "y" * 4081}
    assert len(json.dumps(at_limit, sort_keys=True, separators=(",", ":")).encode()) == 8192
    assert _validate_metadata(at_limit)
    over_limit = {"a": "x" * 4096, "b": "y" * 4082}
    with pytest.raises(TelemetryModelError):
        _validate_metadata(over_limit)
    # The stored JSON escapes non-ASCII characters exactly as the persistence helper does.
    multi_byte = {"x": "é" * 1364}
    assert len(json.dumps(multi_byte, sort_keys=True, separators=(",", ":")).encode()) == 8192
    assert _validate_metadata(multi_byte)
    # Per-string UTF-8 bytes fit, while JSON escaping makes the storage form too large.
    with pytest.raises(TelemetryModelError):
        _validate_metadata({"x": "é" * 1365})


@pytest.mark.parametrize("kind", ["web", "dns"])
def test_atomic_concurrent_duplicate_is_first_write_wins_and_touches_liveness(tmp_path, monkeypatch, kind):
    import services.telemetry_ingestion as ingestion

    db_path = tmp_path / f"{kind}.db"
    sensor_type = "BROWSER" if kind == "web" else "DNS"
    sensor, token = provision_sensor(kind, kind, sensor_type, None, "STANDARD", 30, db_path)
    payload = web_payload() if kind == "web" else dns_payload()
    ingest = ingest_web if kind == "web" else ingest_dns
    barrier = threading.Barrier(2)
    authenticate = ingestion._authenticate

    def synchronized_auth(*args, **kwargs):
        result = authenticate(*args, **kwargs)
        barrier.wait(timeout=5)
        return result

    monkeypatch.setattr(ingestion, "_authenticate", synchronized_auth)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: ingest(sensor["id"], token, payload, db_path), range(2)))
    monkeypatch.setattr(ingestion, "_authenticate", authenticate)

    assert sorted(result["idempotent"] for result in results) == [False, True]
    rows = list_web_observations(sensor["id"], db_path) if kind == "web" else list_dns_observations(sensor["id"], db_path)
    assert len(rows) == 1
    first_id = rows[0]["id"]
    with get_connection(db_path) as connection:
        connection.execute("UPDATE telemetry_sensors SET last_seen_at='2000-01-01T00:00:00+00:00' WHERE id=?", (sensor["id"],))
    changed_payload = {**payload, "url": "https://changed.example/path"} if kind == "web" else {**payload, "queried_domain": "changed.example"}
    duplicate = ingest(sensor["id"], token, changed_payload, db_path)
    assert duplicate["idempotent"] is True
    assert duplicate["id"] == first_id
    rows_after = list_web_observations(sensor["id"], db_path) if kind == "web" else list_dns_observations(sensor["id"], db_path)
    assert len(rows_after) == 1
    assert rows_after[0]["queried_domain" if kind == "dns" else "hostname"] == ("example.test" if kind == "dns" else "example.test")
    with get_connection(db_path) as connection:
        last_seen = connection.execute("SELECT last_seen_at FROM telemetry_sensors WHERE id=?", (sensor["id"],)).fetchone()[0]
    assert last_seen != "2000-01-01T00:00:00+00:00"
    with pytest.raises(TelemetryIngestionError):
        invalid = {**payload, "external_event_id": "rejected-event", "metadata": {"password": "secret"}}
        ingest(sensor["id"], token, invalid, db_path)
    with get_connection(db_path) as connection:
        assert connection.execute("SELECT last_seen_at FROM telemetry_sensors WHERE id=?", (sensor["id"],)).fetchone()[0] == last_seen
    assert len(rows_after) == 1
    assert last_seen


@pytest.mark.parametrize("kind", ["web", "dns"])
def test_atomic_ingestion_rolls_back_insert_when_liveness_update_fails(tmp_path, kind):
    db_path = tmp_path / f"rollback-{kind}.db"
    sensor_type = "BROWSER" if kind == "web" else "DNS"
    sensor, token = provision_sensor(kind, kind, sensor_type, None, "STANDARD", 30, db_path)
    with get_connection(db_path) as connection:
        connection.execute(
            """CREATE TRIGGER fail_telemetry_liveness_update
               BEFORE UPDATE OF last_seen_at ON telemetry_sensors
               BEGIN SELECT RAISE(ABORT, 'injected failure'); END"""
        )
    ingest = ingest_web if kind == "web" else ingest_dns
    payload = web_payload("rollback") if kind == "web" else dns_payload("rollback")
    with pytest.raises(sqlite3.IntegrityError):
        ingest(sensor["id"], token, payload, db_path)
    rows = list_web_observations(sensor["id"], db_path) if kind == "web" else list_dns_observations(sensor["id"], db_path)
    assert rows == []
    with get_connection(db_path) as connection:
        assert connection.execute(
            "SELECT last_seen_at FROM telemetry_sensors WHERE id=?", (sensor["id"],)
        ).fetchone()[0] is None


def test_body_limit_middleware_counts_unknown_length_and_rejects_before_app():
    async def run(path, messages, headers=()):
        called = False
        received = 0
        sent = []

        async def app(scope, receive, send):
            nonlocal called
            called = True

        async def receive():
            nonlocal received
            message = messages[received]
            received += 1
            return message

        async def send(message):
            sent.append(message)

        middleware = SensorBodyLimitMiddleware(app)
        await middleware({"type": "http", "path": path, "headers": list(headers)}, receive, send)
        return called, received, sent

    cap = 16_384
    request = {"type": "http.request", "body": b"x" * (cap + 1), "more_body": True}
    called, received, sent = asyncio.run(run("/telemetry/dns", [request]))
    assert not called
    assert received == 1
    assert sent[0]["status"] == 413
    assert sent[1]["body"] == b'{"detail": "Telemetry request exceeds the allowed size."}'
    assert b"x" * 32 not in sent[1]["body"]

    called, received, sent = asyncio.run(run("/sensor/test", [request]))
    assert not called and sent[0]["status"] == 413
    assert sent[1]["body"] == b'{"detail": "Sensor request body exceeds 16384 bytes."}'
    called, _, _ = asyncio.run(run("/telemetry/dns-extra", [request]))
    assert called
    cumulative = [
        {"type": "http.request", "body": b"x" * cap, "more_body": True},
        {"type": "http.request", "body": b"x", "more_body": True},
        {"type": "http.request", "body": b"unread", "more_body": False},
    ]
    called, received, sent = asyncio.run(run("/telemetry/dns", cumulative))
    assert not called and received == 2 and sent[0]["status"] == 413


def test_body_limit_content_length_and_exact_cap():
    async def run(path, content_length, body=b"", more_body=False):
        called = False
        receive_calls = 0
        sent = []

        async def app(scope, receive, send):
            nonlocal called
            called = True

        async def receive():
            nonlocal receive_calls
            receive_calls += 1
            return {"type": "http.request", "body": body, "more_body": more_body}

        async def send(message):
            sent.append(message)

        headers = [(b"content-length", str(content_length).encode())] if content_length is not None else []
        middleware = SensorBodyLimitMiddleware(app)
        await middleware({"type": "http", "path": path, "headers": headers}, receive, send)
        return called, receive_calls, sent

    called, received, sent = asyncio.run(run("/telemetry/dns", 16_385))
    assert not called and received == 0 and sent[0]["status"] == 413
    called, _, _ = asyncio.run(run("/telemetry/dns", 16_384, b"x" * 16_384))
    assert called
    called, received, sent = asyncio.run(run("/telemetry/web", 65_537))
    assert not called and received == 0 and sent[0]["status"] == 413
    called, _, _ = asyncio.run(run("/telemetry/web", 65_536, b"x" * 65_536))
    assert called


def test_body_middleware_replays_chunks_and_more_body_unchanged():
    messages = [
        {"type": "http.request", "body": b"first", "more_body": True},
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": b"last", "more_body": True},
        {"type": "http.request", "body": b"", "more_body": False},
    ]
    observed = []

    async def app(scope, receive, send):
        while True:
            message = await receive()
            observed.append(message)
            if not message.get("more_body", False):
                break

    async def receive():
        return messages.pop(0)

    async def send(message):
        pass

    asyncio.run(SensorBodyLimitMiddleware(app)(
        {"type": "http", "path": "/telemetry/dns", "headers": []}, receive, send,
    ))
    assert observed == [
        {"type": "http.request", "body": b"first", "more_body": True},
        {"type": "http.request", "body": b"", "more_body": True},
        {"type": "http.request", "body": b"last", "more_body": True},
        {"type": "http.request", "body": b"", "more_body": False},
    ]

