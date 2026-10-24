from datetime import datetime
import json
import re

import pytest
from fastapi import HTTPException
from fastapi.responses import Response
from starlette.requests import Request

import api.main as api_main
import database.event_exports as event_exports
from api.main import app
from api.remote_sensors import local_management
from database.db import initialize_database, save_event
from database.event_exports import get_bounded_export_events
from services.export_contract import (
    EXPORT_MAX_AGGREGATE_TEXT_BYTES,
    EXPORT_MAX_TEXT_BYTES,
    ExportDataError,
    ExportInputError,
    ExportTooLargeError,
    resolve_export_time_filter,
)


@pytest.fixture
def export_database(tmp_path, monkeypatch):
    db_path = tmp_path / "event-exports.db"
    initialize_database(db_path)
    monkeypatch.setattr(api_main, "DB_PATH", db_path)
    return db_path


def add_event(db_path, timestamp, *, source_ip="192.0.2.1", severity="INFO", message="event"):
    save_event(
        timestamp=timestamp,
        source_ip=source_ip,
        username=None,
        event_type="SSH_PREAUTH",
        severity=severity,
        message=message,
        event_count=1,
        db_path=db_path,
    )


def test_rfc3339_filter_accepts_z_and_numeric_offsets_and_normalizes_local():
    for start, end in (
        ("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"),
        ("2026-10-01T00:00:00+02:00", "2026-10-02T00:00:00+02:00"),
        ("2026-10-01T00:00:00-05:00", "2026-10-02T00:00:00-05:00"),
    ):
        resolved = resolve_export_time_filter(
            time_range=None, from_value=start, until_value=end,
        )
        assert resolved.is_custom
        assert resolved.from_value == start
        assert resolved.until_value == end
        aware_start = datetime.fromisoformat(start.replace("Z", "+00:00"))
        expected_local = aware_start.astimezone().replace(tzinfo=None).isoformat(timespec="seconds")
        assert resolved.since == expected_local
        assert resolved.until is not None


@pytest.mark.parametrize(("start", "end", "preset"), [
    ("2026-10-01T00:00:00", "2026-10-02T00:00:00Z", None),
    ("2026-10-01T00:00:00Z", "2026-10-02T00:00:00", None),
    ("2026-10-01T00:00:00Z", None, None),
    (None, "2026-10-02T00:00:00Z", None),
    ("2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", None),
    ("2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z", None),
    ("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", "all"),
    ("not-a-date", "2026-10-02T00:00:00Z", None),
])
def test_custom_range_rejects_invalid_or_conflicting_bounds(start, end, preset):
    with pytest.raises(ExportInputError):
        resolve_export_time_filter(
            time_range=preset, from_value=start, until_value=end,
        )


def test_custom_range_accepts_31_days_and_rejects_longer():
    exact = resolve_export_time_filter(
        time_range=None,
        from_value="2026-01-01T00:00:00Z",
        until_value="2026-02-01T00:00:00Z",
    )
    assert exact.is_custom

    with pytest.raises(ExportInputError):
        resolve_export_time_filter(
            time_range=None,
            from_value="2026-01-01T00:00:00Z",
            until_value="2026-02-01T00:00:00.0000001Z",
        )


def test_export_query_uses_inclusive_start_exclusive_end_and_id_desc(export_database):
    filters = resolve_export_time_filter(
        time_range=None,
        from_value="2026-01-01T00:00:00Z",
        until_value="2026-01-02T00:00:00Z",
    )
    add_event(export_database, filters.since, message="start is included")
    add_event(export_database, "2026-01-01T12:00:00", message="middle")
    add_event(export_database, filters.until, message="end is excluded")
    events = get_bounded_export_events(
        row_limit=10, since=filters.since, until=filters.until,
        db_path=export_database,
    )

    assert [event["message"] for event in events] == ["middle", "start is included"]
    assert [event["id"] for event in events] == sorted(
        (event["id"] for event in events), reverse=True,
    )


def test_custom_range_route_returns_filters_and_complete_rows(export_database):
    filters = resolve_export_time_filter(
        time_range=None,
        from_value="2026-01-01T00:00:00Z",
        until_value="2026-01-02T00:00:00Z",
    )
    add_event(export_database, filters.since, message="inside start")
    add_event(export_database, filters.until, message="outside end")
    response = _call_export(
        api_main.export_events_json,
        from_=filters.from_value,
        until=filters.until_value,
    )

    payload = json.loads(response.body)
    assert payload["count"] == 1
    assert payload["events"][0]["message"] == "inside start"
    assert payload["filters"]["time_range"] is None
    assert payload["filters"]["from"] == filters.from_value
    assert payload["filters"]["until"] == filters.until_value


def test_export_query_preserves_severity_and_exact_source_ip(export_database):
    add_event(export_database, "2026-01-01T00:00:00", severity="INFO")
    add_event(export_database, "2026-01-01T00:00:01", severity="ALERT")
    add_event(export_database, "2026-01-01T00:00:02", source_ip="192.0.2.10", severity="ALERT")
    events = get_bounded_export_events(
        row_limit=10, severity="ALERT", source_ip="192.0.2.1", db_path=export_database,
    )
    assert len(events) == 1
    assert events[0]["source_ip"] == "192.0.2.1"
    assert events[0]["severity"] == "ALERT"


def test_two_stage_export_query_orders_rows_by_id_desc_not_timestamp(export_database):
    add_event(export_database, "2026-01-01T20:00:00", message="inserted first")
    add_event(export_database, "2026-01-01T05:00:00", message="inserted second")

    events = get_bounded_export_events(row_limit=10, db_path=export_database)

    assert [event["message"] for event in events] == ["inserted second", "inserted first"]
    assert [event["id"] for event in events] == [2, 1]


def test_bounded_query_limit_plus_one_and_empty(export_database):
    assert get_bounded_export_events(row_limit=2, db_path=export_database) == []
    add_event(export_database, "2026-01-01T00:00:00")
    add_event(export_database, "2026-01-01T00:00:01")
    assert len(get_bounded_export_events(row_limit=2, db_path=export_database)) == 2
    add_event(export_database, "2026-01-01T00:00:02")
    with pytest.raises(ExportTooLargeError):
        get_bounded_export_events(row_limit=2, db_path=export_database)


def test_text_and_aggregate_preflight_limits(export_database, monkeypatch):
    exact_value = "x" * EXPORT_MAX_TEXT_BYTES
    add_event(export_database, "2026-01-01T00:00:00", message=exact_value)
    events = get_bounded_export_events(row_limit=1, db_path=export_database)
    assert events[0]["message"] == exact_value

    oversized_db = export_database.parent / "oversized-text.db"
    initialize_database(oversized_db)
    add_event(oversized_db, "2026-01-01T00:00:00", message="x" * (EXPORT_MAX_TEXT_BYTES + 1))
    with pytest.raises(ExportTooLargeError):
        get_bounded_export_events(row_limit=1, db_path=oversized_db)

    multibyte_value = "é" * (EXPORT_MAX_TEXT_BYTES // 2 + 1)
    assert len(multibyte_value) < EXPORT_MAX_TEXT_BYTES
    assert len(multibyte_value.encode("utf-8")) == EXPORT_MAX_TEXT_BYTES + 2
    multibyte_db = export_database.parent / "oversized-multibyte.db"
    initialize_database(multibyte_db)
    add_event(multibyte_db, "2026-01-01T00:00:00", message=multibyte_value)

    def fail_if_export_values_are_fetched(_event):
        raise AssertionError("text byte limits must reject before value retrieval")

    monkeypatch.setattr(event_exports, "_validate_event", fail_if_export_values_are_fetched)
    with pytest.raises(ExportTooLargeError):
        get_bounded_export_events(row_limit=1, db_path=multibyte_db)

    aggregate_db = export_database.parent / "aggregate.db"
    initialize_database(aggregate_db)
    add_event(aggregate_db, "2026-01-01T00:00:00", message="x" * 100)
    with pytest.raises(ExportTooLargeError):
        get_bounded_export_events(
            row_limit=1, aggregate_text_limit=99, db_path=aggregate_db,
        )

    aggregate_multibyte_db = export_database.parent / "aggregate-multibyte.db"
    initialize_database(aggregate_multibyte_db)
    aggregate_message = "é" * 480
    aggregate_character_count = 19 + 9 + 11 + 4 + len(aggregate_message)
    aggregate_byte_count = 19 + 9 + 11 + 4 + len(aggregate_message.encode("utf-8"))
    assert aggregate_character_count < 1_000 < aggregate_byte_count
    add_event(
        aggregate_multibyte_db,
        "2026-01-01T00:00:00",
        message=aggregate_message,
    )

    with pytest.raises(ExportTooLargeError):
        get_bounded_export_events(
            row_limit=1, aggregate_text_limit=1_000, db_path=aggregate_multibyte_db,
        )
    assert EXPORT_MAX_AGGREGATE_TEXT_BYTES == 1024 * 1024


def test_malformed_persisted_timestamp_and_severity_are_rejected(export_database):
    add_event(export_database, "not-a-timestamp")
    with pytest.raises(ExportDataError):
        get_bounded_export_events(row_limit=10, db_path=export_database)
    with pytest.raises(HTTPException) as timestamp_error:
        _call_export(api_main.export_events_json)
    assert timestamp_error.value.status_code == 500
    assert timestamp_error.value.detail == api_main.EXPORT_FAILED_DETAIL

    # The legacy schema has no severity CHECK constraint, so this row can
    # demonstrate safe rejection of a corrupt persisted severity.
    add_event(export_database, "2026-01-01T00:00:00", severity="NOT_A_SEVERITY")
    with pytest.raises(ExportDataError):
        get_bounded_export_events(row_limit=10, db_path=export_database)
    with pytest.raises(HTTPException) as severity_error:
        _call_export(api_main.export_events_json)
    assert severity_error.value.status_code == 500
    assert severity_error.value.detail == api_main.EXPORT_FAILED_DETAIL


def _call_export(route, **kwargs):
    return route(**{
        "severity": None,
        "source_ip": None,
        "time_range": None,
        "from_": None,
        "until": None,
        **kwargs,
    })


@pytest.mark.parametrize(("route_name", "cap_name", "format_name"), [
    ("export_events_json", "JSON_EXPORT_MAX_ROWS", "json"),
    ("export_events_csv", "CSV_EXPORT_MAX_ROWS", "csv"),
    ("export_security_report", "PDF_EXPORT_MAX_ROWS", "pdf"),
])
def test_each_export_format_accepts_cap_and_rejects_cap_plus_one(
    export_database, monkeypatch, route_name, cap_name, format_name,
):
    monkeypatch.setattr(api_main, cap_name, 2)
    route = getattr(api_main, route_name)
    add_event(export_database, "2026-01-01T00:00:00")
    response = _call_export(route)
    if format_name == "json":
        assert json.loads(response.body)["count"] == 1
    else:
        assert response.body

    add_event(export_database, "2026-01-01T00:00:01")
    response = _call_export(route)
    if format_name == "json":
        assert json.loads(response.body)["count"] == 2
    else:
        assert response.body

    add_event(export_database, "2026-01-01T00:00:02")
    with pytest.raises(HTTPException) as error:
        _call_export(route)
    assert error.value.status_code == 413
    assert error.value.detail == api_main.EXPORT_TOO_LARGE_DETAIL
    assert error.value.headers["Cache-Control"] == "no-store"


def test_export_empty_semantics_headers_filenames_and_cache_policy(export_database):
    json_response = _call_export(api_main.export_events_json)
    csv_response = _call_export(api_main.export_events_csv)
    pdf_response = _call_export(api_main.export_security_report)

    json_data = json.loads(json_response.body)
    assert json_data["count"] == 0 and json_data["events"] == []
    assert "content-disposition" not in json_response.headers
    assert json_response.media_type == "application/json"
    assert csv_response.body.decode("utf-8").startswith("id,timestamp,")
    assert csv_response.media_type == "text/csv"
    assert re.search(
        r'filename="sentinelip-events-\d{8}-\d{6}\.csv"',
        csv_response.headers["content-disposition"],
    )
    assert pdf_response.body.startswith(b"%PDF")
    assert pdf_response.media_type == "application/pdf"
    assert re.search(
        r'filename="sentinelip-security-report-\d{8}-\d{6}\.pdf"',
        pdf_response.headers["content-disposition"],
    )

    request = Request({
        "type": "http", "method": "GET", "path": "/export/events.json",
        "headers": [], "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 8000), "scheme": "http",
        "query_string": b"", "http_version": "1.1",
    })
    response = Response()
    local_management(request, response)
    assert response.headers["cache-control"] == "no-store"
    for path in ("/export/events.json", "/export/events.csv", "/export/report.pdf"):
        route = next(route for route in app.routes if getattr(route, "path", None) == path)
        assert any(
            dependency.call is local_management
            for dependency in route.dependant.dependencies
        )


def test_source_ip_utf8_byte_bound_and_safe_validation(export_database):
    accepted = "é" * 127 + "a"  # 255 UTF-8 bytes
    api_main._bounded_export_rows(
        severity=None, source_ip=accepted, time_range="all",
        from_value=None, until_value=None, row_limit=1,
    )
    with pytest.raises(HTTPException) as error:
        api_main._bounded_export_rows(
            severity=None, source_ip=accepted + "a", time_range="all",
            from_value=None, until_value=None, row_limit=1,
        )
    assert error.value.status_code == 422
    assert error.value.detail == api_main.EXPORT_INVALID_FILTER_DETAIL


def test_invalid_custom_range_errors_are_fixed_safe_422(export_database):
    with pytest.raises(HTTPException) as error:
        _call_export(
            api_main.export_events_json,
            from_="2026-01-01T00:00:00",
            until="2026-01-02T00:00:00Z",
        )
    assert error.value.status_code == 422
    assert error.value.detail == api_main.EXPORT_INVALID_FILTER_DETAIL


def test_aggregate_budget_rejects_before_pdf_builder(export_database, monkeypatch):
    add_event(export_database, "2026-01-01T00:00:00", message="x" * 100)
    monkeypatch.setattr(api_main, "EXPORT_MAX_AGGREGATE_TEXT_BYTES", 99)

    def should_not_render(**_kwargs):
        raise AssertionError("rendering must not start before aggregate preflight")

    monkeypatch.setattr(api_main, "build_security_report", should_not_render)
    with pytest.raises(HTTPException) as error:
        _call_export(api_main.export_security_report)
    assert error.value.status_code == 413


@pytest.mark.parametrize("preset", ["all", "24h"])
def test_preset_and_custom_filter_conflicts_are_fixed_422(export_database, preset):
    with pytest.raises(HTTPException) as error:
        _call_export(
            api_main.export_events_csv,
            time_range=preset,
            from_="2026-01-01T00:00:00Z",
            until="2026-01-02T00:00:00Z",
        )
    assert error.value.status_code == 422
    assert error.value.detail == api_main.EXPORT_INVALID_FILTER_DETAIL


@pytest.mark.parametrize("filters", [
    {"time_range": "7d"},
    {"severity": "CRITICAL"},
    {"source_ip": "x" * 256},
])
def test_invalid_export_filters_are_fixed_safe_422(export_database, filters):
    with pytest.raises(HTTPException) as error:
        _call_export(api_main.export_events_json, **filters)
    assert error.value.status_code == 422
    assert error.value.detail == api_main.EXPORT_INVALID_FILTER_DETAIL


def test_exact_final_json_byte_limit_and_oversize_reject(export_database, monkeypatch):
    response = _call_export(api_main.export_events_json)
    exact_size = len(response.body)
    monkeypatch.setattr(api_main, "JSON_EXPORT_MAX_BYTES", exact_size + 1)
    assert len(_call_export(api_main.export_events_json).body) == exact_size
    monkeypatch.setattr(api_main, "JSON_EXPORT_MAX_BYTES", exact_size)
    assert len(_call_export(api_main.export_events_json).body) == exact_size
    monkeypatch.setattr(api_main, "JSON_EXPORT_MAX_BYTES", exact_size - 1)
    with pytest.raises(HTTPException) as error:
        _call_export(api_main.export_events_json)
    assert error.value.status_code == 413


def test_exact_csv_and_pdf_final_byte_limits(export_database, monkeypatch):
    csv_response = _call_export(api_main.export_events_csv)
    csv_size = len(csv_response.body)
    monkeypatch.setattr(api_main, "CSV_EXPORT_MAX_BYTES", csv_size + 1)
    assert len(_call_export(api_main.export_events_csv).body) == csv_size
    monkeypatch.setattr(api_main, "CSV_EXPORT_MAX_BYTES", csv_size)
    assert len(_call_export(api_main.export_events_csv).body) == csv_size
    monkeypatch.setattr(api_main, "CSV_EXPORT_MAX_BYTES", csv_size - 1)
    with pytest.raises(HTTPException) as csv_error:
        _call_export(api_main.export_events_csv)
    assert csv_error.value.status_code == 413

    monkeypatch.setattr(api_main, "build_security_report", lambda **_kwargs: b"%PDF-1.4 fixed")
    monkeypatch.setattr(api_main, "PDF_EXPORT_MAX_BYTES", len(b"%PDF-1.4 fixed") + 1)
    assert _call_export(api_main.export_security_report).body == b"%PDF-1.4 fixed"
    monkeypatch.setattr(api_main, "PDF_EXPORT_MAX_BYTES", len(b"%PDF-1.4 fixed"))
    assert _call_export(api_main.export_security_report).body == b"%PDF-1.4 fixed"
    monkeypatch.setattr(api_main, "PDF_EXPORT_MAX_BYTES", len(b"%PDF-1.4 fixed") - 1)
    with pytest.raises(HTTPException) as pdf_error:
        _call_export(api_main.export_security_report)
    assert pdf_error.value.status_code == 413


def test_invalid_blob_field_and_invalid_numeric_are_safe_500(export_database):
    import sqlite3

    add_event(export_database, "2026-01-01T00:00:00")
    with sqlite3.connect(export_database) as connection:
        connection.execute("UPDATE events SET message = CAST(X'80' AS BLOB)")
    with pytest.raises(HTTPException) as blob_error:
        _call_export(api_main.export_events_json)
    assert blob_error.value.status_code == 500
    assert blob_error.value.detail == api_main.EXPORT_FAILED_DETAIL

    with sqlite3.connect(export_database) as connection:
        connection.execute("UPDATE events SET message = 'ok', event_count = -1")
    with pytest.raises(HTTPException) as numeric_error:
        _call_export(api_main.export_events_json)
    assert numeric_error.value.status_code == 500
    assert numeric_error.value.detail == api_main.EXPORT_FAILED_DETAIL


@pytest.mark.parametrize("route_name", [
    "export_events_json", "export_events_csv",
])
def test_invalid_unicode_export_rendering_is_fixed_safe_500(monkeypatch, route_name):
    malformed = {
        "id": 1,
        "timestamp": "2026-01-01T00:00:00",
        "source_ip": "192.0.2.1",
        "username": None,
        "event_type": "SSH_PREAUTH",
        "severity": "INFO",
        "message": "bad surrogate: \ud800",
        "event_count": 1,
    }
    monkeypatch.setattr(api_main, "get_bounded_export_events", lambda **_kwargs: [malformed])
    with pytest.raises(HTTPException) as error:
        _call_export(getattr(api_main, route_name))
    assert error.value.status_code == 500
    assert error.value.detail == api_main.EXPORT_FAILED_DETAIL


def test_unexpected_pdf_renderer_failure_is_fixed_safe_500(monkeypatch):
    monkeypatch.setattr(api_main, "get_bounded_export_events", lambda **_kwargs: [])

    def fail_render(**_kwargs):
        raise RuntimeError("private renderer detail")

    monkeypatch.setattr(api_main, "build_security_report", fail_render)
    with pytest.raises(HTTPException) as error:
        _call_export(api_main.export_security_report)
    assert error.value.status_code == 500
    assert error.value.detail == api_main.EXPORT_FAILED_DETAIL
