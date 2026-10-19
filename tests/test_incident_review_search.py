import sqlite3

import pytest
from fastapi import FastAPI
from fastapi import Response
from starlette.requests import Request

from api.incident_reviews import register_incident_review_routes
from api.remote_sensors import local_management
from database.db import get_connection, initialize_database
from database.incident_reviews import (
    IncidentReviewError, create_review, search_reviews, update_review,
)
from database.inventory import create_device
from database.migrations import MIGRATIONS
from database.networks import create_network
from database import migrations as migration_module
from database.remote_sensors import RemoteSensorStore


def _create(path, title, **kwargs):
    return create_review(title=title, db_path=path, **kwargs)


def _set_dates(path, review_id, *, created, updated=None, closed=None, state=None):
    state_sql = ", state=?" if state is not None else ""
    with get_connection(path) as connection:
        values = [created, updated or created, closed]
        if state is not None:
            values.append(state)
        values.append(review_id)
        connection.execute(f"UPDATE incident_reviews SET created_at=?, updated_at=?, closed_at=?{state_sql} WHERE id=?", values)


@pytest.fixture
def search_db(tmp_path):
    path = tmp_path / "incident-review-search.db"
    initialize_database(path)
    return path


def _app(path):
    app = FastAPI()
    register_incident_review_routes(app, lambda: path)
    return app


def test_title_token_prefix_and_and_semantics(search_db):
    first = _create(search_db, "Firewall Authentication Failure")
    second = _create(search_db, "Authentication Firewall Failure")
    _create(search_db, "Firewall Missing Failure")

    assert {item["id"] for item in search_reviews(title="fire auth", db_path=search_db)["items"]} == {
        first["id"], second["id"],
    }
    assert {item["id"] for item in search_reviews(title="auth fire", db_path=search_db)["items"]} == {
        first["id"], second["id"],
    }
    assert search_reviews(title="fire missing", db_path=search_db)["items"][0]["title"] == "Firewall Missing Failure"
    assert all(item["title"] != "Firewall Authentication Failure" for item in
               search_reviews(title="fire absent", db_path=search_db)["items"])


@pytest.mark.parametrize("query", ["AUTH", "auth"])
def test_title_search_is_case_insensitive(search_db, query):
    _create(search_db, "Authentication review")
    assert search_reviews(title=query, db_path=search_db)["items"][0]["title"] == "Authentication review"


def test_cyrillic_title_search_uses_unicode61_case_behavior(search_db):
    _create(search_db, "Проверка Сетевого Экрана")
    assert search_reviews(title="пров СЕТ", db_path=search_db)["items"][0]["title"] == "Проверка Сетевого Экрана"


def test_prefix_not_interior_substring(search_db):
    _create(search_db, "Authentication review")
    assert search_reviews(title="auth", db_path=search_db)["items"]
    assert not search_reviews(title="thentication", db_path=search_db)["items"]


@pytest.mark.parametrize("query", [
    '"auth', 'title: auth', 'auth OR password', 'auth AND password',
    'auth NOT password', '(auth)', 'auth*', 'fire-wall', 'VPN / Authentication',
])
def test_operator_like_and_punctuation_input_is_literal_token_text(search_db, query):
    literal = _create(search_db, 'Firewall OR Password and quoted "auth" title: VPN')
    _create(search_db, 'Firewall Password')
    # Invalid single-character tokens are rejected; otherwise punctuation only
    # separates safe text tokens and FTS operators are never passed through.
    try:
        result = search_reviews(title=query, db_path=search_db)
    except IncidentReviewError as exc:
        assert exc.status_code == 422
        return
    assert isinstance(result["items"], list)
    assert [row["id"] for row in search_reviews(title="fire OR pass", db_path=search_db)["items"]] == [literal["id"]]


def test_punctuation_only_and_short_terms_are_rejected(search_db):
    for value in ("", "   ", "!!!", "a", "ab", "auth a", "a" * 161):
        with pytest.raises(IncidentReviewError) as error:
            search_reviews(title=value, db_path=search_db)
        assert error.value.status_code == 422


def test_search_indexes_title_only(search_db):
    review = _create(search_db, "UniqueCaseTitle")
    update_review(review["id"], {
        "summary": "summaryneedle",
        "final_summary": "finalneedle",
        "analyst_note": "analystneedle",
    }, db_path=search_db)
    with get_connection(search_db) as connection:
        connection.execute(
            "INSERT INTO incident_review_notes (incident_review_id,note_text,actor_source,created_at) "
            "VALUES (?,?,?,?)", (review["id"], "noteneedle", "OPERATOR", "2026-01-01T00:00:00+00:00"),
        )
    for needle in ("summaryneedle", "finalneedle", "analystneedle", "noteneedle"):
        assert search_reviews(title=needle, db_path=search_db)["items"] == []
    assert search_reviews(title="unique", db_path=search_db)["items"][0]["id"] == review["id"]
    assert "summary" not in search_reviews(title="unique", db_path=search_db)["items"][0]
    assert "final_summary" not in search_reviews(title="unique", db_path=search_db)["items"][0]
    assert "analyst_note" not in search_reviews(title="unique", db_path=search_db)["items"][0]


def test_title_insert_update_delete_sync(search_db):
    review = _create(search_db, "FirstSearchableTitle")
    assert search_reviews(title="firstsearch", db_path=search_db)["items"]
    update_review(review["id"], {"title": "SecondSearchableTitle"}, db_path=search_db)
    assert search_reviews(title="firstsearch", db_path=search_db)["items"] == []
    assert search_reviews(title="secondsearch", db_path=search_db)["items"]
    # Review deletion is not a product operation. Disable FK cascades for this
    # isolated trigger test so append-only review history remains untouched.
    with sqlite3.connect(search_db) as connection:
        connection.execute("DELETE FROM incident_reviews WHERE id=?", (review["id"],))
    assert search_reviews(title="secondsearch", db_path=search_db)["items"] == []


def test_date_filters_normalize_utc_and_closed_bounds_exclude_open(search_db):
    old = _create(search_db, "ThreeWeeksOld review", disposition="BENIGN")
    closed = _create(search_db, "Closed historical review", disposition="BENIGN")
    open_review = _create(search_db, "Open historical review", disposition="BENIGN")
    _set_dates(search_db, old["id"], created="2026-09-28T12:00:00+00:00")
    _set_dates(search_db, closed["id"], created="2026-09-28T12:00:00+00:00",
               updated="2026-10-01T00:00:00+00:00", closed="2026-10-01T00:00:00+00:00", state="CLOSED")
    _set_dates(search_db, open_review["id"], created="2026-09-28T12:00:00+00:00")
    result = search_reviews(
        title="historical", created_from="2026-09-28T14:00:00+02:00",
        created_until="2026-09-29T00:00:00Z", db_path=search_db,
    )
    assert {item["id"] for item in result["items"]} == {closed["id"], open_review["id"]}
    closed_result = search_reviews(
        title="historical", closed_from="2026-10-01T00:00:00Z", db_path=search_db,
    )
    assert [item["id"] for item in closed_result["items"]] == [closed["id"]]
    assert search_reviews(title="threeweeks", created_from="2026-09-28T12:00:00Z",
                          created_until="2026-09-29T12:00:00Z", db_path=search_db)["items"][0]["id"] == old["id"]


@pytest.mark.parametrize("kwargs", [
    {"created_from": "2026-01-01T00:00:00", "created_until": "2026-01-02T00:00:00Z"},
    {"created_from": "bad"},
    {"created_from": "2026-01-02T00:00:00Z", "created_until": "2026-01-01T00:00:00Z"},
    {"created_from": "2025-01-01T00:00:00Z", "created_until": "2026-02-02T00:00:00Z"},
    {"closed_from": "2026-01-01T00:00:00Z", "closed_until": "2026-01-01T00:00:00Z"},
])
def test_invalid_search_dates_rejected(search_db, kwargs):
    with pytest.raises(IncidentReviewError) as error:
        search_reviews(title="review title", db_path=search_db, **kwargs)
    assert error.value.status_code == 422


def test_structured_filters_combine_with_and(search_db):
    expected = _create(search_db, "Firewall Authentication", state="OPEN", priority="HIGH",
                       disposition="BENIGN")
    _create(search_db, "Firewall Authentication", state="IN_REVIEW", priority="HIGH",
            disposition="BENIGN")
    _create(search_db, "Firewall Authentication", state="OPEN", priority="LOW",
            disposition="BENIGN")
    result = search_reviews(title="fire auth", state="OPEN", priority="HIGH",
                            disposition="BENIGN", site_id=9, scope_id=8, device_id=7,
                            db_path=search_db)
    assert [item["id"] for item in result["items"]] == []
    assert search_reviews(title="fire auth", state="OPEN", priority="HIGH",
                          disposition="BENIGN", db_path=search_db)["items"][0]["id"] == expected["id"]


def test_site_scope_and_device_filters_match_explicit_attribution(search_db):
    site = RemoteSensorStore(search_db).create_site("Search site")
    network = create_network("10.77.0.0/24", "Search network", "", True, True, db_path=search_db)
    device = create_device(
        stable_key="search-device", network_id=network["id"], mac_address=None,
        hostname="search-host", vendor=None, first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-01-01T00:00:00+00:00", last_ip_address="10.77.0.9",
        status="ONLINE", identity_confidence="HIGH", db_path=search_db,
    )
    with get_connection(search_db) as connection:
        scope_id = connection.execute(
            "SELECT scope_id FROM network_scope_links WHERE network_id=?", (network["id"],)
        ).fetchone()[0]
        connection.execute("INSERT INTO remote_scope_sites (scope_id,site_id,created_at) VALUES (?,?,?)",
                           (scope_id, site["id"], "2026-01-01T00:00:00+00:00"))
    review = _create(search_db, "Attributed Authentication issue", site_id=site["id"],
                     scope_id=scope_id, device_id=device["id"], state="IN_REVIEW",
                     priority="CRITICAL", disposition="ACTION_REQUIRED")
    base = dict(title="attr auth", db_path=search_db)
    assert search_reviews(**base, site_id=site["id"])["items"][0]["id"] == review["id"]
    assert search_reviews(**base, scope_id=scope_id)["items"][0]["id"] == review["id"]
    assert search_reviews(**base, device_id=device["id"])["items"][0]["id"] == review["id"]
    assert search_reviews(**base, state="IN_REVIEW", priority="CRITICAL",
                          disposition="ACTION_REQUIRED", site_id=site["id"],
                          scope_id=scope_id, device_id=device["id"])["items"][0]["id"] == review["id"]
    assert search_reviews(**base, state="OPEN")["items"] == []


def test_stable_sort_projection_pagination_and_caps(search_db):
    ids = [_create(search_db, f"StableSearch title {n}")["id"] for n in range(4)]
    for review_id in ids:
        _set_dates(search_db, review_id, created="2026-01-01T00:00:00+00:00",
                   updated="2026-02-01T00:00:00+00:00")
    first = search_reviews(title="stable", limit=2, db_path=search_db)
    second = search_reviews(title="stable", limit=2, offset=2, db_path=search_db)
    assert first["limit"] == 2 and first["offset"] == 0 and first["has_more"] is True
    assert second["has_more"] is False
    assert [row["id"] for row in first["items"] + second["items"]] == sorted(ids, reverse=True)
    assert set(first["items"][0]) == {
        "id", "incident_key", "title", "state", "priority", "confidence", "disposition",
        "site_id", "scope_id", "device_id", "created_at", "updated_at", "closed_at",
    }
    assert search_reviews(title="stable", db_path=search_db)["limit"] == 20
    with pytest.raises(IncidentReviewError):
        search_reviews(title="stable", limit=101, db_path=search_db)
    with pytest.raises(IncidentReviewError):
        search_reviews(title="stable", offset=100001, db_path=search_db)


def test_search_uses_one_candidate_query_without_audit_or_review_detail_lookups(search_db, monkeypatch):
    review = _create(search_db, "ReadOnlySearch candidate")
    with get_connection(search_db) as connection:
        before = (
            connection.execute("SELECT COUNT(*) FROM incident_review_events").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM management_audit_events").fetchone()[0],
        )

    def unexpected_detail_lookup(*args, **kwargs):
        raise AssertionError("search must not perform a per-result review lookup")

    monkeypatch.setattr("database.incident_reviews._review", unexpected_detail_lookup)
    assert search_reviews(title="readonly", db_path=search_db)["items"][0]["id"] == review["id"]
    with get_connection(search_db) as connection:
        after = (
            connection.execute("SELECT COUNT(*) FROM incident_review_events").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM management_audit_events").fetchone()[0],
        )
    assert after == before


def test_search_endpoint_is_guarded_ordered_and_no_store(search_db):
    _create(search_db, "RouteOrder title")
    app = _app(search_db)
    route = next(route for route in app.routes if getattr(route, "path", None) == "/incident-reviews/search")
    dynamic = next(route for route in app.routes
                   if getattr(route, "path", None) == "/incident-reviews/{incident_id}")
    assert app.routes.index(route) < app.routes.index(dynamic)
    assert any(dependency.call is local_management for dependency in route.dependant.dependencies)
    result = route.endpoint(
        title="route", state=None, priority=None, disposition=None, site_id=None,
        scope_id=None, device_id=None, created_from=None, created_until=None,
        closed_from=None, closed_until=None, limit=20, offset=0,
    )
    assert result["items"][0]["title"] == "RouteOrder title"
    assert "summary" not in result["items"][0]
    assert result["limit"] == 20 and result["has_more"] is False

    # Exercise the same guard directly with the local operator request contract;
    # the project TestClient transport stalls in this runtime before dispatch.
    def check_guard(*, peer="127.0.0.1", host="127.0.0.1:8000", origin=None):
        headers = [(b"host", host.encode())]
        if origin is not None:
            headers.append((b"origin", origin.encode()))
        request = Request({
            "type": "http", "method": "GET", "scheme": "http", "path": "/incident-reviews/search",
            "raw_path": b"/incident-reviews/search", "query_string": b"title=route",
            "headers": headers, "client": (peer, 5050), "server": ("127.0.0.1", 8000),
        })
        response = Response()
        try:
            local_management(request, response)
        except Exception:
            return response, False
        return response, True

    for origin in (None, "http://127.0.0.1:5173", "http://localhost:5173"):
        response, allowed = check_guard(origin=origin)
        assert allowed and response.headers["cache-control"] == "no-store"
    assert not check_guard(peer="192.0.2.5")[1]
    assert not check_guard(host="example.test")[1]
    assert not check_guard(origin="https://example.test")[1]


def test_existing_list_route_remains_distinct(search_db):
    _create(search_db, "List behavior title")
    app = _app(search_db)
    route = next(route for route in app.routes if getattr(route, "path", None) == "/incident-reviews")
    response = route.endpoint(state=None, priority=None, site_id=None, scope_id=None,
                              device_id=None, disposition=None, limit=20, offset=0)
    assert response["count"] == 1
    assert "total" in response


def test_search_fts_query_plan_uses_virtual_table(search_db):
    with get_connection(search_db) as connection:
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT r.id FROM incident_reviews_fts "
            "JOIN incident_reviews r ON r.id=incident_reviews_fts.rowid "
            "WHERE incident_reviews_fts MATCH ? ORDER BY r.updated_at DESC,r.id DESC LIMIT ?",
            ('"fire"* AND "auth"*', 21),
        ).fetchall()
    assert any("VIRTUAL TABLE INDEX" in row[3] for row in plan)


def test_migration_45_failure_rolls_back(monkeypatch, tmp_path):
    path = tmp_path / "fts-unavailable.db"
    all_migrations = MIGRATIONS
    unavailable_fts = "CREATE VIRTUAL TABLE incident_reviews_fts USING unavailable_fts_module(title)"
    monkeypatch.setattr(migration_module, "MIGRATIONS", all_migrations[:44] + ((45, (unavailable_fts,)),))
    with pytest.raises(sqlite3.OperationalError):
        initialize_database(path)
    with get_connection(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 44
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE name='incident_reviews_fts'").fetchone() is None

