import html.parser
import re

import pytest
from fastapi import FastAPI, HTTPException

from api.incident_reviews import register_incident_review_routes
from api.remote_sensors import local_management
from database import incident_review_reports as reports
from database.db import get_connection, initialize_database
from database.incident_reviews import create_review
from services import incident_review_report_html as renderer


REPORT_AT = "2026-10-18T12:34:56Z"
EVIDENCE_TYPES = (
    "PERIMETER_DETECTION", "PERIMETER_POLICY_CORRELATION", "PERIMETER_HOST_CORRELATION",
    "EXTERNAL_EXPOSURE_CHANGE", "THREAT_DETECTION", "THREAT_CORRELATION", "WEB_DETECTION",
)


def _app(path):
    app = FastAPI()
    register_incident_review_routes(app, lambda: path)
    return app


def _endpoint(path):
    route = next(route for route in _app(path).routes
                 if getattr(route, "path", None) == "/incident-reviews/{incident_id}/report.html")
    return route.endpoint, route


@pytest.fixture
def report_db(tmp_path):
    path = tmp_path / "incident-review-report-html.db"
    initialize_database(path)
    return path


def _seed_projection(report_db):
    review = create_review(title="Report <title>", summary="Summary", db_path=report_db)
    with get_connection(report_db) as connection:
        for index, evidence_type in enumerate(EVIDENCE_TYPES, 1):
            connection.execute("""INSERT INTO incident_review_evidence
                (incident_id,evidence_type,evidence_id,observed_at,added_at)
                VALUES (?,?,?,?,?)""", (review["id"], evidence_type, index,
                                           f"2026-10-{index:02d}T00:00:00Z", REPORT_AT))
        connection.execute("""INSERT INTO incident_review_notes
            (incident_review_id,note_text,actor_source,created_at) VALUES (?,?,?,?)""",
            (review["id"], "Note text", "OPERATOR", "2026-10-01T00:00:00Z"))
        connection.execute("""INSERT INTO incident_review_events
            (incident_review_id,event_type,actor_source,created_at,field_name,old_value,new_value,summary)
            VALUES (?,?,?,?,?,?,?,?)""", (review["id"], "REVIEW_FIELD_CHANGED", "OPERATOR",
            "2026-10-02T00:00:00Z", "title", "never-show-old", "never-show-new", "Timeline summary"))
    return reports.build_incident_review_report(review["id"], REPORT_AT, report_db)


class _HTMLCollector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend((tag, name, value) for name, value in attrs)


def test_html_endpoint_headers_filename_csp_and_same_access_boundary(report_db):
    review = create_review(title="Never in filename", db_path=report_db)
    endpoint, route = _endpoint(report_db)
    response = endpoint(review["id"])
    assert response.status_code == 200
    assert response.media_type == "text/html"
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].startswith("inline; filename=\"")
    assert re.fullmatch(r'inline; filename="sentinelip-incident-review-\d+-\d{8}T\d{6}Z\.html"',
                        response.headers["content-disposition"])
    assert "Never in filename" not in response.headers["content-disposition"]
    csp = response.headers["content-security-policy"]
    for directive in ("default-src 'none'", "style-src 'unsafe-inline'", "img-src 'none'",
                      "font-src 'none'", "script-src 'none'", "object-src 'none'",
                      "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"):
        assert directive in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert any(dependency.call is local_management
               for dependency in route.dependant.dependencies)
    text = response.body.decode("utf-8")
    assert text.startswith("<!doctype html>") and text.endswith("</html>")
    assert "This report represents the current Incident Review state" in text
    assert "Report schema version" in text and "Generated at" in text


def test_html_missing_and_invalid_review_match_json_report_errors(report_db):
    endpoint, _ = _endpoint(report_db)
    with pytest.raises(HTTPException) as missing:
        endpoint(987654)
    assert missing.value.status_code == 404
    with pytest.raises(HTTPException) as invalid:
        endpoint(0)
    assert invalid.value.status_code == 422


def test_html_renders_all_evidence_types_and_keeps_missing_sources_visible(report_db):
    report = _seed_projection(report_db)
    rendered = renderer.render_incident_review_report_html(report).decode("utf-8")
    for label in ("Perimeter detection", "Perimeter policy correlation", "Perimeter host correlation",
                  "External exposure change", "Threat detection", "Threat correlation", "Web detection"):
        assert label in rendered
    assert "Source status" in rendered and "Missing" in rendered
    for evidence_id in range(1, 8):
        assert f"#{evidence_id}" in rendered


def test_html_escapes_all_report_text_and_emits_no_executable_markup(report_db):
    report = _seed_projection(report_db)
    hostile = '<script>alert(1)</script> <img src=x onerror=alert(1)> "><svg/onload=alert(1)> & < > " \' '
    report["review"]["title"] = hostile
    report["review"]["summary"] = hostile
    report["review"]["final_summary"] = hostile
    report["notes"]["items"][0]["text"] = hostile
    report["timeline"]["items"][0]["summary"] = hostile
    report["evidence"]["items"][0]["site_id"] = hostile
    rendered = renderer.render_incident_review_report_html(report).decode("utf-8")
    assert html.parser
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
    assert "&quot;&gt;&lt;svg/onload=alert(1)&gt;" in rendered
    parser = _HTMLCollector()
    parser.feed(rendered)
    assert "script" not in parser.tags
    assert "img" not in parser.tags
    assert "svg" not in parser.tags
    assert all(not name.lower().startswith("on") for _, name, _ in parser.attributes)
    assert "never-show-old" not in rendered and "never-show-new" not in rendered
    assert "<script>alert(1)</script>" not in rendered


def test_html_shows_collection_truncation_counts_and_source_class_without_identity(report_db):
    report = _seed_projection(report_db)
    for name, total, returned, omitted in (("evidence", 247, 200, 47),
                                            ("notes", 63, 50, 13),
                                            ("timeline", 88, 50, 38)):
        report[name].update(total=total, returned=returned, omitted=omitted, truncated=True)
    rendered = renderer.render_incident_review_report_html(report).decode("utf-8")
    assert "Showing 200 of 247 evidence items; 47 omitted by the report limit." in rendered
    assert "Showing 50 of 63 notes; 13 omitted by the report limit." in rendered
    assert "Showing 50 of 88 timeline events; 38 omitted by the report limit." in rendered
    assert "Operator" in rendered
    assert "username" not in rendered.lower() and "analyst identity" not in rendered.lower()


def test_html_uses_only_fixed_projection_fields_and_preserves_input_order(report_db):
    report = _seed_projection(report_db)
    report["evidence"]["items"][0]["raw_payload"] = "must-not-render"
    report["notes"]["items"][0]["private_metadata"] = "must-not-render"
    report["timeline"]["items"][0]["old_value"] = "must-not-render"
    report["timeline"]["items"][0]["new_value"] = "must-not-render"
    rendered = renderer.render_incident_review_report_html(report).decode("utf-8")
    assert "must-not-render" not in rendered
    assert rendered.index("#1") < rendered.index("#7")
    assert "<pre>" not in rendered
    assert "https://" not in rendered


def test_html_renderer_has_no_database_dependency_and_route_uses_one_assembler(report_db, monkeypatch):
    review = create_review(title="No second read", db_path=report_db)
    calls = []
    original = reports.build_incident_review_report

    def tracked(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(reports, "build_incident_review_report", tracked)
    endpoint, _ = _endpoint(report_db)
    assert endpoint(review["id"]).status_code == 200
    assert len(calls) == 1
    assert not hasattr(renderer, "get_connection")
    assert not hasattr(renderer, "sqlite3")


def test_html_output_size_limit_returns_safe_413(report_db, monkeypatch):
    review = create_review(title="Oversize", db_path=report_db)
    monkeypatch.setattr(renderer, "MAX_REPORT_HTML_BYTES", 10)
    endpoint, _ = _endpoint(report_db)
    with pytest.raises(HTTPException) as oversized:
        endpoint(review["id"])
    assert oversized.value.status_code == 413
    assert oversized.value.detail == "Incident review HTML report exceeds the output size limit."


def test_html_renderer_bounds_output_at_six_mib(report_db):
    report = _seed_projection(report_db)
    rendered = renderer.render_incident_review_report_html(report)
    assert len(rendered) <= 6 * 1024 * 1024
    assert len(rendered) > 0
