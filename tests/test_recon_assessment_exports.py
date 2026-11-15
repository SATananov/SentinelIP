import struct
import zlib
from io import BytesIO
import importlib.util
from zipfile import ZipFile

import pytest
from fastapi import HTTPException

from api.remote_sensors import local_management
import services.recon_assessment_exports as exports
from api.recon_assessment_report import build_assessment_report
from api.recon_evidence import ensure_table
from database.db import get_connection, initialize_database
from database.inventory import create_device
from database.networks import create_network
from database.scopes import create_scope, get_scope_for_network
from database.services import create_port, create_service
from services.recon_assessment_exports import (
    ReportOutputLimitError,
    load_export_images,
    render_assessment_docx,
    render_assessment_html,
    render_assessment_pdf,
)


def _chunk(tag, payload):
    return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)


def _png():
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + _chunk(b"IEND", b""))


def _data_counts(path):
    with get_connection(path) as connection:
        return tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("devices", "ports", "services", "findings", "recon_evidence"))


@pytest.fixture
def stored_report(tmp_path):
    path = tmp_path / "recon-export.db"
    initialize_database(path)
    network = create_network("192.168.72.0/24", "Export lab", "", True, True, path)
    scope = get_scope_for_network(network["id"], path)
    device = create_device(
        stable_key=f"network:{network['id']}:ip:192.168.72.5", network_id=network["id"],
        mac_address=None, hostname="<script>alert(1)</script>", vendor="Lab Vendor",
        first_seen="2026-11-01T00:00:00", last_seen="2026-11-01T00:00:00",
        last_ip_address="192.168.72.5", status="ONLINE", identity_confidence="HIGH", db_path=path,
    )
    port = create_port(device["id"], 443, "tcp", "open", "2026-11-01T00:00:00", "2026-11-01T00:00:00", path)
    service = create_service(device["id"], port["id"], "https", "Lab Server", "3.2", None,
                             "HIGH", "2026-11-01T00:00:00", "2026-11-01T00:00:00", path)
    with get_connection(path) as connection:
        cursor = connection.execute(
            """INSERT INTO findings (finding_type,device_id,network_id,severity,confidence,status,title,reason,
               recommendation,evidence_type,source,rule_id,rule_version,stable_key,first_seen,last_seen,created_at,updated_at)
               VALUES ('SERVICE',?,?, 'HIGH','HIGH','OPEN','<img src=x onerror=alert(1)>','Stored technical evidence',
               'Review the exposed service','SERVICE','fixture','fixture.rule','1','export-finding',
               '2026-11-01','2026-11-01','2026-11-01','2026-11-01')""",
            (device["id"], network["id"]),
        )
        finding_id = cursor.lastrowid
        ensure_table(connection)
        cursor = connection.execute(
            """INSERT INTO recon_evidence (device_id,finding_id,filename,description,media_type,image_data,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (device["id"], finding_id, "<proof>.png", "Evidence <script>blocked</script>", "image/png", _png(), "2026-11-02T00:00:00"),
        )
        evidence_id = cursor.lastrowid
    report = build_assessment_report(scope["id"], path)
    images = load_export_images(report, path)
    return path, scope, report, images, evidence_id, service


def test_pdf_document_structure_and_embedded_screenshot(stored_report):
    path, _, report, images, evidence_id, service = stored_report
    before = _data_counts(path)
    result = render_assessment_pdf(report, images)
    assert result.startswith(b"%PDF-")
    assert len(result) <= exports.MAX_OUTPUT_BYTES
    assert evidence_id in images
    assert b"/Subtype /Image" in result
    assert b"/Type /Page" in result
    assert service["service_name"] == "https"
    assert _data_counts(path) == before


def test_docx_structure_and_embedded_screenshot(stored_report):
    pytest.importorskip("docx")
    path, _, report, images, evidence_id, _ = stored_report
    before = _data_counts(path)
    result = render_assessment_docx(report, images)
    with ZipFile(BytesIO(result)) as archive:
        names = archive.namelist()
        document = archive.read("word/document.xml")
        assert "word/media/image1.png" in names
        assert b"SentinelIP Assessment Report" in document
        assert report["report_id"].encode() in document
        assert b"<w:tbl>" in document
        assert b"<w:drawing>" in document
    assert evidence_id in images
    assert _data_counts(path) == before


def test_html_is_self_contained_escaped_and_contains_screenshot(stored_report):
    path, _, report, images, _, _ = stored_report
    before = _data_counts(path)
    result = render_assessment_html(report, images).decode("utf-8")
    assert "<script>alert(1)</script>" not in result
    assert "&lt;script&gt;blocked&lt;/script&gt;" in result
    assert "<img src=x onerror=alert(1)>" not in result
    assert "&lt;img src=x onerror=alert(1)&gt;" in result
    assert "data:image/png;base64," in result
    assert "default-src &#x27;none&#x27;" in result
    assert "https://" not in result and "http://" not in result
    assert _data_counts(path) == before


def test_missing_screenshot_is_not_invented(stored_report):
    path, _, report, _, evidence_id, _ = stored_report
    with get_connection(path) as connection:
        connection.execute("DELETE FROM recon_evidence WHERE id=?", (evidence_id,))
    images = load_export_images(report, path)
    html = render_assessment_html(report, images).decode("utf-8")
    assert evidence_id not in images
    assert "Image not embedded (missing or export size limit reached)." in html


def test_cross_scope_screenshot_is_not_loaded(stored_report):
    path, _, report, _, _, _ = stored_report
    other_scope = create_scope(scope_type="PUBLIC_IPV4", canonical_target="8.8.8.8", name="Other",
                               authorized=True, enabled=True, authorization_confirmed_at="2026-11-01",
                               authorization_confirmation_version="fixture", authorization_source="fixture",
                               db_path=path)
    with get_connection(path) as connection:
        cursor = connection.execute(
            """INSERT INTO devices (stable_key,network_id,scope_id,mac_address,hostname,vendor,first_seen,last_seen,
               last_ip_address,status,identity_confidence,created_at,updated_at)
               VALUES ('other-scope',NULL,?,NULL,NULL,NULL,'2026-11-01','2026-11-01','8.8.8.8','ONLINE','LOW','2026-11-01','2026-11-01')""",
            (other_scope["id"],),
        )
        other_device = cursor.lastrowid
        ensure_table(connection)
        cursor = connection.execute(
            """INSERT INTO recon_evidence (device_id,filename,description,media_type,image_data,created_at)
               VALUES (?,?,?,?,?,?)""",
            (other_device, "secret.png", "other scope", "image/png", _png(), "2026-11-03"),
        )
        other_evidence = cursor.lastrowid
    images = load_export_images(report, path)
    assert other_evidence not in images


def test_image_export_rechecks_authorization(stored_report):
    path, scope, report, _, _, _ = stored_report
    with get_connection(path) as connection:
        connection.execute("UPDATE authorized_scopes SET enabled=0 WHERE id=?", (scope["id"],))
    with pytest.raises(HTTPException) as rejected:
        load_export_images(report, path)
    assert rejected.value.status_code == 403


def test_empty_report_and_output_limit(stored_report, monkeypatch, tmp_path):
    _, scope, report, _, _, _ = stored_report
    empty = dict(report)
    empty["devices"] = []
    empty["findings"] = []
    empty["recommendations"] = []
    assert b"/Type /Page" in render_assessment_pdf(empty, {})
    assert b"No assets were present" in render_assessment_html(empty, {})
    monkeypatch.setattr(exports, "MAX_OUTPUT_BYTES", 10)
    with pytest.raises(ReportOutputLimitError):
        render_assessment_html(report, {})
    assert scope["id"] == report["assessment"]["scope_id"]


def test_export_route_responses_and_existing_recon_routes(stored_report, monkeypatch):
    from api import main as api_main

    path, scope, _, _, _, _ = stored_report
    monkeypatch.setattr(api_main, "DB_PATH", path)
    app = api_main.app

    expected = {
        "/recon/scopes/{scope_id}/assessment-report",
        "/recon/scopes/{scope_id}/assessment-report/pdf",
        "/recon/scopes/{scope_id}/assessment-report/docx",
        "/recon/scopes/{scope_id}/assessment-report/html",
        "/recon/devices/{device_id}/evidence",
        "/recon/devices/{device_id}/evidence/{evidence_id}",
    }
    for path in expected:
        routes = [route for route in app.routes if getattr(route, "path", None) == path
                  and "GET" in (getattr(route, "methods", None) or set())]
        assert len(routes) == 1
        if "assessment-report" in path:
            assert any(dependency.call is local_management for dependency in routes[0].dependant.dependencies)
    for extension, content_type in (("pdf", exports.PDF_MIME), ("html", exports.HTML_MIME)):
        route = next(route for route in app.routes if getattr(route, "path", None) ==
                     f"/recon/scopes/{{scope_id}}/assessment-report/{extension}"
                     and "GET" in (getattr(route, "methods", None) or set()))
        response = route.endpoint(scope["id"])
        assert response.media_type == content_type
        assert response.headers["content-disposition"].endswith(f".{extension}\"")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        if extension == "html":
            assert response.headers["content-security-policy"] == exports.HTML_CSP
    if importlib.util.find_spec("docx"):
        route = next(route for route in app.routes if getattr(route, "path", None) ==
                     "/recon/scopes/{scope_id}/assessment-report/docx"
                     and "GET" in (getattr(route, "methods", None) or set()))
        response = route.endpoint(scope["id"])
        assert response.media_type == exports.DOCX_MIME


def test_docx_is_editable_office_package(stored_report):
    pytest.importorskip("docx")
    _, _, report, images, _, _ = stored_report
    result = render_assessment_docx(report, images)
    with ZipFile(BytesIO(result)) as archive:
        assert "[Content_Types].xml" in archive.namelist()
        assert "word/styles.xml" in archive.namelist()
        assert b"<w:tbl>" in archive.read("word/document.xml")
