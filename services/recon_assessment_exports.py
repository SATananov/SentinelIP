import base64
import html
import io
import sqlite3
import struct
import zlib

from fastapi import HTTPException
from database.db import get_connection

MAX_EMBEDDED_IMAGES = 20
MAX_IMAGE_BYTES = 1_048_576
MAX_IMAGE_PIXELS = 16_000_000
MAX_TOTAL_IMAGE_BYTES = 5_242_880
MAX_OUTPUT_BYTES = 15_728_640
PDF_MIME = "application/pdf"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
HTML_MIME = "text/html; charset=utf-8"
HTML_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"


class ReportOutputLimitError(ValueError):
    pass


def load_export_images(report, db_path):
    scope_id = report["assessment"]["scope_id"]
    expected = []
    for device_report in report["devices"]:
        device_id = device_report["device"]["id"]
        for evidence in device_report["evidence"]:
            expected.append((evidence["id"], device_id, evidence.get("finding_id"), evidence.get("media_type")))
    expected = expected[:MAX_EMBEDDED_IMAGES]
    evidence_ids = [item[0] for item in expected]
    expected_by_id = {item[0]: item for item in expected}
    devices = {item[0]: item[1] for item in expected}
    placeholders = ",".join("?" for _ in evidence_ids)
    connection = get_connection(db_path)
    images = {}
    total_bytes = 0
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        scope = connection.execute(
            "SELECT id,scope_type,canonical_target,authorized,enabled,authorization_confirmed_at,authorization_confirmation_version,authorization_source FROM authorized_scopes WHERE id=?",
            (scope_id,),
        ).fetchone()
        if scope is None or scope["authorized"] != 1 or scope["enabled"] != 1 or not all(
            scope[field] for field in ("authorization_confirmed_at", "authorization_confirmation_version", "authorization_source")
        ):
            raise HTTPException(403, "An authorized, enabled target is required.")
        if not expected:
            return {}
        rows = connection.execute(
            f"""SELECT e.id,e.device_id,e.finding_id,e.media_type,e.image_data,
                       CASE WHEN e.finding_id IS NULL OR f.id IS NOT NULL THEN 1 ELSE 0 END AS finding_valid
                FROM recon_evidence e
                JOIN devices d ON d.id=e.device_id
                LEFT JOIN findings f ON f.id=e.finding_id AND f.device_id=e.device_id
                WHERE e.id IN ({placeholders}) AND e.device_id IN ({','.join('?' for _ in set(devices.values()))})
                  AND (e.finding_id IS NULL OR f.id IS NOT NULL)
                  AND (
                    ( ?='PRIVATE_NETWORK' AND EXISTS (
                       SELECT 1 FROM network_scope_links l WHERE l.scope_id=? AND l.network_id=d.network_id))
                    OR (?='PUBLIC_IPV4' AND d.scope_id=? AND d.network_id IS NULL AND d.last_ip_address=?)
                    OR (?='PUBLIC_CIDR' AND d.scope_id=? AND d.network_id IS NULL AND EXISTS (
                       SELECT 1 FROM scope_cidr_addresses a WHERE a.scope_id=? AND a.canonical_cidr=? AND a.ipv4_address=d.last_ip_address))
                    OR (?='HOSTNAME' AND d.scope_id=? AND d.network_id IS NULL AND EXISTS (
                       SELECT 1 FROM scope_hostname_addresses a WHERE a.scope_id=? AND a.approved=1 AND a.ipv4_address=d.last_ip_address))
                  ) ORDER BY e.id""",
            [*evidence_ids, *set(devices.values()), scope["scope_type"], scope_id,
             scope["scope_type"], scope_id, scope["canonical_target"],
             scope["scope_type"], scope_id, scope_id, scope["canonical_target"],
             scope["scope_type"], scope_id, scope_id],
        ).fetchall()
        for row in rows:
            expected_row = expected_by_id.get(row["id"])
            if (expected_row is None or row["device_id"] != devices.get(row["id"])
                    or row["finding_id"] != expected_row[2]
                    or row["media_type"] != expected_row[3]):
                continue
            image_data = bytes(row["image_data"])
            media_type = _valid_image(image_data)
            if media_type is None or media_type != row["media_type"]:
                continue
            if total_bytes + len(image_data) > MAX_TOTAL_IMAGE_BYTES:
                break
            images[row["id"]] = {"media_type": media_type, "data": image_data}
            total_bytes += len(image_data)
    finally:
        connection.close()
    return images


def render_assessment_pdf(report, images):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    output = io.BytesIO()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("AssessmentTitle", parent=styles["Title"], alignment=TA_CENTER,
                                 textColor=colors.HexColor("#12345a"), fontSize=21, leading=25)
    body = ParagraphStyle("AssessmentBody", parent=styles["BodyText"], fontSize=8, leading=11)
    small = ParagraphStyle("AssessmentSmall", parent=body, fontSize=7, leading=9)
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=18*mm, bottomMargin=18*mm, title="SentinelIP Assessment Report",
                            author="SentinelIP")
    story = [Paragraph("SentinelIP Assessment Report", title_style), Spacer(1, 5*mm)]
    assessment = report["assessment"]
    story += _pdf_table([
        ("Report ID", report["report_id"]), ("Generated (UTC)", report["generated_at"]),
        ("Schema", report["schema_version"]), ("Target", assessment.get("target")),
        ("Scope type", assessment.get("scope_type")), ("Assessment type", assessment.get("assessment_type")),
    ], body)
    coverage = report["coverage"]
    story += [Paragraph("Executive summary", styles["Heading1"])]
    story += [Paragraph(_escape(f"{coverage['discovered_assets']} assets were discovered. "
                                f"{coverage['assets_with_service_evidence']} have stored service evidence; "
                                f"{coverage['assets_without_service_evidence']} do not. "
                                f"{len(report['findings'])} findings and {coverage['unverified_cve_matches']} unverified CVE matches are included. "
                                "No findings do not prove that a device is secure."), body)]
    story += [Paragraph("Authorized scope", styles["Heading1"]),
              Paragraph(_escape(f"{assessment.get('name') or 'Authorized target'} — {assessment.get('target')} ({assessment.get('scope_type')})"), body)]
    story.append(Paragraph("Stored scan observations", styles["Heading1"]))
    scan_observations = report.get("scan_metadata", {}).get("observations", [])
    story += _pdf_data_table([["Device ID", "Latest observation", "Sources"]] + [
        [row.get("device_id"), row.get("latest_observed_at"), ", ".join(row.get("sources", []))]
        for row in scan_observations] if scan_observations else [["No stored scan observations", "", ""]], small)
    story.append(Paragraph("No persisted scan session is available." if not report.get("scan_metadata", {}).get("persisted_session") else "Persisted scan session metadata is available.", small))
    story += [Paragraph("Discovered assets, ports and services", styles["Heading1"])]
    if not report["devices"]:
        story.append(Paragraph("No assets were present in the stored assessment snapshot.", body))
    else:
        story += _pdf_data_table([["IP address", "Device", "Current status", "Ports", "Services", "Findings"]] + [
            [item["device"].get("ip_address"), item["device"].get("hostname") or item["device"].get("vendor") or "Unknown device",
             item["device"].get("status") or "Unavailable", len(item["ports"]), len(item["services"]), len(item["findings"])]
            for item in report["devices"]], small)
    for item in report["devices"]:
        device = item["device"]
        story.append(Paragraph(_escape(f"{device.get('ip_address') or 'Unknown IP'} — {device.get('hostname') or device.get('vendor') or 'Unknown device'} — {device.get('status') or 'Status unavailable'}"), styles["Heading2"]))
        port_service = [["Port / transport", "State", "Service", "Product / version"]]
        service_by_port = {service.get("port_id"): service for service in item["services"]}
        for port in item["ports"]:
            service = service_by_port.get(port["id"], {})
            port_service.append([f"{port.get('port_number')}/{port.get('transport')}", port.get("state"),
                                 service.get("service_name") or "—", " ".join(filter(None, [service.get("product"), service.get("version")])) or "—"])
        if item["ports"]:
            story += _pdf_data_table(port_service, small)
        elif item["services"]:
            story += _pdf_data_table([["Service", "Product", "Version", "Confidence"]] + [
                [service.get("service_name"), service.get("product"), service.get("version"), service.get("confidence")]
                for service in item["services"]], small)
        else:
            story.append(Paragraph("No recorded port or service observations. Service coverage is incomplete.", small))
        if item["ports"] and not item["services"]:
            story.append(Paragraph("No service evidence is stored for this asset.", small))
        http_tls_rows = _http_tls_observation_rows(item)
        if http_tls_rows:
            story.append(Paragraph("HTTP/TLS endpoint observations", styles["Heading3"]))
            story += _pdf_data_table([["Endpoint", "Observed", "Outcome / HTTP", "TLS", "Run / target"]] + [
                [_pdf_wrap_long_tokens(cell) for cell in row] for row in http_tls_rows
            ], small)
        if item.get("truncation", {}).get("http_tls_observations"):
            story.append(Paragraph("HTTP/TLS observations are truncated; this section does not show the complete stored history.", small))
        if item["findings"]:
            story.append(Paragraph("Findings", styles["Heading3"]))
            service_names = {service["id"]: " ".join(filter(None, [service.get("service_name"), service.get("product"), service.get("version")]))
                             for service in item["services"]}
            story += _pdf_data_table([["Title", "Severity", "Status", "Verification", "Service", "Evidence type / description"]] + [
                [finding.get("title"), finding.get("severity"), finding.get("finding_status"),
                 finding.get("verification_status"), service_names.get(finding.get("service_id"), finding.get("service_id") or "—"),
                 f"{finding.get('evidence_type') or '—'}: {finding.get('description')}" ]
                for finding in item["findings"]], small)
            for finding in item["findings"]:
                linked = [evidence for evidence in item["evidence"] if evidence.get("finding_id") == finding["id"]]
                if linked:
                    story.append(Paragraph(_escape(f"Screenshots linked to finding: {finding.get('title')}"), styles["Heading4"]))
                    _pdf_render_evidence(story, linked, images, small, mm)
        if item["cve_matches"]:
            story.append(Paragraph("CVE matches and verification status", styles["Heading3"]))
            story += _pdf_data_table([["CVE", "Match status", "Verification", "Confidence", "Service ID", "Finding ID", "Match evidence and intelligence"]] + [
                [match.get("cve_id"), match.get("match_status"), match.get("verification_status", "UNVERIFIED"), match.get("confidence"),
                 match.get("service_id"), match.get("finding_id"), _cve_intelligence_summary(match)]
                for match in item["cve_matches"]], small)
        if item["evidence"]:
            visible_findings = {finding["id"] for finding in item["findings"]}
            general = [evidence for evidence in item["evidence"]
                       if evidence.get("finding_id") is None or evidence.get("finding_id") not in visible_findings]
            if general:
                story.append(Paragraph("Device screenshots and evidence", styles["Heading3"]))
                _pdf_render_evidence(story, general, images, small, mm)
    story += [Paragraph("Recommendations", styles["Heading1"])]
    recommendations = report["recommendations"]
    story.extend(Paragraph("• " + _escape(item), body) for item in recommendations)
    if not recommendations:
        story.append(Paragraph("No finding-backed remediation recommendations are recorded.", body))
    story += [Paragraph("Coverage and limitations", styles["Heading1"])]
    story += _pdf_table([(key.replace("_", " ").title(), value) for key, value in coverage.items() if key != "limitations"], body)
    story.extend(Paragraph("• " + _escape(item), body) for item in coverage.get("limitations", []))
    story.append(Paragraph("Conclusion", styles["Heading1"]))
    story.append(Paragraph("This report reflects stored evidence available at generation time. Missing scan or service evidence limits conclusions; absence of findings is not assurance of security.", body))
    doc.build(story, onFirstPage=_pdf_page_number, onLaterPages=_pdf_page_number)
    return _bounded_output(output.getvalue())


def render_assessment_docx(report, images):
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Inches, Pt
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    document = Document()
    section = document.sections[0]
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    normal = document.styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(9)
    document.add_heading("SentinelIP Assessment Report", 0)
    assessment = report["assessment"]
    _docx_table(document, [
        ("Report ID", report["report_id"]), ("Generated (UTC)", report["generated_at"]),
        ("Schema", report["schema_version"]), ("Target", assessment.get("target")),
        ("Scope type", assessment.get("scope_type")), ("Assessment type", assessment.get("assessment_type")),
    ])
    coverage = report["coverage"]
    document.add_heading("Executive summary", level=1)
    document.add_paragraph(f"{coverage['discovered_assets']} assets discovered; {coverage['assets_with_service_evidence']} with stored service evidence; {coverage['assets_without_service_evidence']} without. {len(report['findings'])} findings and {coverage['unverified_cve_matches']} unverified CVE matches. No findings do not prove that a device is secure.")
    document.add_heading("Authorized assessment scope", level=1)
    document.add_paragraph(f"{assessment.get('name') or 'Authorized target'} — {assessment.get('target')} ({assessment.get('scope_type')})")
    document.add_heading("Stored scan observations", level=1)
    scan_observations = report.get("scan_metadata", {}).get("observations", [])
    _docx_table(document, [["Device ID", "Latest observation", "Sources"]] + [
        [row.get("device_id"), row.get("latest_observed_at"), ", ".join(row.get("sources", []))]
        for row in scan_observations] if scan_observations else [["No stored scan observations", "", ""]])
    document.add_paragraph("No persisted scan session is available." if not report.get("scan_metadata", {}).get("persisted_session") else "Persisted scan session metadata is available.")
    document.add_heading("Discovered assets", level=1)
    if not report["devices"]:
        document.add_paragraph("No assets were present in the stored assessment snapshot.")
    else:
        _docx_table(document, [["IP address", "Device", "Current status", "Ports", "Services", "Findings"]] + [
            [item["device"].get("ip_address"), item["device"].get("hostname") or item["device"].get("vendor") or "Unknown device",
             item["device"].get("status") or "Unavailable", len(item["ports"]), len(item["services"]), len(item["findings"])]
            for item in report["devices"]])
    for item in report["devices"]:
        device = item["device"]
        document.add_heading(f"{device.get('ip_address') or 'Unknown IP'} — {device.get('hostname') or device.get('vendor') or 'Unknown device'}", level=2)
        document.add_paragraph(f"Status: {device.get('status') or 'Unavailable'}")
        service_by_port = {service.get("port_id"): service for service in item["services"]}
        port_rows = [["Port", "Transport", "State", "Service", "Product", "Version"]] + [
            [port.get("port_number"), port.get("transport"), port.get("state"),
             service_by_port.get(port["id"], {}).get("service_name"),
             service_by_port.get(port["id"], {}).get("product"),
             service_by_port.get(port["id"], {}).get("version")]
            for port in item["ports"]
        ]
        if item["ports"]:
            _docx_table(document, port_rows)
        elif item["services"]:
            _docx_table(document, [["Service", "Product", "Version", "Confidence"]] + [
                [service.get("service_name"), service.get("product"), service.get("version"), service.get("confidence")]
                for service in item["services"]])
        else:
            document.add_paragraph("No recorded port or service observations. Service coverage is incomplete.")
        if item["ports"] and not item["services"]:
            document.add_paragraph("No service evidence is stored for this asset.")
        http_tls_rows = _http_tls_observation_rows(item)
        if http_tls_rows:
            document.add_heading("HTTP/TLS endpoint observations", level=3)
            _docx_table(document, [["Endpoint", "Observed", "Outcome / HTTP", "TLS", "Run / target"]] + http_tls_rows)
        if item.get("truncation", {}).get("http_tls_observations"):
            document.add_paragraph("HTTP/TLS observations are truncated; this section does not show the complete stored history.")
        if item["findings"]:
            document.add_heading("Security findings", level=3)
            service_names = {service["id"]: " ".join(filter(None, [service.get("service_name"), service.get("product"), service.get("version")]))
                             for service in item["services"]}
            _docx_table(document, [["Title", "Severity", "Status", "Verification", "Service", "Evidence type / description"]] + [
                [f.get("title"), f.get("severity"), f.get("finding_status"), f.get("verification_status"),
                 service_names.get(f.get("service_id"), f.get("service_id")), f"{f.get('evidence_type')}: {f.get('description')}"]
                for f in item["findings"]])
            for finding in item["findings"]:
                linked = [evidence for evidence in item["evidence"] if evidence.get("finding_id") == finding["id"]]
                if linked:
                    document.add_heading(f"Evidence linked to: {finding.get('title')}", level=4)
                    _docx_render_evidence(document, linked, images)
        if item["cve_matches"]:
            document.add_heading("CVE matches and verification status", level=3)
            _docx_table(document, [["CVE", "Match status", "Verification", "Confidence", "Service ID", "Finding ID", "Evidence and intelligence"]] + [
                [x.get("cve_id"), x.get("match_status"), x.get("verification_status", "UNVERIFIED"), x.get("confidence"),
                 x.get("service_id"), x.get("finding_id"), _cve_intelligence_summary(x)]
                for x in item["cve_matches"]])
        if item["evidence"]:
            visible_findings = {finding["id"] for finding in item["findings"]}
            general = [evidence for evidence in item["evidence"]
                       if evidence.get("finding_id") is None or evidence.get("finding_id") not in visible_findings]
            if general:
                document.add_heading("Device screenshots and evidence", level=3)
                _docx_render_evidence(document, general, images)
    document.add_heading("Recommendations", level=1)
    for recommendation in report["recommendations"]:
        document.add_paragraph(recommendation, style="List Bullet")
    if not report["recommendations"]:
        document.add_paragraph("No finding-backed remediation recommendations are recorded.")
    document.add_heading("Coverage and limitations", level=1)
    _docx_table(document, [[key.replace("_", " ").title(), str(value)] for key, value in coverage.items() if key != "limitations"])
    for limitation in coverage.get("limitations", []):
        document.add_paragraph(limitation, style="List Bullet")
    document.add_heading("Conclusion", level=1)
    document.add_paragraph("This report reflects stored evidence available at generation time. Missing scan or service evidence limits conclusions; absence of findings is not assurance of security.")
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)
    output = io.BytesIO()
    document.save(output)
    return _bounded_output(output.getvalue())


def render_assessment_html(report, images):
    e = html.escape
    assessment = report["assessment"]
    coverage = report["coverage"]
    parts = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"]
    parts.append(f"<meta http-equiv=\"Content-Security-Policy\" content=\"{e(HTML_CSP)}\"><title>SentinelIP Assessment Report</title>")
    parts.append("<style>body{font:15px/1.5 Arial,sans-serif;color:#142b43;max-width:1100px;margin:2rem auto;padding:0 1.2rem}h1,h2{color:#12345a}table{border-collapse:collapse;width:100%;margin:1rem 0 1.5rem}th,td{border:1px solid #aebdca;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f6}img{display:block;max-width:100%;max-height:560px;margin:.5rem 0}article{border-top:2px solid #d3deea;padding-top:.6rem;margin-top:1.5rem}.meta{color:#425b70}.warning{padding:.7rem;background:#fff5d6}@media print{body{max-width:none;margin:0}button{display:none}article{break-inside:avoid}}</style></head><body>")
    parts.append(f"<h1>SentinelIP Assessment Report</h1><table><tbody>{_html_rows([('Report ID',report['report_id']),('Generated (UTC)',report['generated_at']),('Schema',report['schema_version']),('Target',assessment.get('target')),('Scope type',assessment.get('scope_type')),('Assessment type',assessment.get('assessment_type'))])}</tbody></table>")
    parts.append("<h2>Executive summary</h2>")
    parts.append(f"<p>{e(str(coverage['discovered_assets']))} assets discovered; {e(str(coverage['assets_with_service_evidence']))} with stored service evidence; {e(str(coverage['assets_without_service_evidence']))} without. {e(str(len(report['findings'])))} findings and {e(str(coverage['unverified_cve_matches']))} unverified CVE matches.</p><p class=\"warning\">No findings do not prove that a device is secure.</p>")
    parts.append(f"<h2>Authorized assessment scope</h2><p>{e(str(assessment.get('name') or 'Authorized target'))} — {e(str(assessment.get('target')))} ({e(str(assessment.get('scope_type')))})</p>")
    scan_observations = report.get("scan_metadata", {}).get("observations", [])
    parts.append("<h2>Stored scan observations</h2>" + _html_table([["Device ID", "Latest observation", "Sources"]] + [[row.get("device_id"), row.get("latest_observed_at"), ", ".join(row.get("sources", []))] for row in scan_observations] if scan_observations else [["No stored scan observations", "", ""]]))
    parts.append("<p>No persisted scan session is available.</p>" if not report.get("scan_metadata", {}).get("persisted_session") else "<p>Persisted scan session metadata is available.</p>")
    parts.append("<h2>Discovered assets, ports and services</h2>")
    if not report["devices"]:
        parts.append("<p>No assets were present in the stored assessment snapshot.</p>")
    else:
        parts.append(_html_table([["IP address", "Device", "Current status", "Ports", "Services", "Findings"]] + [
            [item["device"].get("ip_address"), item["device"].get("hostname") or item["device"].get("vendor") or "Unknown device",
             item["device"].get("status") or "Unavailable", len(item["ports"]), len(item["services"]), len(item["findings"])]
            for item in report["devices"]]))
    for item in report["devices"]:
        device = item["device"]
        parts.append(f"<article><h3>{e(str(device.get('ip_address') or 'Unknown IP'))} — {e(str(device.get('hostname') or device.get('vendor') or 'Unknown device'))}</h3><p>Status: {e(str(device.get('status') or 'Unavailable'))}</p>")
        service_by_port = {service.get("port_id"): service for service in item["services"]}
        port_rows = [["Port / transport", "State", "Service", "Product / version"]] + [
            [f"{port.get('port_number')}/{port.get('transport')}", port.get("state"),
             service_by_port.get(port["id"], {}).get("service_name"),
             " ".join(filter(None, [service_by_port.get(port["id"], {}).get("product"), service_by_port.get(port["id"], {}).get("version")]))]
            for port in item["ports"]]
        if item["ports"]:
            parts.append(_html_table(port_rows))
        elif item["services"]:
            parts.append(_html_table([["Service", "Product", "Version", "Confidence"]] + [
                [service.get("service_name"), service.get("product"), service.get("version"), service.get("confidence")]
                for service in item["services"]]))
        else:
            parts.append("<p>No recorded port or service observations. Service coverage is incomplete.</p>")
        if item["ports"] and not item["services"]:
            parts.append("<p>No service evidence is stored for this asset.</p>")
        http_tls_rows = _http_tls_observation_rows(item)
        if http_tls_rows:
            parts.append("<h4>HTTP/TLS endpoint observations</h4>" + _html_table(
                [["Endpoint", "Observed", "Outcome / HTTP", "TLS", "Run / target"]] + http_tls_rows))
        if item.get("truncation", {}).get("http_tls_observations"):
            parts.append("<p>HTTP/TLS observations are truncated; this section does not show the complete stored history.</p>")
        if item["findings"]:
            service_names = {service["id"]: " ".join(filter(None, [service.get("service_name"), service.get("product"), service.get("version")])) for service in item["services"]}
            parts.append("<h4>Security findings</h4>" + _html_table([["Title","Severity","Status","Verification","Service","Evidence type / description"]] + [[x.get("title"),x.get("severity"),x.get("finding_status"),x.get("verification_status"),service_names.get(x.get("service_id"),x.get("service_id")),f"{x.get('evidence_type')}: {x.get('description')}"] for x in item["findings"]]))
            for finding in item["findings"]:
                linked = [evidence for evidence in item["evidence"] if evidence.get("finding_id") == finding["id"]]
                if linked:
                    parts.append(f"<h5>Evidence linked to: {e(str(finding.get('title')))}</h5>" + _html_render_evidence(linked, images))
        if item["cve_matches"]:
            parts.append("<h4>CVE matches and verification status</h4>" + _html_table([["CVE","Match status","Verification","Confidence","Service ID","Finding ID","Evidence and intelligence"]] + [[x.get("cve_id"),x.get("match_status"),x.get("verification_status", "UNVERIFIED"),x.get("confidence"),x.get("service_id"),x.get("finding_id"),_cve_intelligence_summary(x)] for x in item["cve_matches"]]))
        if item["evidence"]:
            visible_findings = {finding["id"] for finding in item["findings"]}
            general = [evidence for evidence in item["evidence"]
                       if evidence.get("finding_id") is None or evidence.get("finding_id") not in visible_findings]
            if general:
                parts.append("<h4>Device screenshots and evidence</h4>" + _html_render_evidence(general, images))
        parts.append("</article>")
    parts.append("<h2>Recommendations</h2><ul>")
    parts.extend(f"<li>{e(str(item))}</li>" for item in report["recommendations"])
    if not report["recommendations"]:
        parts.append("<li>No finding-backed remediation recommendations are recorded.</li>")
    parts.append("</ul><h2>Coverage and limitations</h2>" + _html_table([[key.replace("_"," ").title(), value] for key,value in coverage.items() if key != "limitations"]))
    parts.append("<ul>" + "".join(f"<li>{e(str(item))}</li>" for item in coverage.get("limitations", [])) + "</ul><h2>Conclusion</h2><p>This report reflects stored evidence available at generation time. Missing scan or service evidence limits conclusions; absence of findings is not assurance of security.</p></body></html>")
    return _bounded_output("".join(parts).encode("utf-8"))


def _valid_image(data):
    if len(data) > MAX_IMAGE_BYTES:
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        offset = 8
        dimensions = None
        has_image_data = False
        while offset + 12 <= len(data):
            size = struct.unpack(">I", data[offset:offset + 4])[0]
            end = offset + 12 + size
            if end > len(data):
                return None
            kind = data[offset + 4:offset + 8]
            payload = data[offset + 8:offset + 8 + size]
            checksum = struct.unpack(">I", data[offset + 8 + size:end])[0]
            if zlib.crc32(kind + payload) & 0xFFFFFFFF != checksum:
                return None
            if kind == b"IHDR" and size == 13 and dimensions is None:
                dimensions = struct.unpack(">II", payload[:8])
            elif kind == b"IDAT":
                has_image_data = True
            elif kind == b"IEND":
                if size != 0 or end != len(data) or dimensions is None or not has_image_data:
                    return None
                width, height = dimensions
                return "image/png" if 0 < width * height <= MAX_IMAGE_PIXELS else None
            offset = end
        return None
    if data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9"):
        dimensions = _jpeg_dimensions(data)
        if dimensions and 0 < dimensions[0] * dimensions[1] <= MAX_IMAGE_PIXELS:
            return "image/jpeg"
    return None


def _jpeg_dimensions(data):
    offset = 2
    frame_markers = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            return None
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return None
        marker = data[offset]
        offset += 1
        if marker in {0xD8, 0xD9, 0x01} or 0xD0 <= marker <= 0xD7:
            if marker == 0xD9:
                return None
            continue
        if offset + 2 > len(data):
            return None
        size = struct.unpack(">H", data[offset:offset + 2])[0]
        if size < 2 or offset + size > len(data):
            return None
        if marker in frame_markers:
            if size < 7:
                return None
            height, width = struct.unpack(">HH", data[offset + 3:offset + 7])
            return width, height
        if marker == 0xDA:
            return None
        offset += size
    return None


def _bounded_output(data):
    if len(data) > MAX_OUTPUT_BYTES:
        raise ReportOutputLimitError("The report exceeds the export size limit.")
    return data


def _http_tls_observation_rows(device_report):
    rows = []
    for observation in device_report.get("http_tls_observations", []):
        tls = observation.get("tls") or {}
        tls_facts = [tls.get("verification_status") or "Not applicable"]
        if tls.get("verification_status") == "VERIFIED":
            tls_facts.extend(filter(None, [tls.get("protocol_version")]))
            cipher = tls.get("cipher") or {}
            if cipher.get("name"):
                tls_facts.append(f"Cipher {cipher['name']} ({cipher.get('bits')} bits)")
            for label, key in (("Subject", "certificate_subject"), ("Issuer", "certificate_issuer")):
                entries = tls.get(key) or []
                if entries:
                    tls_facts.append(label + ": " + ", ".join(
                        f"{entry.get('name')}: {entry.get('value')}" for entry in entries[:8]
                    ))
            validity = " — ".join(filter(None, [tls.get("not_before"), tls.get("not_after")]))
            if validity:
                tls_facts.append("Validity " + validity)
            sans = tls.get("subject_alt_names") or []
            if sans:
                tls_facts.append("SAN " + ", ".join(
                    f"{entry.get('type')}: {entry.get('value')}" for entry in sans[:8]
                ))
            if tls.get("sha256_fingerprint"):
                tls_facts.append("SHA-256 " + tls["sha256_fingerprint"])
        elif tls.get("verification_status") in {"FAILED", "NOT_COMPLETED"} and tls.get("error_category"):
            tls_facts[0] = "Verification failed" if tls.get("verification_status") == "FAILED" else "Handshake not completed"
            tls_facts.append(tls["error_category"])
        tls_summary = "; ".join(tls_facts)
        endpoint_host = observation.get("approved_hostname") or observation.get("target_ip")
        endpoint = (f"Observation {observation.get('id')}; {observation.get('scheme')}://"
                    f"{endpoint_host}:{observation.get('port_number')}/tcp")
        outcome = observation.get("outcome") or "Unknown"
        if observation.get("status_code") is not None:
            outcome += f" / HTTP {observation['status_code']}"
        if observation.get("error_category"):
            outcome += f" ({observation['error_category']})"
        http_facts = []
        if observation.get("content_type"):
            http_facts.append("Content-Type " + observation["content_type"])
        if observation.get("content_length") is not None:
            http_facts.append("Declared length " + str(observation["content_length"]))
        headers = observation.get("response_headers") or {}
        http_facts.extend(f"{name}: {value}" for name, value in sorted(headers.items()))
        server = observation.get("server_identifier")
        if server:
            http_facts.append(f"Server (self-reported, low confidence): {server.get('value')}")
        if observation.get("redirect_location"):
            http_facts.append("Redirect observed: " + observation["redirect_location"])
        if observation.get("error_category"):
            http_facts.append("Error: " + observation["error_category"])
        run = observation.get("scan") or {}
        provenance = (f"Run {run.get('run_id')}; target {run.get('target_id')} / "
                      f"{run.get('target_outcome')}; {run.get('scanner')} / {run.get('profile')}")
        rows.append([endpoint, observation.get("observed_at"), outcome,
                     "; ".join(http_facts) or "No response metadata", tls_summary + "; " + provenance])
    return rows


def _pdf_wrap_long_tokens(value, width=28):
    parts = []
    for token in str(value if value is not None else "-").split(" "):
        if len(token) > width:
            token = " ".join(token[index:index + width] for index in range(0, len(token), width))
        parts.append(token)
    return " ".join(parts)


def _escape(value):
    from xml.sax.saxutils import escape
    return escape("-" if value is None else str(value))


def _pdf_table(rows, style):
    return _pdf_data_table([[key, value] for key, value in rows], style)


def _pdf_data_table(rows, style):
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    column_count = max(len(row) for row in rows)
    table = Table([[Paragraph(_escape(cell), style) for cell in row] for row in rows],
                  colWidths=[178*mm/column_count] * column_count, repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#dce7f1")),
                               ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor("#12345a")),
                               ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#9aabba")),
                               ("VALIGN", (0,0), (-1,-1), "TOP"),
                               ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f8fb")]),
                               ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4)]))
    return [table, Spacer(1, 3*mm)]


def _pdf_render_evidence(story, evidence_rows, images, style, mm):
    from reportlab.platypus import Image, Paragraph

    for evidence in evidence_rows:
        story.append(Paragraph(_escape(
            f"{evidence.get('description')} — {evidence.get('filename')} — {evidence.get('media_type')} — "
            f"uploaded {evidence.get('created_at')} — evidence #{evidence.get('id')} — "
            f"finding {evidence.get('finding_id') or 'not linked'}"), style))
        image = images.get(evidence["id"])
        if image:
            story.append(Image(io.BytesIO(image["data"]), width=90*mm, height=55*mm, kind="proportional"))
        else:
            story.append(Paragraph("Image not embedded (missing or export size limit reached).", style))


def _pdf_page_number(canvas, document):
    from reportlab.lib.units import mm

    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColorRGB(.25,.34,.42)
    canvas.drawRightString(195*mm, 9*mm, f"SentinelIP · Page {document.page}")
    canvas.restoreState()


def _cve_intelligence_summary(match):
    parts = [match.get("match_reason") or "No correlation explanation recorded."]
    manual = match.get("manual_verification")
    if isinstance(manual, dict):
        parts.append(f"Manual verification recorded {manual.get('verified_at') or 'date unavailable'}: {manual.get('evidence') or 'evidence unavailable'}.")
    intel = match.get("intelligence") or {}
    data = intel.get("intelligence") or {}
    parts.append(f"Version assessment: {intel.get('version_match', 'UNAVAILABLE')}.")
    if data.get("vulnerability_status"):
        parts.append(f"NVD vulnerability status: {data['vulnerability_status']}.")
    cvss = data.get("cvss")
    if isinstance(cvss, dict) and cvss.get("score") is not None:
        parts.append(f"CVSS {cvss['score']} v{cvss.get('version') or 'unknown'}; source {cvss.get('source') or 'not recorded'}; vector {cvss.get('vector') or 'not recorded'}.")
    else:
        parts.append("CVSS unavailable.")
    epss = data.get("epss")
    if isinstance(epss, dict) and epss.get("probability") is not None:
        parts.append(f"EPSS probability {epss['probability']}; percentile {epss.get('percentile') if epss.get('percentile') is not None else 'unavailable'}; observed {epss.get('observed_at') or 'date unavailable'}.")
    else:
        parts.append("EPSS unavailable.")
    kev = data.get("kev")
    kev_timestamps = intel.get("source_timestamps", {}).get("cisa_kev", {})
    catalog_released = kev_timestamps.get("catalog_released_at")
    if isinstance(kev, dict) and kev.get("member") is True:
        parts.append(f"CISA KEV listed; added {kev.get('date_added') or 'date unavailable'}; due {kev.get('due_date') or 'date unavailable'}; catalog released {catalog_released or 'date unavailable'}.")
    elif isinstance(kev, dict) and kev.get("member") is False:
        parts.append(f"Not listed in cached CISA KEV catalog released {catalog_released or 'date unavailable'}.")
    else:
        parts.append("CISA KEV status unavailable.")
    cwes = data.get("cwes") or []
    if cwes:
        parts.append("CWE: " + ", ".join(str(item) for item in cwes[:10]) + ".")
    affected = data.get("affected_products") or []
    affected_names = []
    for item in affected[:3]:
        if isinstance(item, dict):
            label = " ".join(filter(None, [item.get("vendor"), item.get("product"), item.get("cpe")]))
            bounds = [f"{key} {item[key]}" for key in ("version_start_including", "version_start_excluding",
                      "version_end_including", "version_end_excluding") if item.get(key)]
            if bounds:
                label = " ".join(filter(None, [label, ", ".join(bounds)]))
            if label:
                affected_names.append(label[:300])
    if affected_names:
        parts.append("Affected product evidence: " + "; ".join(affected_names) + ".")
    references = data.get("advisories") or []
    urls = [item.get("url") for item in references[:3] if isinstance(item, dict) and item.get("url")]
    if urls:
        parts.append("References: " + "; ".join(str(url)[:300] for url in urls) + ".")
    statuses = intel.get("source_status") or {}
    if statuses:
        parts.append("Source states: " + ", ".join(f"{source} {state}" for source, state in sorted(statuses.items())) + ".")
    parts.append(f"Intelligence freshness: {intel.get('freshness', 'UNAVAILABLE')}.")
    return " ".join(parts)


def _docx_table(document, rows):
    if not rows:
        return
    width = max(len(row) for row in rows)
    table = document.add_table(rows=0, cols=width)
    table.style = "Light Shading Accent 1"
    for row in rows:
        cells = table.add_row().cells
        for index, cell in enumerate(cells):
            value = row[index] if index < len(row) else ""
            cell.text = "-" if value is None else str(value)


def _docx_render_evidence(document, evidence_rows, images):
    from docx.shared import Inches

    for evidence in evidence_rows:
        document.add_paragraph(
            f"{evidence.get('description')} — {evidence.get('filename')} — {evidence.get('media_type')} — "
            f"uploaded {evidence.get('created_at')} — evidence #{evidence.get('id')} — "
            f"finding {evidence.get('finding_id') or 'not linked'}"
        )
        image = images.get(evidence["id"])
        if image:
            document.add_picture(io.BytesIO(image["data"]), width=Inches(4.5))
        else:
            document.add_paragraph("Image not embedded (missing or export size limit reached).")


def _html_rows(rows):
    return "".join(f"<tr><th>{html.escape(str(key))}</th><td>{html.escape('-' if value is None else str(value))}</td></tr>" for key,value in rows)


def _html_table(rows):
    if not rows:
        return ""
    head = "<thead><tr>" + "".join(f"<th>{html.escape(str(value))}</th>" for value in rows[0]) + "</tr></thead>"
    body = "<tbody>" + "".join("<tr>" + "".join(f"<td>{html.escape('-' if value is None else str(value))}</td>" for value in row) + "</tr>" for row in rows[1:]) + "</tbody>"
    return "<table>" + head + body + "</table>"


def _html_render_evidence(evidence_rows, images):
    parts = []
    for evidence in evidence_rows:
        parts.append(
            f"<p>{html.escape(str(evidence.get('description')))} — {html.escape(str(evidence.get('filename')))} — "
            f"{html.escape(str(evidence.get('media_type')))} — uploaded {html.escape(str(evidence.get('created_at')))} — "
            f"evidence #{html.escape(str(evidence.get('id')))} — finding "
            f"{html.escape(str(evidence.get('finding_id') or 'not linked'))}</p>"
        )
        image = images.get(evidence["id"])
        if image:
            data = base64.b64encode(image["data"]).decode("ascii")
            parts.append(f"<img src=\"data:{html.escape(image['media_type'])};base64,{data}\" alt=\"{html.escape(str(evidence.get('description')))}\">")
        else:
            parts.append("<p>Image not embedded (missing or export size limit reached).</p>")
    return "".join(parts)
