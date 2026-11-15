import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import Response

from api.remote_sensors import local_management
from database.db import get_connection
from services.recon_assessment_exports import (
    DOCX_MIME,
    HTML_CSP,
    HTML_MIME,
    PDF_MIME,
    ReportOutputLimitError,
    load_export_images,
    render_assessment_docx,
    render_assessment_html,
    render_assessment_pdf,
)
from services.vulnerability_intelligence import project_cached_intelligence

REPORT_SCHEMA_VERSION = "1.0"
MAX_DEVICES = 100
MAX_PORTS = 50
MAX_SERVICES = 50
MAX_FINDINGS = 25
MAX_CVE_MATCHES = 50
MAX_EVIDENCE = 20
MAX_REPORT_BYTES = 15_728_640


def register_recon_assessment_report_routes(app: FastAPI, db_path_provider: Callable):
    @app.get("/recon/scopes/{scope_id}/assessment-report", dependencies=[Depends(local_management)])
    def get_assessment_report(scope_id: int):
        return _bounded_assessment_report(scope_id, db_path_provider())

    def export(scope_id, renderer, media_type, extension):
        path = db_path_provider()
        report = _bounded_assessment_report(scope_id, path)
        images = load_export_images(report, path)
        try:
            body = renderer(report, images)
        except ReportOutputLimitError as exc:
            raise HTTPException(413, str(exc)) from exc
        headers = {
            "Content-Disposition": f'attachment; filename="sentinelip-assessment-{scope_id}-{report["report_id"]}.{extension}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
        if extension == "html":
            headers["Content-Security-Policy"] = HTML_CSP
        return Response(content=body, media_type=media_type, headers=headers)

    @app.get("/recon/scopes/{scope_id}/assessment-report/pdf", dependencies=[Depends(local_management)])
    def get_assessment_report_pdf(scope_id: int):
        return export(scope_id, render_assessment_pdf, PDF_MIME, "pdf")

    @app.get("/recon/scopes/{scope_id}/assessment-report/docx", dependencies=[Depends(local_management)])
    def get_assessment_report_docx(scope_id: int):
        return export(scope_id, render_assessment_docx, DOCX_MIME, "docx")

    @app.get("/recon/scopes/{scope_id}/assessment-report/html", dependencies=[Depends(local_management)])
    def get_assessment_report_html(scope_id: int):
        return export(scope_id, render_assessment_html, HTML_MIME, "html")


def _bounded_assessment_report(scope_id, db_path):
    report = build_assessment_report(scope_id, db_path)
    if len(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_REPORT_BYTES:
        raise HTTPException(413, "Assessment report exceeds the configured output limit.")
    return report


def build_assessment_report(scope_id: int, db_path: str):
    if scope_id <= 0:
        raise HTTPException(422, "Scope identifier must be positive.")
    path = db_path
    if not Path(path).is_file():
        raise HTTPException(404, "Assessment data is unavailable.")
    try:
        connection = get_connection(path)
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(404, "Assessment data is unavailable.") from exc
    with connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        scope = connection.execute(
            """SELECT s.*, l.network_id FROM authorized_scopes s
               LEFT JOIN network_scope_links l ON l.scope_id=s.id WHERE s.id=?""",
            (scope_id,),
        ).fetchone()
        if scope is None:
            raise HTTPException(404, "Authorized target not found.")
        if (scope["authorized"] != 1 or scope["enabled"] != 1
                or not scope["authorization_confirmed_at"]
                or not scope["authorization_confirmation_version"]
                or not scope["authorization_source"]):
            raise HTTPException(403, "An authorized, enabled target is required.")
        if scope["scope_type"] == "PRIVATE_NETWORK" and scope["network_id"] is None:
            raise HTTPException(403, "The private network is not linked to this target.")
        if scope["scope_type"] == "PRIVATE_NETWORK":
            devices = connection.execute(
                "SELECT * FROM devices WHERE network_id=? ORDER BY id LIMIT ?",
                (scope["network_id"], MAX_DEVICES + 1),
            ).fetchall()
        elif scope["scope_type"] == "PUBLIC_IPV4":
            devices = connection.execute(
                """SELECT * FROM devices WHERE scope_id=? AND network_id IS NULL
                   AND last_ip_address=? ORDER BY id LIMIT ?""",
                (scope_id, scope["canonical_target"], MAX_DEVICES + 1),
            ).fetchall()
        elif scope["scope_type"] == "PUBLIC_CIDR":
            devices = connection.execute(
                """SELECT d.* FROM devices d WHERE d.scope_id=? AND d.network_id IS NULL
                   AND EXISTS (SELECT 1 FROM scope_cidr_addresses a WHERE a.scope_id=?
                     AND a.canonical_cidr=? AND a.ipv4_address=d.last_ip_address)
                   ORDER BY d.id LIMIT ?""",
                (scope_id, scope_id, scope["canonical_target"], MAX_DEVICES + 1),
            ).fetchall()
        elif scope["scope_type"] == "HOSTNAME":
            devices = connection.execute(
                """SELECT d.* FROM devices d WHERE d.scope_id=? AND d.network_id IS NULL
                   AND EXISTS (SELECT 1 FROM scope_hostname_addresses a WHERE a.scope_id=?
                     AND a.ipv4_address=d.last_ip_address AND a.approved=1)
                   ORDER BY d.id LIMIT ?""",
                (scope_id, scope_id, MAX_DEVICES + 1),
            ).fetchall()
        else:
            raise HTTPException(403, "Unsupported authorized target type.")
        truncated = len(devices) > MAX_DEVICES
        devices = devices[:MAX_DEVICES]
        result_devices = []
        all_findings = []
        scan_evidence = []
        services_scanned = 0
        assets_without_services = 0
        unverified_cves = 0
        manually_verified_cves = 0
        for device in devices:
            device_id = device["id"]
            ports = connection.execute(
                "SELECT id,port_number,transport,state,first_seen,last_seen FROM ports WHERE device_id=? ORDER BY port_number,transport LIMIT ?",
                (device_id, MAX_PORTS + 1),
            ).fetchall()
            services = connection.execute(
                """SELECT id,port_id,service_name,product,version,extra_info,confidence,first_seen,last_seen
                   FROM services WHERE device_id=? ORDER BY port_id LIMIT ?""",
                (device_id, MAX_SERVICES + 1),
            ).fetchall()
            ports_truncated = len(ports) > MAX_PORTS
            services_truncated = len(services) > MAX_SERVICES
            ports = ports[:MAX_PORTS]
            services = services[:MAX_SERVICES]
            if services:
                services_scanned += 1
            else:
                assets_without_services += 1
            observations = connection.execute(
                """SELECT observed_at,source FROM port_observations WHERE device_id=?
                   ORDER BY observed_at DESC,id DESC LIMIT 50""",
                (device_id,),
            ).fetchall()
            inventory_observations = connection.execute(
                "SELECT observed_at,source FROM device_observations WHERE device_id=? ORDER BY observed_at DESC,id DESC LIMIT 50",
                (device_id,),
            ).fetchall() if scope["scope_type"] == "PRIVATE_NETWORK" else connection.execute(
                "SELECT observed_at,source FROM scope_device_observations WHERE scope_id=? AND device_id=? ORDER BY observed_at DESC,id DESC LIMIT 50",
                (scope_id, device_id),
            ).fetchall()
            observation_rows = list(observations) + list(inventory_observations)
            if observation_rows:
                latest_observation = max(observation_rows, key=lambda row: row["observed_at"])
                scan_evidence.append({"device_id": device_id,
                                      "latest_observed_at": latest_observation["observed_at"],
                                      "sources": list(dict.fromkeys(_bounded_text(row["source"], 128) for row in observation_rows))})
            findings = connection.execute(
                """SELECT id,title,reason,severity,confidence,status,recommendation,evidence_type,source,
                          rule_id,rule_version,port_id,service_id,first_seen,last_seen
                   FROM findings WHERE device_id=? ORDER BY id LIMIT ?""",
                (device_id, MAX_FINDINGS + 1),
            ).fetchall()
            findings_truncated = len(findings) > MAX_FINDINGS
            findings = findings[:MAX_FINDINGS]
            for finding in findings:
                value = _bounded_row(finding, {"title": 500, "reason": 2000, "recommendation": 2000,
                                               "evidence_type": 128, "source": 128, "rule_id": 128,
                                               "rule_version": 64, "severity": 32, "confidence": 32,
                                               "status": 32})
                value["description"] = value.pop("reason")
                value["finding_status"] = value.pop("status")
                value["verification_status"] = "NOT_RECORDED"
                all_findings.append(value)
            intelligence_columns = (
                "ci.intelligence_json,ci.source_status_json,ci.source_timestamps_json,ci.fetched_at"
                if _table_exists(connection, "cve_intelligence")
                else "NULL AS intelligence_json,NULL AS source_status_json,NULL AS source_timestamps_json,NULL AS fetched_at"
            )
            intelligence_join = "LEFT JOIN cve_intelligence ci ON ci.cve_id=r.cve_id" if _table_exists(connection, "cve_intelligence") else ""
            cves = connection.execute(
                f"""SELECT m.id,r.cve_id,m.status AS match_status,m.confidence,m.match_reason,
                          m.service_id,m.finding_id,m.observed_product,m.observed_version,
                          m.metadata_json AS match_metadata_json,r.source,r.product,r.vendor,
                          r.version_expression,{intelligence_columns}
                   FROM cve_matches m JOIN cve_records r ON r.id=m.cve_record_id {intelligence_join}
                   WHERE m.device_id=? ORDER BY m.id LIMIT ?""",
                (device_id, MAX_CVE_MATCHES + 1),
            ).fetchall()
            cves_truncated = len(cves) > MAX_CVE_MATCHES
            cves = cves[:MAX_CVE_MATCHES]
            cve_projection = []
            for match in cves:
                value = _bounded_row(match, {"cve_id": 32, "match_status": 32, "confidence": 32,
                                              "match_reason": 1000, "observed_product": 255,
                                              "observed_version": 128, "source": 255,
                                              "product": 255, "vendor": 255,
                                              "version_expression": 500})
                try:
                    match_metadata = json.loads(match["match_metadata_json"]) if match["match_metadata_json"] else None
                except (TypeError, json.JSONDecodeError):
                    match_metadata = None
                value.pop("match_metadata_json", None)
                try:
                    cached_intelligence = ({
                        "cve_id": match["cve_id"],
                        "intelligence": json.loads(match["intelligence_json"]),
                        "source_status": json.loads(match["source_status_json"]),
                        "source_timestamps": json.loads(match["source_timestamps_json"]),
                        "fetched_at": match["fetched_at"],
                    } if match["intelligence_json"] else None)
                except (TypeError, json.JSONDecodeError):
                    cached_intelligence = None
                value["intelligence"] = project_cached_intelligence(
                    cached_intelligence, match["match_status"], match["confidence"],
                    match["observed_product"], match["observed_version"],
                    match["match_reason"], match_metadata,
                )
                value["verification_status"] = (
                    value["intelligence"]["version_match"]
                    if match["match_status"] == "CONFIRMED_ISSUE"
                    else "UNVERIFIED"
                )
                manual_verification = match_metadata.get("manual_verification") if isinstance(match_metadata, dict) else None
                if value["verification_status"] == "MANUALLY_VERIFIED" and isinstance(manual_verification, dict):
                    value["manual_verification"] = {
                        "verified_at": _bounded_text(manual_verification.get("verified_at"), 64),
                        "verified_by": _bounded_text(manual_verification.get("verified_by"), 128),
                        "evidence": _bounded_text(manual_verification.get("evidence"), 2000),
                    }
                    manually_verified_cves += 1
                else:
                    unverified_cves += 1
                cve_projection.append(value)
            evidence = connection.execute(
                """SELECT id,device_id,finding_id,description,filename,media_type,created_at
                       FROM recon_evidence WHERE device_id=? AND (finding_id IS NULL OR finding_id IN
                         (SELECT id FROM findings WHERE device_id=?)) ORDER BY id DESC LIMIT ?""",
                    (device_id, device_id, MAX_EVIDENCE + 1),
            ).fetchall() if _table_exists(connection, "recon_evidence") else []
            evidence_truncated = len(evidence) > MAX_EVIDENCE
            evidence = evidence[:MAX_EVIDENCE]
            result_devices.append({
                "device": {"id": device_id, "ip_address": _bounded_text(device["last_ip_address"], 64),
                           "hostname": _bounded_text(device["hostname"], 255),
                           "vendor": _bounded_text(device["vendor"], 255), "status": _bounded_text(device["status"], 32)},
                "ports": [_bounded_row(row, {"transport": 32, "state": 32}) for row in ports],
                "services": [_bounded_row(row, {"service_name": 255, "product": 255, "version": 255,
                                                   "extra_info": 1000, "confidence": 32}) for row in services],
                "findings": [_finding_projection(row) for row in findings],
                "cve_matches": cve_projection,
                "evidence": [_bounded_row(row, {"description": 500, "filename": 160, "media_type": 64,
                                                   "created_at": 64}) for row in evidence],
                "truncation": {"ports": ports_truncated, "services": services_truncated,
                               "findings": findings_truncated, "cve_matches": cves_truncated,
                               "evidence": evidence_truncated},
            })
        generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "report_id": str(uuid4()),
            "generated_at": generated_at,
            "snapshot_kind": "generated_report_snapshot",
            "historical_scan_session": False,
                "assessment": {"scope_id": scope_id, "target": _bounded_text(scope["canonical_target"], 255),
                               "scope_type": scope["scope_type"], "name": _bounded_text(scope["name"], 255),
                           "assessment_type": "authorized_network_assessment"},
            "scan_metadata": {"available": bool(scan_evidence), "persisted_session": False,
                              "observations": scan_evidence,
                                  "message": ("Stored observations are included." if scan_evidence else "No stored scan observations are available.")
                                             + " No persisted assessment session record is available."},
            "devices": result_devices,
            "findings": all_findings[:MAX_DEVICES * MAX_FINDINGS],
            "recommendations": list(dict.fromkeys(
                f["recommendation"] for f in all_findings if f.get("recommendation")
            )),
            "coverage": {"discovered_assets": len(result_devices),
                         "assets_with_service_evidence": services_scanned,
                         "assets_without_service_evidence": assets_without_services,
                         "potential_vulnerabilities": len(all_findings) + unverified_cves,
                         "confirmed_findings": sum(1 for x in all_findings if str(x["verification_status"]).upper() in {"CONFIRMED", "VERIFIED"}),
                         "manually_verified_cve_matches": manually_verified_cves,
                         "unverified_cve_matches": unverified_cves,
                         "data_incomplete": truncated or any(any(d["truncation"].values()) for d in result_devices),
                         "limitations": ["No findings does not prove that a device is secure.",
                                         "CVE matches are leads and are not confirmed vulnerabilities.",
                                         "Scan history is unavailable without a persisted assessment session."]},
            "truncation": {"devices": truncated},
        }

def _table_exists(connection, name):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _bounded_text(value, limit):
    return value[:limit] if isinstance(value, str) else value


def _bounded_row(row, limits):
    result = dict(row)
    for field, limit in limits.items():
        result[field] = _bounded_text(result.get(field), limit)
    return result


def _finding_projection(row):
    result = _bounded_row(row, {"title": 500, "reason": 2000, "recommendation": 2000,
                                "evidence_type": 128, "source": 128, "rule_id": 128,
                                "rule_version": 64, "severity": 32, "confidence": 32,
                                "status": 32})
    result["finding_status"] = result.pop("status")
    result["verification_status"] = "NOT_RECORDED"
    return result
