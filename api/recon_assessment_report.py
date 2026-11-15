import json
import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
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
MAX_HTTP_TLS_OBSERVATIONS_PER_DEVICE = 20
MAX_HTTP_TLS_OBSERVATIONS_PER_REPORT = 200
MAX_HTTP_TLS_METADATA_BYTES = 8_192
MAX_HTTP_TLS_CERTIFICATE_ENTRIES = 8


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
        endpoint_observations, endpoint_truncation = _http_tls_report_observations(
            connection, scope, [device["id"] for device in devices]
        )
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
            device_report = {
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
            }
            observations = endpoint_observations.get(device_id, [])
            observation_truncated = endpoint_truncation.get(device_id, False)
            if observations or observation_truncated:
                device_report["http_tls_observations"] = observations
                device_report["truncation"]["http_tls_observations"] = observation_truncated
            result_devices.append(device_report)
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


def _http_tls_report_observations(connection, scope, device_ids):
    if not device_ids or not _table_exists(connection, "http_endpoint_observations"):
        return {}, {}
    placeholders = ",".join("?" for _ in device_ids)
    rows = connection.execute(
        f"""WITH eligible AS (
                SELECT e.id,e.scope_id,e.device_id,e.port_id,p.port_number,e.scheme,e.target_ip,
                       e.approved_hostname,e.observed_at,e.source,e.outcome,e.error_category,
                       e.status_code,e.response_headers_json,e.content_type,e.content_length,
                       e.server_identifier,e.redirect_location,e.scan_target_id,
                       r.id AS scan_run_id,r.profile,r.scanner,r.scanner_version,r.status AS run_status,
                       t.outcome AS target_outcome,t.error_category AS target_error_category,
                       tls.verification_status,tls.hostname_verification,tls.ip_address_verification,
                       tls.verification_name,tls.protocol_version,tls.cipher_name,tls.cipher_protocol,
                       tls.cipher_bits,tls.certificate_subject_json,tls.certificate_issuer_json,
                       tls.not_before,tls.not_after,tls.subject_alt_names_json,tls.sha256_fingerprint,
                       tls.error_category AS tls_error_category,
                       ROW_NUMBER() OVER (PARTITION BY e.device_id ORDER BY e.observed_at DESC,e.id DESC) AS device_rank,
                       COUNT(*) OVER (PARTITION BY e.device_id) AS device_total
                FROM http_endpoint_observations e
                JOIN devices d ON d.id=e.device_id
                JOIN ports p ON p.id=e.port_id AND p.device_id=e.device_id
                JOIN recon_scan_targets t ON t.id=e.scan_target_id AND t.device_id=e.device_id
                  AND t.target_ip=e.target_ip
                JOIN recon_scan_runs r ON r.id=t.run_id AND r.scope_id=e.scope_id
                  AND r.profile='http_endpoint_fingerprint'
                LEFT JOIN http_tls_observations tls ON tls.endpoint_observation_id=e.id
                WHERE e.scope_id=? AND e.device_id IN ({placeholders}) AND lower(p.transport)='tcp'
                  AND d.last_ip_address=e.target_ip
                  AND EXISTS (SELECT 1 FROM port_observations po WHERE po.device_id=e.device_id
                    AND po.port_id=e.port_id AND po.ip_address=e.target_ip
                    AND lower(po.transport)='tcp' AND lower(po.state)='open')
                  AND ((?='HOSTNAME' AND e.approved_hostname=?)
                    OR (?!='HOSTNAME' AND e.approved_hostname IS NULL))
            ), limited AS (
                SELECT * FROM eligible WHERE device_rank<=?
            )
            SELECT * FROM limited ORDER BY observed_at DESC,id DESC LIMIT ?""",
        (scope["id"], *device_ids, scope["scope_type"], scope["canonical_target"], scope["scope_type"],
         MAX_HTTP_TLS_OBSERVATIONS_PER_DEVICE + 1,
         MAX_DEVICES * (MAX_HTTP_TLS_OBSERVATIONS_PER_DEVICE + 1)),
    ).fetchall()
    candidates = []
    totals = {}
    for row in rows:
        totals[row["device_id"]] = row["device_total"]
        candidates.append(_http_tls_observation_projection(row))
    truncation = {device_id: totals.get(device_id, 0) > 0 for device_id in device_ids}
    candidates = candidates[:MAX_HTTP_TLS_OBSERVATIONS_PER_REPORT]
    projected = {device_id: [] for device_id in device_ids}
    for item in candidates:
        device_id = item["device_id"]
        if len(projected[device_id]) < MAX_HTTP_TLS_OBSERVATIONS_PER_DEVICE:
            projected[device_id].append(item)
    for device_id in device_ids:
        selected = len(projected[device_id])
        truncation[device_id] = totals.get(device_id, 0) > selected
    return projected, truncation


def _http_tls_observation_projection(row):
    def text(field, limit, nullable=False):
        value = row[field]
        if value is None and nullable:
            return None
        if (not isinstance(value, str) or len(value.encode("utf-8")) > limit
                or any(ord(character) < 32 or ord(character) == 127 for character in value)):
            raise ValueError(f"Stored endpoint report field {field} exceeds its limit.")
        return value

    def json_value(field, byte_limit, expected_type):
        value = text(field, byte_limit, nullable=True)
        if value is None or len(value.encode("utf-8")) > MAX_HTTP_TLS_METADATA_BYTES:
            raise ValueError(f"Stored endpoint report metadata {field} exceeds its limit.")
        parsed = json.loads(value)
        if not isinstance(parsed, expected_type):
            raise ValueError(f"Stored endpoint report metadata {field} is invalid.")
        return parsed

    headers = json_value("response_headers_json", MAX_HTTP_TLS_METADATA_BYTES, dict)
    allowed_headers = {"date", "cache-control", "strict-transport-security", "x-content-type-options",
                       "x-frame-options", "content-security-policy", "referrer-policy", "permissions-policy"}
    if set(headers) - allowed_headers or len(headers) > len(allowed_headers):
        raise ValueError("Stored endpoint report headers are invalid.")
    for name, value in headers.items():
        if (not isinstance(name, str) or not isinstance(value, str) or len(value.encode("utf-8")) > 512
                or any(ord(character) < 32 or ord(character) == 127 for character in value)):
            raise ValueError("Stored endpoint report header exceeds its limit.")
    outcome = row["outcome"]
    if outcome not in {"RESPONSE_RECEIVED", "TLS_VERIFICATION_FAILED", "TLS_HANDSHAKE_FAILED",
                       "TIMEOUT", "HEADER_LIMIT_EXCEEDED", "MALFORMED_RESPONSE",
                       "CONNECTION_FAILED", "DNS_REVALIDATION_FAILED"}:
        raise ValueError("Stored endpoint outcome is invalid.")
    if outcome == "RESPONSE_RECEIVED":
        if type(row["status_code"]) is not int or not 100 <= row["status_code"] <= 599:
            raise ValueError("Stored endpoint response status is invalid.")
    elif row["status_code"] is not None or headers or row["content_type"] is not None or row["content_length"] is not None:
        raise ValueError("Failed endpoint observation contains response facts.")
    if row["scheme"] not in {"http", "https"}:
        raise ValueError("Stored endpoint scheme is invalid.")
    target_ip = text("target_ip", 15)
    parsed_target = ipaddress.ip_address(target_ip)
    if not isinstance(parsed_target, ipaddress.IPv4Address) or str(parsed_target) != target_ip:
        raise ValueError("Stored endpoint target is not canonical IPv4.")
    if type(row["port_number"]) is not int or not 1 <= row["port_number"] <= 65535:
        raise ValueError("Stored endpoint TCP port is invalid.")
    if row["source"] != ("http-head-v1" if row["scheme"] == "http" else "https-tls-head-v1"):
        raise ValueError("Stored endpoint source does not match its scheme.")
    timestamp = text("observed_at", 64)
    parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
        raise ValueError("Stored endpoint timestamp is not timezone-aware.")
    redirect_location = text("redirect_location", 1024, True)
    if redirect_location is not None:
        redirect = urlsplit(redirect_location)
        if (redirect.username or redirect.password or redirect.query or redirect.fragment
                or (redirect.scheme and redirect.scheme not in {"http", "https"})):
            raise ValueError("Stored redirect metadata is not sanitized.")
    result = {
        "id": row["id"], "scope_id": row["scope_id"], "device_id": row["device_id"],
        "port_id": row["port_id"], "port_number": row["port_number"], "transport": "tcp",
        "target_ip": target_ip, "approved_hostname": text("approved_hostname", 255, True),
        "scheme": row["scheme"], "observed_at": text("observed_at", 64),
        "source": text("source", 64), "outcome": outcome,
        "error_category": text("error_category", 64, True), "status_code": row["status_code"],
        "response_headers": headers, "content_type": text("content_type", 512, True),
        "content_length": row["content_length"], "server_identifier": text("server_identifier", 512, True),
        "redirect_location": redirect_location,
        "scan": {"run_id": text("scan_run_id", 64), "target_id": row["scan_target_id"],
                 "profile": text("profile", 64), "scanner": text("scanner", 128),
                 "scanner_version": text("scanner_version", 64, True),
                 "run_outcome": text("run_status", 32), "target_outcome": text("target_outcome", 32),
                 "error_category": text("target_error_category", 64, True)},
        "tls": None,
    }
    if result["server_identifier"] is not None:
        result["server_identifier"] = {"value": result["server_identifier"],
                                       "confidence": "LOW", "source": "http_response_header"}
    if result["scheme"] == "https":
        verification = row["verification_status"]
        if verification not in {"VERIFIED", "FAILED", "NOT_COMPLETED"}:
            raise ValueError("Stored TLS verification state is invalid.")
        tls = {"verification_status": verification,
               "hostname_verification": row["hostname_verification"],
               "ip_address_verification": row["ip_address_verification"],
               "verification_name": text("verification_name", 255),
               "error_category": text("tls_error_category", 64, True)}
        if verification == "VERIFIED":
            subject = json_value("certificate_subject_json", 2048, list)
            issuer = json_value("certificate_issuer_json", 2048, list)
            sans = json_value("subject_alt_names_json", 4096, list)
            if any(len(value) > MAX_HTTP_TLS_CERTIFICATE_ENTRIES for value in (subject, issuer, sans)):
                raise ValueError("Stored TLS certificate collection exceeds its limit.")
            for collection, keys in ((subject, {"name", "value"}), (issuer, {"name", "value"}),
                                      (sans, {"type", "value"})):
                if any(not isinstance(item, dict) or set(item) != keys
                       or any(not isinstance(item[key], str) or len(item[key].encode("utf-8")) > 128
                              or any(ord(character) < 32 or ord(character) == 127 for character in item[key])
                              for key in keys) for item in collection):
                    raise ValueError("Stored TLS certificate fact is invalid.")
            fingerprint = text("sha256_fingerprint", 64)
            if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
                raise ValueError("Stored certificate fingerprint is invalid.")
            tls.update({"protocol_version": text("protocol_version", 32, True),
                        "cipher": {"name": text("cipher_name", 128),
                                   "protocol": text("cipher_protocol", 32), "bits": row["cipher_bits"]},
                        "certificate_subject": subject, "certificate_issuer": issuer,
                        "not_before": text("not_before", 64, True), "not_after": text("not_after", 64, True),
                        "subject_alt_names": sans, "sha256_fingerprint": fingerprint})
        elif any(row[field] is not None for field in (
                "protocol_version", "cipher_name", "cipher_protocol", "cipher_bits",
                "certificate_subject_json", "certificate_issuer_json", "not_before", "not_after",
                "subject_alt_names_json", "sha256_fingerprint")):
            raise ValueError("Unverified TLS observation contains certificate facts.")
        result["tls"] = tls
    elif row["verification_status"] is not None:
        raise ValueError("HTTP observation unexpectedly contains TLS data.")
    if result["outcome"] == "RESPONSE_RECEIVED":
        if row["run_status"] != "COMPLETED" or row["target_outcome"] != "COMPLETED":
            raise ValueError("Completed endpoint response has inconsistent scan provenance.")
    elif row["run_status"] == "COMPLETED" or row["target_outcome"] == "COMPLETED":
        raise ValueError("Failed endpoint result has completed scan provenance.")
    if result["scheme"] == "https":
        verification = result["tls"]["verification_status"]
        expected_verification = {
            "RESPONSE_RECEIVED": "VERIFIED",
            "TLS_VERIFICATION_FAILED": "FAILED",
            "TLS_HANDSHAKE_FAILED": "NOT_COMPLETED",
        }.get(result["outcome"])
        if expected_verification is not None and verification != expected_verification:
            raise ValueError("Endpoint outcome and TLS verification state disagree.")
    if len(json.dumps({"headers": headers, "tls": result["tls"]}, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")) > MAX_HTTP_TLS_METADATA_BYTES:
        raise ValueError("Stored endpoint report metadata exceeds its combined limit.")
    return result


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
