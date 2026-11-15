import base64
from datetime import datetime
import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
from uuid import UUID

from database.db import DB_PATH, get_connection


DEFAULT_HISTORY_PAGE_SIZE = 20
MAX_HISTORY_PAGE_SIZE = 100
MAX_HISTORY_CURSOR_BYTES = 512
MAX_HISTORY_RESPONSE_BYTES = 2_097_152
MAX_ENDPOINT_METADATA_BYTES = 8_192
MAX_TLS_SUBJECT_BYTES = 2_048
MAX_TLS_SAN_BYTES = 4_096
MAX_TLS_COLLECTION_ENTRIES = 8
HISTORY_PROFILE = "http_endpoint_fingerprint"
HISTORY_HEADER_ALLOWLIST = {
    "date", "cache-control", "strict-transport-security", "x-content-type-options",
    "x-frame-options", "content-security-policy", "referrer-policy", "permissions-policy",
}
_CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,480}\.[0-9a-f]{16}$")


class HistoryAccessError(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code


class HistoryCursorError(ValueError):
    pass


def _json_bytes(value):
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field.")
        result[key] = value
    return result


def _encode_cursor(observed_at, observation_id, scope_id, device_id, port_id, scan_run_id):
    payload = json.dumps({
        "v": 1, "at": observed_at, "id": observation_id, "scope": scope_id,
        "device": device_id, "port": port_id, "run": scan_run_id,
    }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(payload).hexdigest()[:16]
    cursor = f"{encoded}.{digest}"
    if len(cursor.encode("ascii")) > MAX_HISTORY_CURSOR_BYTES:
        raise HistoryCursorError("Pagination cursor exceeds its size limit.")
    return cursor


def _decode_cursor(cursor, scope_id, device_id, port_id, scan_run_id):
    if (not isinstance(cursor, str) or len(cursor) > MAX_HISTORY_CURSOR_BYTES
            or len(cursor.encode("utf-8")) > MAX_HISTORY_CURSOR_BYTES or not _CURSOR_RE.fullmatch(cursor)):
        raise HistoryCursorError("Pagination cursor is malformed.")
    encoded, supplied_digest = cursor.split(".", 1)
    try:
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii") != encoded:
            raise ValueError("Non-canonical base64.")
        expected_digest = hashlib.sha256(payload).hexdigest()[:16]
        if not hmac.compare_digest(expected_digest, supplied_digest):
            raise ValueError("Cursor checksum mismatch.")
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_strict_object)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise HistoryCursorError("Pagination cursor is malformed or has been modified.") from exc
    if (not isinstance(value, dict)
            or set(value) != {"v", "at", "id", "scope", "device", "port", "run"}
            or type(value["v"]) is not int or value["v"] != 1
            or type(value["id"]) is not int or value["id"] <= 0
            or type(value["scope"]) is not int or value["scope"] != scope_id
            or type(value["device"]) is not int or value["device"] != device_id
            or type(value["port"]) is not int or value["port"] != port_id
            or value["run"] != scan_run_id
            or not isinstance(value["at"], str) or len(value["at"]) > 64):
        raise HistoryCursorError("Pagination cursor does not match this history query.")
    try:
        parsed = datetime.fromisoformat(value["at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise HistoryCursorError("Pagination cursor timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HistoryCursorError("Pagination cursor timestamp must include a timezone.")
    return value["at"], value["id"]


def _bounded_text(value, name, byte_limit, *, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > byte_limit or len(value.encode("utf-8")) > byte_limit:
        raise ValueError(f"Stored {name} exceeds its projection limit.")
    return value


def _load_json(value, name, byte_limit):
    value = _bounded_text(value, name, byte_limit)
    if len(value.encode("utf-8")) > byte_limit:
        raise ValueError(f"Stored {name} exceeds its projection limit.")
    try:
        return json.loads(value, object_pairs_hook=_strict_object)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"Stored {name} is malformed.") from exc


def _project_headers(value):
    headers = _load_json(value, "response headers", MAX_ENDPOINT_METADATA_BYTES)
    if not isinstance(headers, dict) or len(headers) > len(HISTORY_HEADER_ALLOWLIST) or set(headers) - HISTORY_HEADER_ALLOWLIST:
        raise ValueError("Stored response headers are invalid.")
    for name, header_value in headers.items():
        if not isinstance(name, str) or not isinstance(header_value, str) or len(header_value.encode("utf-8")) > 512:
            raise ValueError("Stored response header exceeds its projection limit.")
    return headers


def _project_certificate_entries(value, field, keys, limits):
    if not isinstance(value, list) or len(value) > MAX_TLS_COLLECTION_ENTRIES:
        raise ValueError(f"Stored {field} collection is invalid.")
    projected = []
    for item in value:
        if not isinstance(item, dict) or set(item) != set(keys):
            raise ValueError(f"Stored {field} entry is invalid.")
        projected.append({key: _bounded_text(item[key], field, limits[key]) for key in keys})
    return projected


def _project_tls(row):
    if row["verification_status"] is None:
        return None
    verification = row["verification_status"]
    if verification not in {"VERIFIED", "FAILED", "NOT_COMPLETED"}:
        raise ValueError("Stored TLS verification status is invalid.")
    result = {
        "verification_status": verification,
        "hostname_verification": row["hostname_verification"],
        "ip_address_verification": row["ip_address_verification"],
        "verification_name": _bounded_text(row["verification_name"], "TLS verification name", 255),
        "protocol_version": _bounded_text(row["protocol_version"], "TLS protocol", 32, nullable=True),
        "cipher": None,
        "certificate_subject": None,
        "certificate_issuer": None,
        "not_before": _bounded_text(row["not_before"], "certificate not-before", 64, nullable=True),
        "not_after": _bounded_text(row["not_after"], "certificate not-after", 64, nullable=True),
        "subject_alt_names": None,
        "sha256_fingerprint": None,
        "error_category": _bounded_text(row["tls_error_category"], "TLS error category", 64, nullable=True),
    }
    if verification == "VERIFIED":
        subject = _load_json(row["certificate_subject_json"], "certificate subject", MAX_TLS_SUBJECT_BYTES)
        issuer = _load_json(row["certificate_issuer_json"], "certificate issuer", MAX_TLS_SUBJECT_BYTES)
        sans = _load_json(row["subject_alt_names_json"], "certificate SANs", MAX_TLS_SAN_BYTES)
        if any(not isinstance(items, list) or len(items) > MAX_TLS_COLLECTION_ENTRIES for items in (subject, issuer, sans)):
            raise ValueError("Stored TLS certificate collections are invalid.")
        subject = _project_certificate_entries(subject, "certificate subject", ("name", "value"),
                                               {"name": 64, "value": 128})
        issuer = _project_certificate_entries(issuer, "certificate issuer", ("name", "value"),
                                             {"name": 64, "value": 128})
        sans = _project_certificate_entries(sans, "certificate SAN", ("type", "value"),
                                            {"type": 32, "value": 128})
        cipher_name = _bounded_text(row["cipher_name"], "TLS cipher", 128)
        cipher_protocol = _bounded_text(row["cipher_protocol"], "TLS cipher protocol", 32)
        bits = row["cipher_bits"]
        fingerprint = _bounded_text(row["sha256_fingerprint"], "TLS fingerprint", 64)
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or type(bits) is not int or not 0 <= bits <= 65535:
            raise ValueError("Stored verified TLS facts are invalid.")
        result.update({
            "cipher": {"name": cipher_name, "protocol": cipher_protocol, "bits": bits},
            "certificate_subject": subject, "certificate_issuer": issuer,
            "subject_alt_names": sans, "sha256_fingerprint": fingerprint,
        })
    elif any(row[key] is not None for key in (
        "protocol_version", "cipher_name", "cipher_protocol", "cipher_bits",
        "certificate_subject_json", "certificate_issuer_json", "not_before", "not_after",
        "subject_alt_names_json", "sha256_fingerprint",
    )):
        raise ValueError("Unverified TLS row contains certificate facts.")
    return result


def _project_observation(row):
    target_ip = _bounded_text(row["target_ip"], "target IP", 15)
    parsed_ip = ipaddress.ip_address(target_ip)
    if not isinstance(parsed_ip, ipaddress.IPv4Address) or str(parsed_ip) != target_ip:
        raise ValueError("Stored target address is not IPv4.")
    outcome = row["outcome"]
    if outcome not in {
        "RESPONSE_RECEIVED", "TLS_VERIFICATION_FAILED", "TLS_HANDSHAKE_FAILED", "TIMEOUT",
        "HEADER_LIMIT_EXCEEDED", "MALFORMED_RESPONSE", "CONNECTION_FAILED", "DNS_REVALIDATION_FAILED",
    }:
        raise ValueError("Stored endpoint outcome is invalid.")
    server_value = _bounded_text(row["server_identifier"], "server identifier", 512, nullable=True)
    redirect = _bounded_text(row["redirect_location"], "redirect location", 1024, nullable=True)
    if redirect is not None:
        from urllib.parse import urlsplit
        parsed = urlsplit(redirect)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or (parsed.scheme and parsed.scheme not in {"http", "https"}):
            raise ValueError("Stored redirect metadata is not sanitized.")
    status = row["status_code"]
    if outcome == "RESPONSE_RECEIVED":
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Stored HTTP status is invalid.")
    elif status is not None:
        raise ValueError("Failed endpoint outcome contains an HTTP status.")
    if outcome != "RESPONSE_RECEIVED" and row["error_category"] is None:
        raise ValueError("Failed endpoint outcome has no error category.")
    content_length = row["content_length"]
    if content_length is not None and (type(content_length) is not int or content_length < 0):
        raise ValueError("Stored content length is invalid.")
    result = {
        "id": row["id"], "scope_id": row["scope_id"], "device_id": row["device_id"],
        "port_id": row["port_id"], "target_ip": target_ip,
        "approved_hostname": _bounded_text(row["approved_hostname"], "approved hostname", 255, nullable=True),
        "scheme": row["scheme"], "observed_at": _bounded_text(row["observed_at"], "observation timestamp", 64),
        "source": _bounded_text(row["source"], "observation source", 64), "outcome": outcome,
        "error_category": _bounded_text(row["error_category"], "error category", 64, nullable=True),
        "status_code": status, "response_headers": _project_headers(row["response_headers_json"]),
        "content_type": _bounded_text(row["content_type"], "content type", 512, nullable=True),
        "content_length": content_length,
        "server_identifier": None if server_value is None else {
            "value": server_value, "confidence": "LOW", "source": "http_response_header",
        },
        "redirect_location": redirect,
        "tls": _project_tls(row),
        "scan": {
            "run_id": _bounded_text(row["scan_run_id"], "scan run ID", 64),
            "target_id": row["scan_target_id"], "profile": _bounded_text(row["profile"], "scan profile", 64),
            "scanner": _bounded_text(row["scanner"], "scanner identity", 128),
            "scanner_version": _bounded_text(row["scanner_version"], "scanner version", 64, nullable=True),
            "status": row["run_status"], "target_outcome": row["target_outcome"],
            "error_category": _bounded_text(row["target_error_category"], "scan error category", 64, nullable=True),
        },
    }
    observed_at = result["observed_at"]
    try:
        timestamp = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Stored observation timestamp is invalid.") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Stored observation timestamp must include a timezone.")
    expected_source = "http-head-v1" if result["scheme"] == "http" else "https-tls-head-v1"
    if result["source"] != expected_source:
        raise ValueError("Stored endpoint source is invalid.")
    if outcome != "RESPONSE_RECEIVED" and any((
        result["response_headers"], result["content_type"], content_length is not None,
        result["server_identifier"], redirect,
    )):
        raise ValueError("Failed endpoint outcome contains response metadata.")
    if result["scheme"] not in {"http", "https"}:
        raise ValueError("Stored endpoint scheme is invalid.")
    if result["scheme"] == "https" and result["tls"] is None:
        raise ValueError("HTTPS endpoint has no TLS observation.")
    if result["scheme"] == "http" and result["tls"] is not None:
        raise ValueError("HTTP endpoint has TLS metadata.")
    if result["scheme"] == "https":
        verification = result["tls"]["verification_status"]
        if outcome == "RESPONSE_RECEIVED" and verification != "VERIFIED":
            raise ValueError("HTTPS response lacks verified TLS metadata.")
        if outcome == "TLS_VERIFICATION_FAILED" and verification != "FAILED":
            raise ValueError("TLS verification outcome and metadata disagree.")
        if outcome == "TLS_HANDSHAKE_FAILED" and verification != "NOT_COMPLETED":
            raise ValueError("TLS handshake outcome and metadata disagree.")
    if outcome == "RESPONSE_RECEIVED" and (
        row["run_status"] != "COMPLETED" or row["target_outcome"] != "COMPLETED"
    ):
        raise ValueError("Completed response provenance is inconsistent.")
    if outcome != "RESPONSE_RECEIVED" and (
        row["run_status"] == "COMPLETED" or row["target_outcome"] == "COMPLETED"
    ):
        raise ValueError("Failed response provenance is inconsistent.")
    return result


def list_http_endpoint_history(
    scope_id, device_id, port_id, *, limit=DEFAULT_HISTORY_PAGE_SIZE,
    cursor=None, scan_run_id=None, db_path=DB_PATH,
):
    if any(type(value) is not int or value <= 0 for value in (scope_id, device_id, port_id)):
        raise HistoryAccessError(404, "Endpoint history was not found.")
    if type(limit) is not int or not 1 <= limit <= MAX_HISTORY_PAGE_SIZE:
        raise HistoryCursorError("Page size must be between 1 and 100.")
    if scan_run_id is not None:
        if not isinstance(scan_run_id, str) or len(scan_run_id) != 36:
            raise HistoryAccessError(404, "Endpoint history was not found.")
        try:
            scan_run_id = str(UUID(scan_run_id))
        except ValueError as exc:
            raise HistoryAccessError(404, "Endpoint history was not found.") from exc
    cursor_key = _decode_cursor(cursor, scope_id, device_id, port_id, scan_run_id) if cursor is not None else None
    connection = get_connection(db_path)
    try:
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RuntimeError("Foreign-key enforcement is disabled.")
        connection.row_factory = sqlite3.Row
        scope = connection.execute(
            """SELECT s.scope_type,s.canonical_target,s.authorized,s.enabled,
                      s.authorization_confirmed_at,s.authorization_confirmation_version,
                      s.authorization_source,l.network_id
               FROM authorized_scopes s LEFT JOIN network_scope_links l ON l.scope_id=s.id
               WHERE s.id=?""", (scope_id,),
        ).fetchone()
        if scope is None:
            raise HistoryAccessError(404, "Endpoint history was not found.")
        if (scope["authorized"] != 1 or scope["enabled"] != 1
                or not all(isinstance(scope[key], str) and scope[key].strip() for key in (
                    "authorization_confirmed_at", "authorization_confirmation_version", "authorization_source"))):
            raise HistoryAccessError(403, "An enabled, confirmed authorized scope is required.")
        device = connection.execute(
            "SELECT network_id,scope_id FROM devices WHERE id=?", (device_id,),
        ).fetchone()
        if device is None:
            raise HistoryAccessError(404, "Endpoint history was not found.")
        if scope["scope_type"] == "PRIVATE_NETWORK":
            device_belongs = device["network_id"] == scope["network_id"] and device["scope_id"] is None
        else:
            device_belongs = device["scope_id"] == scope_id and device["network_id"] is None
        if not device_belongs:
            raise HistoryAccessError(404, "Endpoint history was not found.")
        port = connection.execute(
            """SELECT p.id FROM ports p WHERE p.id=? AND p.device_id=?
               AND lower(p.transport)='tcp'
               AND EXISTS (SELECT 1 FROM port_observations o WHERE o.port_id=p.id
                 AND o.device_id=p.device_id AND lower(o.transport)='tcp')""",
            (port_id, device_id),
        ).fetchone()
        if port is None:
            raise HistoryAccessError(404, "Endpoint history was not found.")
        if scan_run_id is not None:
            run = connection.execute(
                "SELECT 1 FROM recon_scan_runs WHERE id=? AND scope_id=? AND profile=?",
                (scan_run_id, scope_id, HISTORY_PROFILE),
            ).fetchone()
            if run is None:
                raise HistoryAccessError(404, "Endpoint history was not found.")
        where = ["e.scope_id=?", "e.device_id=?", "e.port_id=?"]
        parameters = [scope_id, device_id, port_id]
        if scan_run_id is not None:
            where.append("r.id=?")
            parameters.append(scan_run_id)
        if cursor_key is not None:
            where.append("(e.observed_at < ? OR (e.observed_at = ? AND e.id < ?))")
            parameters.extend((cursor_key[0], cursor_key[0], cursor_key[1]))
        rows = connection.execute(
            f"""SELECT e.id,e.scope_id,e.device_id,e.port_id,e.scan_target_id,e.scheme,
                       e.target_ip,e.approved_hostname,e.observed_at,e.source,e.outcome,
                       e.error_category,e.status_code,e.response_headers_json,e.content_type,
                       e.content_length,e.server_identifier,e.redirect_location,
                       tls.verification_status,tls.hostname_verification,tls.ip_address_verification,
                       tls.verification_name,tls.protocol_version,tls.cipher_name,tls.cipher_protocol,
                       tls.cipher_bits,tls.certificate_subject_json,tls.certificate_issuer_json,
                       tls.not_before,tls.not_after,tls.subject_alt_names_json,
                       tls.sha256_fingerprint,tls.error_category AS tls_error_category,
                       r.id AS scan_run_id,r.profile,r.scanner,r.scanner_version,r.status AS run_status,
                       t.outcome AS target_outcome,t.error_category AS target_error_category
                FROM http_endpoint_observations e
                JOIN recon_scan_targets t ON t.id=e.scan_target_id
                JOIN recon_scan_runs r ON r.id=t.run_id
                LEFT JOIN http_tls_observations tls ON tls.endpoint_observation_id=e.id
                WHERE {' AND '.join(where)}
                ORDER BY e.observed_at DESC,e.id DESC LIMIT ?""",
            (*parameters, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        page = [_project_observation(row) for row in rows[:limit]]
        next_cursor = None
        if has_more and page:
            last = page[-1]
            next_cursor = _encode_cursor(
                last["observed_at"], last["id"], scope_id, device_id, port_id, scan_run_id,
            )
        response = {"items": page, "limit": limit, "returned": len(page), "next_cursor": next_cursor}
        if _json_bytes(response) > MAX_HISTORY_RESPONSE_BYTES:
            raise ValueError("Endpoint history response exceeds its size limit.")
        return response
    finally:
        connection.close()
