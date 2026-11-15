import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlsplit
import uuid

from database.db import DB_PATH, get_connection


SCANNER_ID = "sentinelip-http-tls-fingerprint"
SCAN_PROFILE = "http_endpoint_fingerprint"
SOURCE_BY_SCHEME = {"http": "http-head-v1", "https": "https-tls-head-v1"}
OUTCOMES = {
    "RESPONSE_RECEIVED", "TLS_VERIFICATION_FAILED", "TLS_HANDSHAKE_FAILED",
    "TIMEOUT", "HEADER_LIMIT_EXCEEDED", "MALFORMED_RESPONSE",
    "CONNECTION_FAILED", "DNS_REVALIDATION_FAILED",
}
ERROR_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")
FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SAFE_HEADERS = {
    "date", "cache-control", "strict-transport-security", "x-content-type-options",
    "x-frame-options", "content-security-policy", "referrer-policy", "permissions-policy",
}
MAX_METADATA_BYTES = 8_192
MAX_HTTP_ENDPOINT_OBSERVATIONS_PER_SCOPE = 10_000


class HttpEndpointPersistenceError(ValueError):
    pass


def _byte_length(value):
    return len(value.encode("utf-8"))


def _bounded_string(value, field, limit, *, nullable=False):
    if value is None and nullable:
        return None
    if (not isinstance(value, str) or len(value) > limit or _byte_length(value) > limit
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise HttpEndpointPersistenceError(f"{field} is invalid or exceeds its limit.")
    return value


def _measure_json(value, limit, state, depth=0):
    state["items"] += 1
    if state["items"] > 128 or depth > 5:
        raise HttpEndpointPersistenceError("JSON metadata exceeds its structural limits.")
    if value is None or type(value) is bool:
        return 4
    if type(value) is int:
        if not -(2 ** 63) <= value <= 2 ** 63 - 1:
            raise HttpEndpointPersistenceError("JSON integer exceeds its storage range.")
        return 20
    if isinstance(value, str):
        if len(value) > limit:
            raise HttpEndpointPersistenceError("JSON string exceeds its storage limit.")
        size = 2
        for character in value:
            codepoint = ord(character)
            size += 2 if character in {'"', "\\"} else (
                12 if codepoint > 0xFFFF else 6 if codepoint < 32 or codepoint > 126 else 1
            )
        return size
    if isinstance(value, list):
        if len(value) > 16:
            raise HttpEndpointPersistenceError("JSON collection exceeds its entry limit.")
        return 2 + max(0, len(value) - 1) + sum(
            _measure_json(item, limit, state, depth + 1) for item in value
        )
    if isinstance(value, dict):
        if len(value) > 32:
            raise HttpEndpointPersistenceError("JSON object exceeds its field limit.")
        size = 2
        for index, (key, item) in enumerate(value.items()):
            if not isinstance(key, str):
                raise HttpEndpointPersistenceError("JSON object keys must be strings.")
            size += _measure_json(key, limit, state, depth + 1) + 1
            size += _measure_json(item, limit, state, depth + 1) + (1 if index else 0)
        return size
    raise HttpEndpointPersistenceError("JSON metadata contains an unsupported value.")


def _timestamp(value, field):
    value = _bounded_string(value, field, 64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HttpEndpointPersistenceError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HttpEndpointPersistenceError(f"{field} must include a timezone.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _certificate_timestamp(value, field):
    if value is None:
        return None
    value = _bounded_string(value, field, 64)
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HttpEndpointPersistenceError(f"{field} must be a valid certificate date.") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise HttpEndpointPersistenceError(f"{field} must include a timezone.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _json(value, field, limit):
    if _measure_json(value, limit, {"items": 0}) > limit:
        raise HttpEndpointPersistenceError(f"{field} exceeds its storage limit.")
    try:
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise HttpEndpointPersistenceError(f"{field} is not valid JSON data.") from exc
    if _byte_length(encoded) > limit:
        raise HttpEndpointPersistenceError(f"{field} exceeds its storage limit.")
    return encoded


def _metadata(result):
    if not isinstance(result, dict):
        raise HttpEndpointPersistenceError("Inspection result must be an object.")
    allowed_keys = {
        "scope_id", "device_id", "port_id", "scheme", "target_ip", "host", "observed_at",
        "source", "status_code", "response_headers", "content_type", "content_length",
        "server_identifier", "redirect_location", "outcome", "error_category", "tls",
        "approved_hostname",
    }
    if set(result) - allowed_keys:
        raise HttpEndpointPersistenceError("Inspection result contains unsupported fields.")
    scope_id, device_id, port_id = (result.get(key) for key in ("scope_id", "device_id", "port_id"))
    if any(type(value) is not int or value <= 0 for value in (scope_id, device_id, port_id)):
        raise HttpEndpointPersistenceError("Scope, device and port identifiers must be positive integers.")
    scheme = result.get("scheme")
    if scheme not in SOURCE_BY_SCHEME:
        raise HttpEndpointPersistenceError("Inspection scheme is unsupported.")
    try:
        address = ipaddress.ip_address(result.get("target_ip"))
    except (TypeError, ValueError) as exc:
        raise HttpEndpointPersistenceError("Target address must be IPv4.") from exc
    if not isinstance(address, ipaddress.IPv4Address) or str(address) != result.get("target_ip"):
        raise HttpEndpointPersistenceError("Target address must be canonical IPv4.")
    observed_at = _timestamp(result.get("observed_at"), "observed_at")
    source = _bounded_string(result.get("source"), "source", 64)
    if source != SOURCE_BY_SCHEME[scheme]:
        raise HttpEndpointPersistenceError("Inspection source does not match its scheme.")
    outcome = result.get("outcome")
    if outcome == "CAPACITY_REJECTED":
        raise HttpEndpointPersistenceError("Capacity-rejected operations are not persisted.")
    if outcome not in OUTCOMES:
        raise HttpEndpointPersistenceError("Inspection outcome is unsupported.")
    if outcome in {"TLS_VERIFICATION_FAILED", "TLS_HANDSHAKE_FAILED"} and scheme != "https":
        raise HttpEndpointPersistenceError("TLS outcomes require HTTPS.")
    error_category = result.get("error_category")
    if error_category is not None and (
        not isinstance(error_category, str) or not ERROR_PATTERN.fullmatch(error_category)
    ):
        raise HttpEndpointPersistenceError("Error category is invalid.")
    status = result.get("status_code")
    if outcome == "RESPONSE_RECEIVED":
        if type(status) is not int or not 100 <= status <= 599 or error_category is not None:
            raise HttpEndpointPersistenceError("Successful response status is invalid.")
    elif status is not None:
        raise HttpEndpointPersistenceError("Failed inspection cannot contain an HTTP status.")
    elif error_category is None:
        raise HttpEndpointPersistenceError("Failed inspection requires a bounded error category.")
    headers = result.get("response_headers")
    if not isinstance(headers, dict) or set(headers) - SAFE_HEADERS:
        raise HttpEndpointPersistenceError("Response headers contain unsupported fields.")
    clean_headers = {}
    for name, value in headers.items():
        if not isinstance(value, str) or _byte_length(value) > 512:
            raise HttpEndpointPersistenceError("A response header exceeds its limit.")
        clean_headers[name] = value
    content_type = _bounded_string(result.get("content_type"), "content_type", 512, nullable=True)
    content_length = result.get("content_length")
    if content_length is not None and (type(content_length) is not int or not 0 <= content_length <= 9_223_372_036_854_775_807):
        raise HttpEndpointPersistenceError("Content length is invalid.")
    server = result.get("server_identifier")
    server_value = None
    if server is not None:
        if not isinstance(server, dict) or set(server) != {"value", "confidence", "source"}:
            raise HttpEndpointPersistenceError("Server identifier is invalid.")
        if server["confidence"] != "LOW" or server["source"] != "http_response_header":
            raise HttpEndpointPersistenceError("Server identifier provenance is invalid.")
        server_value = _bounded_string(server["value"], "server_identifier", 512)
    redirect = _bounded_string(result.get("redirect_location"), "redirect_location", 1024, nullable=True)
    if redirect is not None:
        try:
            parsed = urlsplit(redirect)
            if parsed.username or parsed.password or parsed.query or parsed.fragment or (parsed.scheme and parsed.scheme not in {"http", "https"}):
                raise ValueError
            if parsed.netloc and not parsed.hostname:
                raise ValueError
        except ValueError as exc:
            raise HttpEndpointPersistenceError("Redirect metadata is not sanitized.") from exc
    if outcome != "RESPONSE_RECEIVED" and any((clean_headers, content_type, content_length is not None, server_value, redirect)):
        raise HttpEndpointPersistenceError("Failed inspection cannot contain response metadata.")
    if _byte_length(_json(clean_headers, "response_headers", MAX_METADATA_BYTES)) > MAX_METADATA_BYTES:
        raise HttpEndpointPersistenceError("Response metadata exceeds its limit.")
    approved_hostname = result.get("approved_hostname")
    if approved_hostname is not None:
        approved_hostname = _bounded_string(approved_hostname, "approved_hostname", 255)
    host = _bounded_string(result.get("host"), "host", 300)
    tls = result.get("tls")
    if scheme == "https":
        if not isinstance(tls, dict):
            raise HttpEndpointPersistenceError("HTTPS result requires TLS metadata.")
        if _byte_length(_json(tls, "TLS metadata", MAX_METADATA_BYTES)) > MAX_METADATA_BYTES:
            raise HttpEndpointPersistenceError("TLS metadata exceeds its storage limit.")
    elif tls is not None:
        raise HttpEndpointPersistenceError("HTTP observations cannot contain TLS metadata.")
    data = {
        "scope_id": scope_id, "device_id": device_id, "port_id": port_id,
        "scheme": scheme, "target_ip": str(address), "approved_hostname": approved_hostname,
        "host": host,
        "observed_at": observed_at, "source": source, "outcome": outcome,
        "error_category": error_category, "status_code": status,
        "response_headers_json": _json(clean_headers, "response_headers", MAX_METADATA_BYTES),
        "content_type": content_type, "content_length": content_length,
        "server_identifier": server_value, "redirect_location": redirect, "tls": tls,
    }
    if _byte_length(_json({key: value for key, value in data.items() if key not in {"tls"}}, "endpoint metadata", MAX_METADATA_BYTES)) + (
        _byte_length(_json(tls, "TLS metadata", MAX_METADATA_BYTES)) if tls is not None else 0
    ) > MAX_METADATA_BYTES:
        raise HttpEndpointPersistenceError("Combined endpoint metadata exceeds its storage limit.")
    return data


def _validate_tls(tls, target_ip, approved_hostname):
    if not isinstance(tls, dict):
        raise HttpEndpointPersistenceError("HTTPS result requires TLS metadata.")
    allowed_keys = {
        "protocol_version", "cipher", "certificate_subject", "certificate_issuer", "not_before",
        "not_after", "subject_alt_names", "sha256_fingerprint", "certificate_verification",
        "hostname_verification", "ip_address_verification", "verification_name", "error_category",
    }
    if set(tls) - allowed_keys:
        raise HttpEndpointPersistenceError("TLS result contains unsupported fields.")
    verification = tls.get("certificate_verification")
    if verification not in {"VERIFIED", "FAILED", "NOT_COMPLETED"}:
        raise HttpEndpointPersistenceError("TLS verification state is invalid.")
    verification_name = _bounded_string(tls.get("verification_name"), "verification_name", 255)
    expected_name = approved_hostname or target_ip
    if verification_name != expected_name:
        raise HttpEndpointPersistenceError("TLS verification name does not match the authorized endpoint.")
    host_state = tls.get("hostname_verification")
    ip_state = tls.get("ip_address_verification")
    if approved_hostname:
        if ip_state is not None or host_state not in {"MATCHED", "FAILED", "NOT_COMPLETED"}:
            raise HttpEndpointPersistenceError("TLS hostname verification state is invalid.")
    elif host_state is not None or ip_state not in {"MATCHED", "FAILED", "NOT_COMPLETED"}:
        raise HttpEndpointPersistenceError("TLS IP verification state is invalid.")
    error = tls.get("error_category")
    if error is not None and (not isinstance(error, str) or not ERROR_PATTERN.fullmatch(error)):
        raise HttpEndpointPersistenceError("TLS error category is invalid.")
    if verification == "VERIFIED":
        if error is not None or (host_state if approved_hostname else ip_state) != "MATCHED":
            raise HttpEndpointPersistenceError("Verified TLS metadata lacks successful identity verification.")
        fingerprint = tls.get("sha256_fingerprint")
        if not isinstance(fingerprint, str) or not FINGERPRINT_PATTERN.fullmatch(fingerprint):
            raise HttpEndpointPersistenceError("Verified TLS fingerprint is invalid.")
        subject = tls.get("certificate_subject")
        issuer = tls.get("certificate_issuer")
        sans = tls.get("subject_alt_names")
        if not isinstance(subject, list) or not isinstance(issuer, list) or not isinstance(sans, list):
            raise HttpEndpointPersistenceError("Verified TLS certificate fields are invalid.")
        if len(subject) > 8 or len(issuer) > 8 or len(sans) > 8:
            raise HttpEndpointPersistenceError("TLS certificate collections exceed their entry limits.")
        for item in subject + issuer:
            if not isinstance(item, dict) or set(item) != {"name", "value"}:
                raise HttpEndpointPersistenceError("TLS distinguished-name data is invalid.")
            _bounded_string(item["name"], "certificate name", 64)
            _bounded_string(item["value"], "certificate value", 128)
        for item in sans:
            if not isinstance(item, dict) or set(item) != {"type", "value"}:
                raise HttpEndpointPersistenceError("TLS SAN data is invalid.")
            _bounded_string(item["type"], "SAN type", 32)
            _bounded_string(item["value"], "SAN value", 128)
        cipher = tls.get("cipher")
        if not isinstance(cipher, dict) or set(cipher) != {"name", "protocol", "bits"}:
            raise HttpEndpointPersistenceError("TLS cipher data is invalid.")
        protocol = _bounded_string(tls.get("protocol_version"), "TLS protocol", 32)
        cipher_name = _bounded_string(cipher["name"], "TLS cipher name", 128)
        cipher_protocol = _bounded_string(cipher["protocol"], "TLS cipher protocol", 32)
        bits = cipher["bits"]
        if type(bits) is not int or not 0 <= bits <= 65535:
            raise HttpEndpointPersistenceError("TLS cipher strength field is invalid.")
        not_before = _bounded_string(tls.get("not_before"), "certificate not-before", 64, nullable=True)
        not_after = _bounded_string(tls.get("not_after"), "certificate not-after", 64, nullable=True)
        not_before = _certificate_timestamp(not_before, "not_before")
        not_after = _certificate_timestamp(not_after, "not_after")
        if not_before is not None and not_after is not None and not_before > not_after:
            raise HttpEndpointPersistenceError("Certificate validity interval is invalid.")
        subject_json = _json(subject, "certificate subject", 2048)
        issuer_json = _json(issuer, "certificate issuer", 2048)
        sans_json = _json(sans, "certificate SANs", 4096)
        return {
            "verification_status": verification, "hostname_verification": host_state,
            "ip_address_verification": ip_state, "verification_name": verification_name,
            "protocol_version": protocol, "cipher_name": cipher_name,
            "cipher_protocol": cipher_protocol, "cipher_bits": bits,
            "certificate_subject_json": subject_json, "certificate_issuer_json": issuer_json,
            "not_before": not_before, "not_after": not_after,
            "subject_alt_names_json": sans_json, "sha256_fingerprint": fingerprint,
            "error_category": None,
        }
    facts = (tls.get("protocol_version"), tls.get("cipher"), tls.get("certificate_subject"),
             tls.get("certificate_issuer"), tls.get("not_before"), tls.get("not_after"),
             tls.get("subject_alt_names"), tls.get("sha256_fingerprint"))
    if any(value not in (None, [], {}) for value in facts):
        raise HttpEndpointPersistenceError("Unverified TLS attempts cannot include certificate facts.")
    return {
        "verification_status": verification, "hostname_verification": host_state,
        "ip_address_verification": ip_state, "verification_name": verification_name,
        "protocol_version": None, "cipher_name": None, "cipher_protocol": None,
        "cipher_bits": None, "certificate_subject_json": None,
        "certificate_issuer_json": None, "not_before": None, "not_after": None,
        "subject_alt_names_json": None, "sha256_fingerprint": None,
        "error_category": error,
    }


def _validate_relationships(connection, data):
    scope = connection.execute(
        """SELECT s.scope_type, s.canonical_target, s.authorized, s.enabled,
                  l.network_id, n.cidr, s.authorization_confirmed_at,
                  s.authorization_confirmation_version, s.authorization_source
           FROM authorized_scopes s
           LEFT JOIN network_scope_links l ON l.scope_id=s.id
           LEFT JOIN networks n ON n.id=l.network_id WHERE s.id=?""",
        (data["scope_id"],),
    ).fetchone()
    if (scope is None or scope[2] != 1 or scope[3] != 1
            or not all(isinstance(value, str) and value.strip() for value in scope[6:9])):
        raise HttpEndpointPersistenceError("An enabled authorized scope is required.")
    device = connection.execute(
        "SELECT network_id, scope_id, last_ip_address FROM devices WHERE id=?",
        (data["device_id"],),
    ).fetchone()
    if device is None or device[2] != data["target_ip"]:
        raise HttpEndpointPersistenceError("Device does not match the pinned target.")
    address = ipaddress.ip_address(data["target_ip"])
    scope_type, target, _, _, network_id, cidr = scope[:6]
    if scope_type == "PRIVATE_NETWORK":
        allowed = (network_id is not None and device[0] == network_id and cidr
                   and address in ipaddress.ip_network(cidr, strict=False)
                   and address.is_private and not (address.is_loopback or address.is_link_local
                   or address.is_multicast or address.is_unspecified or address.is_reserved))
    elif scope_type == "PUBLIC_IPV4":
        allowed = (device[1] == data["scope_id"] and device[0] is None
                   and target == data["target_ip"] and address.is_global)
    elif scope_type == "PUBLIC_CIDR":
        try:
            approved = connection.execute(
                "SELECT 1 FROM scope_cidr_addresses WHERE scope_id=? AND canonical_cidr=? AND ipv4_address=?",
                (data["scope_id"], target, data["target_ip"]),
            ).fetchone()
            allowed = (device[1] == data["scope_id"] and device[0] is None
                       and address in ipaddress.ip_network(target, strict=False)
                       and address.is_global and approved is not None)
        except ValueError:
            allowed = False
    elif scope_type == "HOSTNAME":
        approved = connection.execute(
            "SELECT 1 FROM scope_hostname_addresses WHERE scope_id=? AND ipv4_address=? AND approved=1",
            (data["scope_id"], data["target_ip"]),
        ).fetchone()
        allowed = (device[1] == data["scope_id"] and device[0] is None and address.is_global
                   and data["approved_hostname"] in (None, target) and approved is not None)
    else:
        allowed = False
    if not allowed:
        raise HttpEndpointPersistenceError("Target is outside the authorized scope.")
    approved_hostname = target if scope_type == "HOSTNAME" else None
    if data["approved_hostname"] not in (None, approved_hostname):
        raise HttpEndpointPersistenceError("Approved hostname does not match the authorized scope.")
    data["approved_hostname"] = approved_hostname
    if data["scheme"] == "https":
        data["tls"] = _validate_tls(data["tls"], data["target_ip"], approved_hostname)
        if data["outcome"] == "TLS_VERIFICATION_FAILED" and data["tls"]["verification_status"] != "FAILED":
            raise HttpEndpointPersistenceError("TLS verification outcome and metadata disagree.")
        if data["outcome"] == "TLS_HANDSHAKE_FAILED" and data["tls"]["verification_status"] != "NOT_COMPLETED":
            raise HttpEndpointPersistenceError("TLS handshake outcome and metadata disagree.")
        if data["outcome"] == "RESPONSE_RECEIVED" and data["tls"]["verification_status"] != "VERIFIED":
            raise HttpEndpointPersistenceError("HTTPS response requires a verified TLS handshake.")
    port = connection.execute(
        """SELECT p.device_id, p.port_number, p.transport, p.state,
                  (SELECT o.ip_address FROM port_observations o
                   WHERE o.port_id=p.id AND o.device_id=p.device_id
                     AND lower(o.transport)='tcp' AND lower(o.state)='open'
                   ORDER BY o.observed_at DESC, o.id DESC LIMIT 1) AS observed_ip
           FROM ports p WHERE p.id=?""",
        (data["port_id"],),
    ).fetchone()
    if (port is None or port[0] != data["device_id"] or str(port[2]).lower() != "tcp"
            or str(port[3]).lower() != "open" or port[4] != data["target_ip"]
            or type(port[1]) is not int or not 1 <= port[1] <= 65535):
        raise HttpEndpointPersistenceError("Port is not an observed open TCP port for the target device.")
    host = target if scope_type == "HOSTNAME" else data["target_ip"]
    expected_host = host if port[1] == 80 else f"{host}:{port[1]}"
    supplied_host = data["host"]
    if supplied_host != expected_host:
        raise HttpEndpointPersistenceError("HTTP Host value does not match the authorized endpoint.")


def persist_http_endpoint_observation(result, db_path=DB_PATH, *, started_at=None, completed_at=None):
    data = _metadata(result)
    started = _timestamp(started_at, "started_at") if started_at is not None else data["observed_at"]
    completed = _timestamp(completed_at, "completed_at") if completed_at is not None else data["observed_at"]
    if datetime.fromisoformat(started) > datetime.fromisoformat(completed):
        raise HttpEndpointPersistenceError("Run start time cannot follow completion time.")
    connection = get_connection(db_path)
    try:
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise HttpEndpointPersistenceError("SQLite foreign-key enforcement is required.")
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        _validate_relationships(connection, data)
        stored_count = connection.execute(
            "SELECT COUNT(*) FROM http_endpoint_observations WHERE scope_id=?",
            (data["scope_id"],),
        ).fetchone()[0]
        if stored_count >= MAX_HTTP_ENDPOINT_OBSERVATIONS_PER_SCOPE:
            raise HttpEndpointPersistenceError("Scope endpoint history reached its bounded retention cap.")
        scan_run_id = str(uuid.uuid4())
        cursor = connection.execute(
            """INSERT INTO recon_scan_runs
               (id, scope_id, profile, scanner, scanner_version, started_at, completed_at, status, error_category)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_run_id, data["scope_id"], SCAN_PROFILE, SCANNER_ID, "1.0", started,
             completed, "COMPLETED" if data["outcome"] == "RESPONSE_RECEIVED" else "FAILED",
             data["error_category"]),
        )
        if cursor.rowcount != 1:
            raise HttpEndpointPersistenceError("Scan run could not be created.")
        target_cursor = connection.execute(
            """INSERT INTO recon_scan_targets
               (run_id, target_ip, device_id, started_at, completed_at, outcome, error_category)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (scan_run_id, data["target_ip"], data["device_id"], started, completed,
             "COMPLETED" if data["outcome"] == "RESPONSE_RECEIVED" else "FAILED",
             data["error_category"]),
        )
        target_id = target_cursor.lastrowid
        endpoint_cursor = connection.execute(
            """INSERT INTO http_endpoint_observations
               (scope_id, device_id, port_id, scan_target_id, scheme, target_ip, approved_hostname,
                observed_at, source, outcome, error_category, status_code, response_headers_json,
                content_type, content_length, server_identifier, redirect_location)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data["scope_id"], data["device_id"], data["port_id"], target_id, data["scheme"],
             data["target_ip"], data["approved_hostname"], data["observed_at"], data["source"],
             data["outcome"], data["error_category"], data["status_code"],
             data["response_headers_json"], data["content_type"], data["content_length"],
             data["server_identifier"], data["redirect_location"]),
        )
        endpoint_id = endpoint_cursor.lastrowid
        if data["tls"] is not None:
            tls = data["tls"]
            connection.execute(
                """INSERT INTO http_tls_observations
                   (endpoint_observation_id, verification_status, hostname_verification,
                    ip_address_verification, verification_name, protocol_version, cipher_name,
                    cipher_protocol, cipher_bits, certificate_subject_json, certificate_issuer_json,
                    not_before, not_after, subject_alt_names_json, sha256_fingerprint, error_category)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (endpoint_id, tls["verification_status"], tls["hostname_verification"],
                 tls["ip_address_verification"], tls["verification_name"], tls["protocol_version"],
                 tls["cipher_name"], tls["cipher_protocol"], tls["cipher_bits"],
                 tls["certificate_subject_json"], tls["certificate_issuer_json"], tls["not_before"],
                 tls["not_after"], tls["subject_alt_names_json"], tls["sha256_fingerprint"], tls["error_category"]),
            )
        connection.commit()
        return {"observation_id": endpoint_id, "scan_run_id": scan_run_id, "scan_target_id": target_id}
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
