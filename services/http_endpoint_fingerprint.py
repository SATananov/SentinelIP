import asyncio
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import sqlite3
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from database.db import DB_PATH, get_connection
from database.inventory import get_device
from database.networks import get_network
from database.scopes import get_scope, require_cidr_membership
from services.hostname_resolution import HostnameResolver
from services.hostname_scope_discovery import (
    HostnameReauthorizationRequired,
    HostnameResolverUnavailable,
    verify_hostname_resolution,
)
from services.public_target_policy import normalize_public_ipv4
from services.scope_authorization import (
    ScopeAuthorizationError,
    require_hostname_scope,
    require_private_network_scope,
    require_public_cidr_scope,
    require_public_ipv4_scope,
)
from services.target_policy import validate_cidr


SOURCE_ID = "http-head-v1"
HTTP_OPERATION_LIMIT = 4
HTTP_CONNECT_TIMEOUT_SECONDS = 3.0
HTTP_TOTAL_TIMEOUT_SECONDS = 8.0
HTTP_MAX_HEADER_BYTES = 32_768
HTTP_MAX_METADATA_BYTES = 8_192
HTTP_MAX_HEADER_VALUE_BYTES = 512
HTTP_MAX_REDIRECT_BYTES = 1_024
TLS_MAX_HANDSHAKE_BYTES = 262_144
TLS_MAX_METADATA_ENTRIES = 8
TLS_MAX_METADATA_VALUE_BYTES = 128
_HTTP_OPERATION_SLOTS = threading.BoundedSemaphore(HTTP_OPERATION_LIMIT)
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?\Z")
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SAFE_HEADERS = (
    "date",
    "content-type",
    "content-length",
    "server",
    "cache-control",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
)


class HttpEndpointError(ValueError):
    def __init__(self, message, status_code=403):
        super().__init__(message)
        self.status_code = status_code


class _HeaderLimitExceeded(Exception):
    pass


class _MalformedResponse(Exception):
    pass


class _DeadlineExceeded(Exception):
    pass


class _TLSHandshakeFailure(Exception):
    def __init__(self, category, *, verification_failed=False, hostname_failed=False):
        super().__init__(category)
        self.category = category
        self.verification_failed = verification_failed
        self.hostname_failed = hostname_failed


class _DirectSocketChannel:
    def __init__(self, sock):
        self.sock = sock
        self.loop = asyncio.get_running_loop()

    async def sendall(self, data, deadline):
        await _wait_until(self.loop.sock_sendall(self.sock, data), deadline)

    async def recv(self, size, deadline):
        return await _wait_until(self.loop.sock_recv(self.sock, size), deadline)

    def close(self):
        self.sock.close()


class _TLSChannel:
    def __init__(self, channel, ssl_object, incoming, outgoing):
        self.channel = channel
        self.ssl_object = ssl_object
        self.incoming = incoming
        self.outgoing = outgoing
        self.received_handshake_bytes = 0

    @classmethod
    async def establish(cls, channel, context, server_hostname, deadline):
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise _TLSHandshakeFailure("verification_policy_invalid", verification_failed=True)
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        try:
            ssl_object = context.wrap_bio(
                incoming, outgoing, server_side=False, server_hostname=server_hostname,
            )
            wrapped = cls(channel, ssl_object, incoming, outgoing)
            await wrapped._handshake(deadline)
            return wrapped
        except _TLSHandshakeFailure:
            raise
        except ssl.SSLCertVerificationError as exc:
            category = _certificate_error_category(exc)
            raise _TLSHandshakeFailure(
                category, verification_failed=True,
                hostname_failed=category in {"hostname_mismatch", "ip_address_mismatch"},
            ) from exc
        except ssl.SSLError as exc:
            raise _TLSHandshakeFailure(_tls_error_category(exc)) from exc
        except _DeadlineExceeded as exc:
            raise _TLSHandshakeFailure("handshake_timeout") from exc

    async def _flush(self, deadline):
        while self.outgoing.pending:
            block = self.outgoing.read(min(self.outgoing.pending, 16_384))
            await _wait_until(self.channel.sendall(block, deadline), deadline)

    async def _receive_encrypted(self, deadline, *, handshake=False):
        limit = TLS_MAX_HANDSHAKE_BYTES - self.received_handshake_bytes if handshake else 16_384
        if limit <= 0:
            raise _TLSHandshakeFailure("handshake_size_limit")
        block = await _wait_until(
            self.channel.recv(min(16_384, limit), deadline), deadline,
        )
        if not block:
            self.incoming.write_eof()
            return
        if handshake:
            self.received_handshake_bytes += len(block)
        self.incoming.write(block)

    async def _handshake(self, deadline):
        while True:
            try:
                self.ssl_object.do_handshake()
                await self._flush(deadline)
                return
            except ssl.SSLWantReadError:
                await self._flush(deadline)
                await self._receive_encrypted(deadline, handshake=True)
            except ssl.SSLWantWriteError:
                await self._flush(deadline)

    async def sendall(self, data, deadline):
        view = memoryview(data)
        while view:
            try:
                written = self.ssl_object.write(view)
                view = view[written:]
                await self._flush(deadline)
            except ssl.SSLWantReadError:
                await self._flush(deadline)
                await self._receive_encrypted(deadline)
            except ssl.SSLWantWriteError:
                await self._flush(deadline)

    async def recv(self, size, deadline):
        while True:
            try:
                return self.ssl_object.read(size)
            except ssl.SSLWantReadError:
                await self._flush(deadline)
                await self._receive_encrypted(deadline)
            except ssl.SSLWantWriteError:
                await self._flush(deadline)
            except ssl.SSLZeroReturnError:
                return b""

    def close(self):
        self.channel.close()


class DirectIPv4Connector:
    async def connect(self, target_ip, port, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _DeadlineExceeded
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.sock_connect(sock, (target_ip, port)),
                timeout=min(HTTP_CONNECT_TIMEOUT_SECONDS, remaining),
            )
        except asyncio.TimeoutError as exc:
            sock.close()
            raise _DeadlineExceeded from exc
        except BaseException:
            sock.close()
            raise
        return _DirectSocketChannel(sock)


async def _wait_until(awaitable, deadline, timeout_cap=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _DeadlineExceeded
    timeout = remaining if timeout_cap is None else min(remaining, timeout_cap)
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise _DeadlineExceeded from exc


def _certificate_error_category(error):
    code = getattr(error, "verify_code", None)
    message = str(getattr(error, "verify_message", "") or error).lower()
    if code in {10, 11} or "expired" in message:
        return "certificate_expired"
    if code in {9} or "not yet valid" in message:
        return "certificate_not_yet_valid"
    if code in {18, 19} or "self signed" in message:
        return "self_signed_certificate"
    if code in {62} or "hostname mismatch" in message:
        return "hostname_mismatch"
    if code in {64} or "ip address mismatch" in message:
        return "ip_address_mismatch"
    if any(token in message for token in ("malformed", "decode", "bad certificate")):
        return "malformed_certificate"
    return "untrusted_certificate"


def _tls_error_category(error):
    reason = str(getattr(error, "reason", "")).upper()
    message = str(error).lower()
    if (reason in {"UNSUPPORTED_PROTOCOL", "PROTOCOL_VERSION"}
            or "protocol version" in message or "unsupported protocol" in message):
        return "unsupported_protocol"
    if (reason in {"BAD_CERTIFICATE", "CERTIFICATE_UNKNOWN", "DECODE_ERROR"}
            or any(token in message for token in ("bad certificate", "decode error", "malformed certificate"))):
        return "malformed_certificate"
    return "handshake_failure"


def _bounded_certificate_values(values, *, nested=False):
    result = []
    limit = 4 if nested else TLS_MAX_METADATA_ENTRIES
    for item in values[:limit]:
        if nested and isinstance(item, (list, tuple)):
            for key, value in item[:4]:
                result.append({
                    "name": _truncate_utf8(str(key), 64),
                    "value": _truncate_utf8(str(value), TLS_MAX_METADATA_VALUE_BYTES),
                })
                if len(result) >= TLS_MAX_METADATA_ENTRIES:
                    return result
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            result.append({
                "type": _truncate_utf8(str(item[0]), 32),
                "value": _truncate_utf8(str(item[1]), TLS_MAX_METADATA_VALUE_BYTES),
            })
    return result


def _empty_tls_observation(endpoint, *, error_category=None, certificate_status="NOT_COMPLETED"):
    hostname = endpoint["hostname"]
    return {
        "protocol_version": None,
        "cipher": None,
        "certificate_subject": [],
        "certificate_issuer": [],
        "not_before": None,
        "not_after": None,
        "subject_alt_names": [],
        "sha256_fingerprint": None,
        "certificate_verification": certificate_status,
        "hostname_verification": "NOT_COMPLETED" if hostname else None,
        "ip_address_verification": None if hostname else "NOT_COMPLETED",
        "verification_name": hostname or endpoint["target_ip"],
        "error_category": error_category,
    }


def _verified_tls_observation(ssl_object, endpoint):
    try:
        certificate = ssl_object.getpeercert()
        certificate_der = ssl_object.getpeercert(binary_form=True)
    except (ssl.SSLError, ValueError) as exc:
        raise _TLSHandshakeFailure("malformed_certificate") from exc
    if not certificate or not certificate_der:
        raise _TLSHandshakeFailure("malformed_certificate")
    cipher = ssl_object.cipher()
    if not cipher:
        raise _TLSHandshakeFailure("handshake_failure")
    return {
        "protocol_version": _truncate_utf8(str(ssl_object.version() or ""), 32),
        "cipher": {
            "name": _truncate_utf8(str(cipher[0]), 128),
            "protocol": _truncate_utf8(str(cipher[1]), 32),
            "bits": int(cipher[2]),
        },
        "certificate_subject": _bounded_certificate_values(certificate.get("subject", ()), nested=True),
        "certificate_issuer": _bounded_certificate_values(certificate.get("issuer", ()), nested=True),
        "not_before": _truncate_utf8(str(certificate.get("notBefore", "")), 64) or None,
        "not_after": _truncate_utf8(str(certificate.get("notAfter", "")), 64) or None,
        "subject_alt_names": _bounded_certificate_values(certificate.get("subjectAltName", ())),
        "sha256_fingerprint": hashlib.sha256(certificate_der).hexdigest(),
        "certificate_verification": "VERIFIED",
        "hostname_verification": "MATCHED" if endpoint["hostname"] else None,
        "ip_address_verification": None if endpoint["hostname"] else "MATCHED",
        "verification_name": endpoint["hostname"] or endpoint["target_ip"],
        "error_category": None,
    }


def _result_with_tls(result, scheme, endpoint, observation=None, error_category=None):
    if scheme != "https":
        return result
    tls = observation or _empty_tls_observation(endpoint, error_category=error_category)
    if error_category is not None and observation is None:
        tls["error_category"] = error_category
    combined = {**result, "tls": tls}
    _bound_metadata(combined)
    return combined


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_size(value):
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))


def _sanitize_redirect(value):
    if not isinstance(value, str) or len(value.encode("utf-8", errors="replace")) > 4_096:
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme and scheme not in {"http", "https"}:
            return None
        authority = ""
        if parsed.netloc:
            hostname = parsed.hostname
            if not hostname:
                return None
            if ":" in hostname:
                hostname = f"[{hostname}]"
            port = parsed.port
            authority = hostname if port is None else f"{hostname}:{port}"
        path = parsed.path[:HTTP_MAX_REDIRECT_BYTES]
        return urlunsplit((scheme, authority, path, "", ""))[:HTTP_MAX_REDIRECT_BYTES]
    except (ValueError, UnicodeError):
        return None


def _validate_private_address(target, cidr):
    try:
        address = ipaddress.ip_address(target)
        network = ipaddress.ip_network(validate_cidr(cidr).cidr)
    except (TypeError, ValueError) as exc:
        raise HttpEndpointError("Authorized target address is invalid.") from exc
    if (not isinstance(address, ipaddress.IPv4Address)
            or address not in network
            or not address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved):
        raise HttpEndpointError("Target is outside the supported private IPv4 policy.")
    return str(address)


class HttpEndpointFingerprintService:
    def __init__(self, db_path=DB_PATH, *, resolver=None, connector=None, operation_slots=None,
                 total_timeout_seconds=HTTP_TOTAL_TIMEOUT_SECONDS):
        self.db_path = db_path
        self.resolver = resolver or HostnameResolver()
        self.connector = connector or DirectIPv4Connector()
        self.operation_slots = operation_slots or _HTTP_OPERATION_SLOTS
        self.total_timeout_seconds = min(float(total_timeout_seconds), HTTP_TOTAL_TIMEOUT_SECONDS)

    def _authorized_endpoint(self, scope_id, device_id, port_id):
        scope = get_scope(scope_id, self.db_path)
        if scope is None:
            raise HttpEndpointError("Authorized scope was not found.", 404)
        if scope.get("authorized") is not True or scope.get("enabled") is not True:
            raise HttpEndpointError("An enabled authorized scope is required.")
        if not all(isinstance(scope.get(key), str) and scope[key].strip() for key in (
                "authorization_confirmed_at", "authorization_confirmation_version", "authorization_source")):
            raise HttpEndpointError("Persisted scope confirmation is required.")

        device = get_device(device_id, db_path=self.db_path)
        if device is None:
            raise HttpEndpointError("Device was not found in the authorized scope.", 404)
        target_ip = device.get("last_ip_address")
        hostname = None

        if scope.get("scope_type") == "PRIVATE_NETWORK":
            network = get_network(scope.get("network_id"), db_path=self.db_path)
            try:
                require_private_network_scope(network, scope)
                target_ip = _validate_private_address(target_ip, network["cidr"])
            except (ScopeAuthorizationError, TypeError, KeyError) as exc:
                raise HttpEndpointError("Private network scope authorization is invalid.") from exc
            if device.get("network_id") != network.get("id"):
                raise HttpEndpointError("Device does not belong to the authorized scope.", 404)
        elif scope.get("scope_type") == "PUBLIC_IPV4":
            try:
                authorized_ip = require_public_ipv4_scope(scope)
                target_ip = normalize_public_ipv4(target_ip)
            except (ScopeAuthorizationError, ValueError) as exc:
                raise HttpEndpointError("Public target authorization is invalid.") from exc
            if target_ip != authorized_ip:
                raise HttpEndpointError("Device is outside the authorized scope.", 404)
            if device.get("scope_id") != scope_id or device.get("network_id") is not None:
                raise HttpEndpointError("Device does not belong to the authorized scope.", 404)
        elif scope.get("scope_type") == "PUBLIC_CIDR":
            try:
                require_public_cidr_scope(scope)
                addresses = require_cidr_membership(scope, self.db_path)
                target_ip = normalize_public_ipv4(target_ip)
            except (ScopeAuthorizationError, ValueError) as exc:
                raise HttpEndpointError("Public CIDR authorization is invalid.") from exc
            if target_ip not in addresses or device.get("scope_id") != scope_id or device.get("network_id") is not None:
                raise HttpEndpointError("Device is outside the authorized scope.", 404)
        elif scope.get("scope_type") == "HOSTNAME":
            try:
                hostname = require_hostname_scope(scope)
                approved = tuple(normalize_public_ipv4(value) for value in scope.get("approved_addresses", []))
                target_ip = normalize_public_ipv4(target_ip)
            except (ScopeAuthorizationError, ValueError) as exc:
                raise HttpEndpointError("Hostname scope authorization is invalid.") from exc
            if (target_ip not in approved or device.get("scope_id") != scope_id
                    or device.get("network_id") is not None):
                raise HttpEndpointError("Device is outside the authorized hostname scope.", 404)
        else:
            raise HttpEndpointError("Scope type is not supported for HTTP inspection.")

        if type(port_id) is not int or port_id <= 0:
            raise HttpEndpointError("TCP port identifier is invalid.", 422)
        connection = get_connection(self.db_path)
        try:
            with connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    """SELECT p.id, p.device_id, p.port_number, p.transport, p.state,
                              (SELECT o.ip_address FROM port_observations o
                               WHERE o.port_id=p.id AND o.device_id=p.device_id
                                 AND lower(o.transport)='tcp' AND lower(o.state)='open'
                               ORDER BY o.observed_at DESC, o.id DESC LIMIT 1) AS observed_ip
                       FROM ports p WHERE p.id=? AND p.device_id=?""",
                    (port_id, device_id),
                ).fetchone()
        finally:
            connection.close()
        if (row is None or row["device_id"] != device_id
                or str(row["transport"]).lower() != "tcp"
                or str(row["state"]).lower() != "open"
                or row["observed_ip"] != target_ip
                or type(row["port_number"]) is not int
                or not 1 <= row["port_number"] <= 65535):
            raise HttpEndpointError("An open, observed TCP port for this device is required.", 404)

        host_header = hostname or target_ip
        if row["port_number"] != 80:
            host_header = f"{host_header}:{row['port_number']}"
        return {
            "scope": scope,
            "scope_id": scope_id,
            "device_id": device_id,
            "port_id": port_id,
            "port": row["port_number"],
            "target_ip": target_ip,
            "hostname": hostname,
            "host_header": host_header,
        }

    async def _revalidate_hostname(self, endpoint, deadline):
        scope = endpoint["scope"]
        if scope.get("scope_type") != "HOSTNAME":
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _DeadlineExceeded
        resolver = self.resolver
        if isinstance(resolver, HostnameResolver) and resolver.timeout_seconds > remaining:
            resolver = HostnameResolver(
                lookup=resolver.lookup,
                timeout_seconds=max(0.01, remaining),
                max_addresses=resolver.max_addresses,
            )
        try:
            addresses = verify_hostname_resolution(scope, resolver, db_path=self.db_path)
        except HostnameResolverUnavailable as exc:
            if time.monotonic() >= deadline:
                raise _DeadlineExceeded from exc
            raise
        if endpoint["target_ip"] not in addresses:
            raise HostnameReauthorizationRequired("Approved hostname address set changed.")

    async def inspect(self, scope_id, device_id, port_id, *, scheme="http"):
        if not isinstance(scheme, str) or scheme not in ("http", "https"):
            raise HttpEndpointError("Only HTTP and HTTPS schemes are supported.", 422)
        deadline = time.monotonic() + self.total_timeout_seconds
        endpoint = self._authorized_endpoint(scope_id, device_id, port_id)
        base = {
            "scope_id": scope_id,
            "device_id": device_id,
            "port_id": port_id,
            "scheme": scheme,
            "target_ip": endpoint["target_ip"],
            "host": endpoint["host_header"],
            "observed_at": _timestamp(),
            "source": SOURCE_ID if scheme == "http" else "https-tls-head-v1",
            "status_code": None,
            "response_headers": {},
            "content_type": None,
            "content_length": None,
            "server_identifier": None,
            "redirect_location": None,
            "outcome": None,
            "error_category": None,
        }
        if not self.operation_slots.acquire(blocking=False):
            result = {**base, "outcome": "CAPACITY_REJECTED", "error_category": "capacity"}
            return _result_with_tls(result, scheme, endpoint, error_category="capacity")

        channel = None
        tls_observation = None
        phase = "authorization"
        try:
            await self._revalidate_hostname(endpoint, deadline)
            endpoint = self._authorized_endpoint(scope_id, device_id, port_id)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _DeadlineExceeded
            phase = "connect"
            channel = await _wait_until(
                self.connector.connect(endpoint["target_ip"], endpoint["port"], deadline),
                deadline,
                HTTP_CONNECT_TIMEOUT_SECONDS,
            )
            if scheme == "https":
                phase = "tls_handshake"
                context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                server_hostname = endpoint["hostname"] or endpoint["target_ip"]
                channel = await _TLSChannel.establish(channel, context, server_hostname, deadline)
                tls_observation = _verified_tls_observation(channel.ssl_object, endpoint)
            phase = "http_request"
            request = (
                f"HEAD / HTTP/1.1\r\nHost: {endpoint['host_header']}\r\n"
                f"User-Agent: SentinelIP-HTTP-Fingerprint/1.0\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            await _wait_until(channel.sendall(request, deadline), deadline)
            status_code, headers = await _read_bounded_response(channel, deadline)
            selected = _selected_headers(headers)
            content_length = _parse_content_length(headers.get("content-length", []))
            content_type = _single_header(selected, "content-type")
            server_value = _single_header(selected, "server")
            server_identifier = ({
                "value": server_value,
                "confidence": "LOW",
                "source": "http_response_header",
            } if server_value is not None else None)
            redirect_values = headers.get("location", [])
            redirect = _sanitize_redirect(redirect_values[0]) if len(redirect_values) == 1 else None
            selected.pop("content-length", None)
            selected.pop("content-type", None)
            selected.pop("server", None)
            result = {
                **base,
                "status_code": status_code,
                "response_headers": selected,
                "content_type": content_type,
                "content_length": content_length,
                "server_identifier": server_identifier,
                "redirect_location": redirect,
                "outcome": "RESPONSE_RECEIVED",
            }
            _bound_metadata(result)
            return _result_with_tls(result, scheme, endpoint, tls_observation)
        except asyncio.CancelledError:
            raise
        except _TLSHandshakeFailure as exc:
            status = "FAILED" if exc.verification_failed else "NOT_COMPLETED"
            tls_observation = _empty_tls_observation(
                endpoint, error_category=exc.category, certificate_status=status,
            )
            if exc.hostname_failed:
                if endpoint["hostname"]:
                    tls_observation["hostname_verification"] = "FAILED"
                else:
                    tls_observation["ip_address_verification"] = "FAILED"
            outcome = "TLS_VERIFICATION_FAILED" if exc.verification_failed else (
                "TIMEOUT" if exc.category == "handshake_timeout" else "TLS_HANDSHAKE_FAILED"
            )
            result = {
                **base,
                "outcome": outcome,
                "error_category": exc.category,
            }
            return _result_with_tls(result, scheme, endpoint, tls_observation)
        except _DeadlineExceeded:
            result = {**base, "outcome": "TIMEOUT", "error_category": "timeout"}
            tls_error = (
                "connection_timeout" if phase == "connect" else
                "operation_timeout" if phase == "http_request" else
                "authorization_timeout"
            )
            return _result_with_tls(
                result, scheme, endpoint, tls_observation,
                tls_error if scheme == "https" else None,
            )
        except _HeaderLimitExceeded:
            result = {**base, "outcome": "HEADER_LIMIT_EXCEEDED", "error_category": "header_limit"}
            return _result_with_tls(result, scheme, endpoint, tls_observation, "header_limit")
        except _MalformedResponse:
            result = {**base, "outcome": "MALFORMED_RESPONSE", "error_category": "malformed_response"}
            return _result_with_tls(result, scheme, endpoint, tls_observation, "malformed_response")
        except (OSError, asyncio.TimeoutError):
            result = {**base, "outcome": "CONNECTION_FAILED", "error_category": "connection_error"}
            return _result_with_tls(result, scheme, endpoint, tls_observation, "connection_error")
        except HostnameResolverUnavailable:
            result = {**base, "outcome": "DNS_REVALIDATION_FAILED", "error_category": "dns_unavailable"}
            return _result_with_tls(result, scheme, endpoint, tls_observation, "dns_unavailable")
        finally:
            try:
                if channel is not None:
                    channel.close()
            except Exception:
                pass
            finally:
                self.operation_slots.release()


async def _read_bounded_response(channel, deadline):
    data = bytearray()
    terminator = b"\r\n\r\n"
    end = -1
    while end < 0:
        remaining = HTTP_MAX_HEADER_BYTES - len(data)
        if remaining <= 0:
            raise _HeaderLimitExceeded
        block = await _wait_until(channel.recv(min(4096, remaining), deadline), deadline)
        if not block:
            raise _MalformedResponse
        if len(block) > remaining:
            raise _HeaderLimitExceeded
        data.extend(block)
        end = data.find(terminator)
    header_size = end + len(terminator)
    if header_size > HTTP_MAX_HEADER_BYTES:
        raise _HeaderLimitExceeded
    raw_lines = bytes(data[:end]).split(b"\r\n")
    if not raw_lines or not _STATUS_LINE.fullmatch(raw_lines[0]):
        raise _MalformedResponse
    status_code = int(raw_lines[0].split(b" ", 2)[1])
    headers = {}
    for line in raw_lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise _MalformedResponse
        name, value = line.split(b":", 1)
        if not _HEADER_NAME.fullmatch(name):
            raise _MalformedResponse
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise _MalformedResponse
        key = name.decode("ascii").lower()
        if key in _SAFE_HEADERS or key == "location":
            headers.setdefault(key, []).append(value.decode("latin-1").strip(" \t"))
    return status_code, headers


def _truncate_utf8(value, max_bytes):
    encoded = value.encode("utf-8", errors="replace")
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _selected_headers(headers):
    result = {}
    for name in _SAFE_HEADERS:
        values = headers.get(name, [])
        if not values or name == "content-length":
            continue
        if name == "content-type" and len(values) != 1:
            continue
        result[name] = _truncate_utf8(", ".join(values), HTTP_MAX_HEADER_VALUE_BYTES)
    return result


def _single_header(headers, name):
    value = headers.get(name)
    return value if isinstance(value, str) and value else None


def _parse_content_length(values):
    if len(values) != 1 or not re.fullmatch(r"[0-9]{1,20}", values[0]):
        return None
    try:
        parsed = int(values[0])
    except ValueError:
        return None
    return parsed if parsed <= 9_223_372_036_854_775_807 else None


def _bound_metadata(result):
    result["redirect_location"] = (
        _truncate_utf8(result["redirect_location"], HTTP_MAX_REDIRECT_BYTES)
        if result.get("redirect_location") else None
    )
    while _json_size(result) > HTTP_MAX_METADATA_BYTES and result["response_headers"]:
        result["response_headers"].pop(next(reversed(result["response_headers"])))
    if _json_size(result) > HTTP_MAX_METADATA_BYTES:
        result["redirect_location"] = None
    if _json_size(result) > HTTP_MAX_METADATA_BYTES:
        result["server_identifier"] = None
    if _json_size(result) > HTTP_MAX_METADATA_BYTES:
        raise _MalformedResponse
