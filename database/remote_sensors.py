"""Transactional remote-sensor foundation. No scanner, job or result-ingestion path."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import sqlite3
import json
import uuid
import re

from database.db import DB_PATH, get_connection, initialize_database
from database.management_audit import record_event
from services.remote_sensor_models import (
    IssuedSecret, LocalScopeGrant, RemoteSensorError, RemoteSensorAuthError,
    RemoteSensorCapacityError, RemoteSensorConflictError, RemoteSensorRateLimitError,
    RemoteSensorReplayError,
    capabilities, fleet_sensor_health, private_lan, sensor_status,
)
from services.scope_authorization import require_private_network_scope
from services.telemetry_auth import TOKEN_ITERATIONS, hash_sensor_token, verify_sensor_token

TRANSPORT_FRESHNESS_SECONDS = 300
TRANSPORT_RATE_WINDOW_SECONDS = 60
TRANSPORT_RATE_LIMIT = 50
TRANSPORT_NONCES_PER_SENSOR = 512
TRANSPORT_NONCES_GLOBAL = 100_000
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _text(value, label, maximum=128, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise RemoteSensorError(f"Invalid {label}.")
    return value.strip()


def _boolean(value):
    if type(value) is not bool:
        raise RemoteSensorError("Enabled state must be boolean.")
    return int(value)


def _secret_hash(token):
    if not isinstance(token, str) or not 40 <= len(token) <= 128:
        raise RemoteSensorAuthError("Enrollment credential rejected.")
    return hashlib.sha256(("sentinelip-remote-enrollment-v1:" + token).encode()).hexdigest()


class RemoteSensorStore:
    def __init__(self, db_path=DB_PATH, *, clock=None):
        self.db_path = db_path
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        initialize_database(db_path)

    def _now(self):
        now = self.clock()
        if now.tzinfo is None:
            raise RemoteSensorError("An aware server clock is required.")
        return now.astimezone(timezone.utc)

    @contextmanager
    def _connection(self, *, write=False):
        connection = get_connection(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _site(c, site_id, *, active=False):
        row = c.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        if row is None:
            raise RemoteSensorError("Site not found.")
        result = dict(row)
        result['enabled'] = bool(result['enabled'])
        if active and not result['enabled']:
            raise RemoteSensorError("Site is disabled.")
        return result

    def create_site(self, name, description='', enabled=True):
        name = _text(name, 'site name')
        description = _text(description, 'description', 1000, True)
        enabled = _boolean(enabled)
        now = self._now().isoformat()
        with self._connection(write=True) as c:
            site_id = c.execute(
                "INSERT INTO sites (name,description,enabled,created_at,updated_at) VALUES (?,?,?,?,?)",
                (name, description, enabled, now, now),
            ).lastrowid
            record_event(c, event_type="SITE_CREATED", entity_type="SITE", entity_id=site_id,
                         site_id=site_id, actor_type="LOCAL_OPERATOR",
                         new_state="ENABLED" if enabled else "DISABLED")
            return self._site(c, site_id)

    def get_site(self, site_id):
        with self._connection() as c:
            return self._site(c, site_id)

    def list_sites(self, limit=100, offset=0):
        self._page(limit, offset)
        with self._connection() as c:
            return [self._site(c, r[0]) for r in c.execute(
                "SELECT id FROM sites ORDER BY id LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()]

    @staticmethod
    def _page(limit, offset):
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset < 0:
            raise RemoteSensorError("Invalid pagination.")

    def set_site_enabled(self, site_id, enabled):
        enabled = _boolean(enabled)
        with self._connection(write=True) as c:
            site = self._site(c, site_id)
            prior = int(site['enabled'])
            c.execute("UPDATE sites SET enabled=?,updated_at=? WHERE id=?", (enabled, self._now().isoformat(), site_id))
            if prior != enabled:
                record_event(c, event_type="SITE_ENABLED" if enabled else "SITE_DISABLED",
                             entity_type="SITE", entity_id=site_id, site_id=site_id,
                             actor_type="LOCAL_OPERATOR", previous_state="ENABLED" if prior else "DISABLED",
                             new_state="ENABLED" if enabled else "DISABLED")
            return self._site(c, site_id)

    @staticmethod
    def _enrollment(row):
        return {key: row[key] for key in ('id', 'site_id', 'created_at', 'expires_at', 'revoked_at', 'consumed_at', 'sensor_id')}

    def create_enrollment(self, site_id, ttl_seconds=900):
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 3600:
            raise RemoteSensorError("Enrollment lifetime must be 60–3600 seconds.")
        token = secrets.token_urlsafe(32)
        now = self._now()
        with self._connection(write=True) as c:
            self._site(c, site_id, active=True)
            enrollment_id = c.execute(
                "INSERT INTO sensor_enrollment_tokens (site_id,token_hash,created_at,expires_at) VALUES (?,?,?,?)",
                (site_id, _secret_hash(token), now.isoformat(), (now + timedelta(seconds=ttl_seconds)).isoformat()),
            ).lastrowid
            row = c.execute("SELECT * FROM sensor_enrollment_tokens WHERE id=?", (enrollment_id,)).fetchone()
            record_event(c, event_type="ENROLLMENT_ISSUED", entity_type="SENSOR_ENROLLMENT",
                         entity_id=enrollment_id, site_id=site_id, actor_type="LOCAL_OPERATOR",
                         new_state="ISSUED", enrollment_expires_at=row['expires_at'])
            return IssuedSecret(self._enrollment(row), token)

    def list_enrollments(self, site_id, limit=100, offset=0):
        self._page(limit, offset)
        with self._connection() as c:
            self._site(c, site_id)
            return [self._enrollment(row) for row in c.execute(
                "SELECT * FROM sensor_enrollment_tokens WHERE site_id=? ORDER BY id LIMIT ? OFFSET ?", (site_id, limit, offset)
            )]

    def revoke_enrollment(self, enrollment_id):
        with self._connection(write=True) as c:
            row = c.execute("SELECT * FROM sensor_enrollment_tokens WHERE id=?", (enrollment_id,)).fetchone()
            if row is None:
                raise RemoteSensorError("Enrollment not found.")
            if row['revoked_at'] is None:
                c.execute("UPDATE sensor_enrollment_tokens SET revoked_at=? WHERE id=?", (self._now().isoformat(), enrollment_id))
                record_event(c, event_type="ENROLLMENT_REVOKED", entity_type="SENSOR_ENROLLMENT",
                             entity_id=enrollment_id, site_id=row['site_id'], actor_type="LOCAL_OPERATOR",
                             previous_state="CONSUMED" if row['consumed_at'] is not None else "ISSUED",
                             new_state="REVOKED")
            return self._enrollment(c.execute("SELECT * FROM sensor_enrollment_tokens WHERE id=?", (enrollment_id,)).fetchone())

    def consume_enrollment(self, token, *, name, platform, version, reported_capabilities=(), sensor_uuid=None):
        """Atomically create one identity and consume its site-bound invitation."""
        token_hash = _secret_hash(token)
        if sensor_uuid is None:
            sensor_uuid = str(uuid.uuid4())
        else:
            try:
                sensor_uuid = str(uuid.UUID(_text(sensor_uuid, 'sensor UUID', 36)))
            except ValueError as exc:
                raise RemoteSensorError('Invalid sensor UUID.') from exc
        name = _text(name, 'sensor name')
        platform = _text(platform, 'platform', 64)
        version = _text(version, 'version', 64)
        declared = capabilities(reported_capabilities)
        credential = secrets.token_urlsafe(32)
        salt = secrets.token_bytes(16)
        digest = hash_sensor_token(credential, salt)
        with self._connection(write=True) as c:
            now = self._now()
            row = c.execute("SELECT * FROM sensor_enrollment_tokens WHERE token_hash=?", (token_hash,)).fetchone()
            if row is None or row['consumed_at'] or row['revoked_at'] or datetime.fromisoformat(row['expires_at']) <= now:
                raise RemoteSensorAuthError("Enrollment credential rejected.")
            self._site(c, row['site_id'], active=True)
            if c.execute('SELECT 1 FROM remote_sensors WHERE sensor_uuid=?', (sensor_uuid,)).fetchone():
                raise RemoteSensorConflictError('Sensor UUID is already registered.')
            stamp = now.isoformat()
            sensor_id = c.execute(
                """INSERT INTO remote_sensors (site_id,sensor_uuid,name,platform,version,capabilities,
                enabled,credential_salt,credential_hash,credential_iterations,registered_at,created_at,updated_at)
                VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?)""",
                (row['site_id'], sensor_uuid, name, platform, version, json.dumps(declared),
                 salt.hex(), digest, TOKEN_ITERATIONS, stamp, stamp, stamp),
            ).lastrowid
            c.execute("UPDATE sensor_enrollment_tokens SET consumed_at=?,sensor_id=? WHERE id=?", (stamp, sensor_id, row['id']))
            record_event(c, event_type="ENROLLMENT_CONSUMED", entity_type="SENSOR_ENROLLMENT",
                         entity_id=row['id'], site_id=row['site_id'], sensor_id=sensor_id,
                         actor_type="SENSOR", previous_state="ISSUED", new_state="CONSUMED")
            record_event(c, event_type="SENSOR_REGISTERED", entity_type="SENSOR",
                         entity_id=sensor_id, site_id=row['site_id'], sensor_id=sensor_id,
                         actor_type="SENSOR", new_state="REGISTERED")
            return IssuedSecret(self._sensor(c, sensor_id), credential)

    def _sensor(self, c, sensor_id, *, active=False):
        row = c.execute("SELECT * FROM remote_sensors WHERE id=?", (sensor_id,)).fetchone()
        if row is None:
            raise RemoteSensorError("Sensor not found.")
        site = self._site(c, row['site_id'], active=active)
        if active and (not row['enabled'] or row['credential_revoked_at']):
            raise RemoteSensorError("Sensor is disabled.")
        result = {key: row[key] for key in (
            'id', 'site_id', 'sensor_uuid', 'name', 'platform', 'version', 'enabled',
            'last_seen_at', 'registered_at', 'created_at', 'updated_at', 'credential_revoked_at',
        )}
        result['enabled'] = bool(result['enabled'])
        result['capabilities'] = json.loads(row['capabilities'])
        result['status'] = sensor_status(enabled=result['enabled'] and not row['credential_revoked_at'], site_enabled=site['enabled'], last_seen_at=row['last_seen_at'], now=self._now())
        return result

    def get_sensor(self, sensor_id):
        with self._connection() as c:
            return self._sensor(c, sensor_id)

    def list_sensors(self, site_id, limit=100, offset=0):
        self._page(limit, offset)
        with self._connection() as c:
            self._site(c, site_id)
            return [self._sensor(c, r[0]) for r in c.execute(
                "SELECT id FROM remote_sensors WHERE site_id=? ORDER BY id LIMIT ? OFFSET ?", (site_id, limit, offset)
            ).fetchall()]

    def list_fleet_sensors(self, *, limit=100, offset=0, site_id=None,
                           status=None, platform=None, enabled=None):
        """Read a bounded all-sites inventory using one request-wide evaluation clock."""
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 100000:
            raise RemoteSensorError("Invalid fleet pagination.")
        if site_id is not None and (type(site_id) is not int or site_id <= 0):
            raise RemoteSensorError("Invalid site filter.")
        if status is not None and status not in {"REVOKED", "DISABLED", "PENDING", "ONLINE", "OFFLINE", "UNKNOWN"}:
            raise RemoteSensorError("Invalid fleet status filter.")
        if platform is not None and (not isinstance(platform, str) or not platform or len(platform) > 64):
            raise RemoteSensorError("Invalid platform filter.")
        if enabled is not None and type(enabled) is not bool:
            raise RemoteSensorError("Invalid enabled filter.")

        evaluated_at = self._now()
        with self._connection() as c:
            if site_id is not None and c.execute("SELECT 1 FROM sites WHERE id=?", (site_id,)).fetchone() is None:
                raise LookupError("Site not found.")

            def fleet_status_sql(last_seen_at, sensor_enabled, revoked_at, site_enabled):
                return fleet_sensor_health(
                    enabled=bool(sensor_enabled), site_enabled=None if site_enabled is None else bool(site_enabled),
                    credential_revoked_at=revoked_at, last_seen_at=last_seen_at, now=evaluated_at,
                )[0]

            c.create_function("fleet_status", 4, fleet_status_sql, deterministic=False)
            query = """
                WITH page_sensors AS (
                    SELECT rs.id, rs.sensor_uuid, rs.name, rs.site_id,
                           s.name AS site_name, s.enabled AS site_enabled,
                           rs.platform, rs.version, rs.enabled, rs.registered_at,
                           rs.last_seen_at, rs.credential_revoked_at, rs.capabilities
                    FROM remote_sensors rs
                    LEFT JOIN sites s ON s.id=rs.site_id
                    WHERE (? IS NULL OR rs.site_id=?)
                      AND (? IS NULL OR rs.platform=?)
                      AND (? IS NULL OR rs.enabled=?)
                      AND (? IS NULL OR fleet_status(rs.last_seen_at, rs.enabled,
                           rs.credential_revoked_at, s.enabled)=?)
                    ORDER BY rs.site_id ASC, lower(trim(rs.name)) ASC, rs.id ASC
                    LIMIT ? OFFSET ?
                ), page_assignments AS (
                    SELECT a.sensor_id, COUNT(*) AS assignment_count
                    FROM sensor_scope_assignments a
                    WHERE a.sensor_id IN (SELECT id FROM page_sensors)
                    GROUP BY a.sensor_id
                )
                SELECT p.*, COALESCE(a.assignment_count, 0) AS assignment_count
                FROM page_sensors p
                LEFT JOIN page_assignments a ON a.sensor_id=p.id
                ORDER BY p.site_id ASC, lower(trim(p.name)) ASC, p.id ASC
            """
            rows = c.execute(query, (
                site_id, site_id, platform, platform,
                None if enabled is None else int(enabled), None if enabled is None else int(enabled),
                status, status, limit + 1, offset,
            )).fetchall()

        has_more = len(rows) > limit
        items = []
        for row in rows[:limit]:
            row = dict(row)
            fleet_status, heartbeat_age = fleet_sensor_health(
                enabled=bool(row["enabled"]),
                site_enabled=None if row["site_enabled"] is None else bool(row["site_enabled"]),
                credential_revoked_at=row["credential_revoked_at"],
                last_seen_at=row["last_seen_at"], now=evaluated_at,
            )
            try:
                raw_capabilities = json.loads(row["capabilities"])
                declared_capabilities = list(capabilities(raw_capabilities))
            except (TypeError, ValueError, json.JSONDecodeError):
                declared_capabilities = None
            items.append({
                "id": row["id"], "sensor_uuid": row["sensor_uuid"], "name": row["name"],
                "site_id": row["site_id"], "site_name": row["site_name"],
                "site_enabled": None if row["site_enabled"] is None else bool(row["site_enabled"]),
                "platform": row["platform"], "version": row["version"],
                "enabled": bool(row["enabled"]), "registered_at": row["registered_at"],
                "last_seen_at": row["last_seen_at"], "status": fleet_status,
                "heartbeat_age_seconds": heartbeat_age,
                "capabilities": declared_capabilities,
                "assignment_count": row["assignment_count"],
            })
        return {
            "evaluated_at": evaluated_at.isoformat(), "items": items,
            "limit": limit, "offset": offset, "has_more": has_more,
        }

    def set_sensor_enabled(self, sensor_id, enabled):
        enabled = _boolean(enabled)
        with self._connection(write=True) as c:
            sensor = self._sensor(c, sensor_id)
            if enabled and sensor['credential_revoked_at'] is not None:
                raise RemoteSensorError("Revoked sensors require a new enrollment.")
            prior = int(sensor['enabled'])
            c.execute("UPDATE remote_sensors SET enabled=?,updated_at=? WHERE id=?", (enabled, self._now().isoformat(), sensor_id))
            if prior != enabled:
                record_event(c, event_type="SENSOR_ENABLED" if enabled else "SENSOR_DISABLED",
                             entity_type="SENSOR", entity_id=sensor_id, site_id=sensor['site_id'],
                             sensor_id=sensor_id, actor_type="LOCAL_OPERATOR",
                             previous_state="ENABLED" if prior else "DISABLED",
                             new_state="ENABLED" if enabled else "DISABLED")
            return self._sensor(c, sensor_id)

    def revoke_sensor(self, sensor_id):
        """Invalidate the credential permanently; enabling alone cannot restore it."""
        salt = secrets.token_bytes(16)
        digest = hash_sensor_token(secrets.token_urlsafe(32), salt)
        with self._connection(write=True) as c:
            sensor = self._sensor(c, sensor_id)
            now = self._now().isoformat()
            if sensor['credential_revoked_at'] is None:
                if sensor['enabled']:
                    record_event(c, event_type="SENSOR_DISABLED", entity_type="SENSOR",
                                 entity_id=sensor_id, site_id=sensor['site_id'], sensor_id=sensor_id,
                                 actor_type="LOCAL_OPERATOR", previous_state="ENABLED", new_state="DISABLED",
                                 )
                c.execute("UPDATE remote_sensors SET enabled=0,credential_salt=?,credential_hash=?,credential_revoked_at=?,updated_at=? WHERE id=?",
                          (salt.hex(), digest, now, now, sensor_id))
                record_event(c, event_type="SENSOR_CREDENTIAL_REVOKED", entity_type="SENSOR",
                             entity_id=sensor_id, site_id=sensor['site_id'], sensor_id=sensor_id,
                             actor_type="LOCAL_OPERATOR", previous_state="CREDENTIAL_ACTIVE",
                             new_state="CREDENTIAL_REVOKED")
            return self._sensor(c, sensor_id)

    def _authenticate(self, c, sensor_id, credential):
        if not isinstance(credential, str) or not 40 <= len(credential) <= 128:
            raise RemoteSensorAuthError("Sensor credential rejected.")
        row = c.execute("SELECT * FROM remote_sensors WHERE id=?", (sensor_id,)).fetchone()
        if row is None or not verify_sensor_token(credential, bytes.fromhex(row['credential_salt']), row['credential_hash'], row['credential_iterations']):
            raise RemoteSensorAuthError("Sensor credential rejected.")
        try:
            return self._sensor(c, sensor_id, active=True)
        except RemoteSensorError as exc:
            raise RemoteSensorAuthError("Sensor credential rejected.") from exc

    def authenticate_sensor(self, sensor_uuid, credential):
        """UUID is a lookup key only; the dedicated secret proves identity."""
        if not isinstance(sensor_uuid, str) or len(sensor_uuid) != 36:
            raise RemoteSensorAuthError('Sensor credential rejected.')
        with self._connection() as c:
            row = c.execute('SELECT id FROM remote_sensors WHERE sensor_uuid=?', (sensor_uuid,)).fetchone()
            if row is None:
                raise RemoteSensorAuthError('Sensor credential rejected.')
            return self._authenticate(c, row['id'], credential)

    def authorize_transport_request(self, sensor_uuid, credential, timestamp, nonce):
        """Authenticate and atomically admit a fresh, unique, rate-limited request."""
        if type(timestamp) is not int:
            raise RemoteSensorError('Invalid request timestamp.')
        if not isinstance(nonce, str) or not _NONCE_PATTERN.fullmatch(nonce):
            raise RemoteSensorError('Invalid request nonce.')
        now = int(self._now().timestamp())
        if abs(now - timestamp) > TRANSPORT_FRESHNESS_SECONDS:
            raise RemoteSensorError('Request timestamp is outside the allowed window.')
        with self._connection(write=True) as c:
            row = c.execute('SELECT id FROM remote_sensors WHERE sensor_uuid=?', (sensor_uuid,)).fetchone()
            if row is None:
                raise RemoteSensorAuthError('Sensor credential rejected.')
            sensor = self._authenticate(c, row['id'], credential)
            c.execute('DELETE FROM sensor_transport_nonces WHERE request_timestamp < ?',
                      (now - TRANSPORT_FRESHNESS_SECONDS,))
            if c.execute('SELECT 1 FROM sensor_transport_nonces WHERE sensor_id=? AND nonce=?',
                          (sensor['id'], nonce)).fetchone():
                raise RemoteSensorReplayError('Request nonce has already been used.')
            count = c.execute('SELECT COUNT(*) FROM sensor_transport_nonces WHERE sensor_id=? AND received_at > ?',
                              (sensor['id'], now - TRANSPORT_RATE_WINDOW_SECONDS)).fetchone()[0]
            if count >= TRANSPORT_RATE_LIMIT:
                raise RemoteSensorRateLimitError('Sensor request rate limit exceeded.')
            total = c.execute('SELECT COUNT(*) FROM sensor_transport_nonces').fetchone()[0]
            if total >= TRANSPORT_NONCES_GLOBAL:
                raise RemoteSensorCapacityError('Sensor transport capacity is temporarily exhausted.')
            sensor_count = c.execute('SELECT COUNT(*) FROM sensor_transport_nonces WHERE sensor_id=?',
                                     (sensor['id'],)).fetchone()[0]
            if sensor_count >= TRANSPORT_NONCES_PER_SENSOR:
                raise RemoteSensorRateLimitError('Sensor replay record limit exceeded.')
            c.execute('INSERT INTO sensor_transport_nonces VALUES (?,?,?,?)',
                      (sensor['id'], nonce, timestamp, now))
            return sensor

    def heartbeat(self, sensor_id, credential, *, platform, version, reported_capabilities=()):
        platform = _text(platform, 'platform', 64)
        version = _text(version, 'version', 64)
        declared = capabilities(reported_capabilities)
        with self._connection(write=True) as c:
            self._authenticate(c, sensor_id, credential)
            now = self._now().isoformat()
            c.execute("UPDATE remote_sensors SET platform=?,version=?,capabilities=?,last_seen_at=?,updated_at=? WHERE id=?",
                      (platform, version, json.dumps(declared), now, now, sensor_id))
            return self._sensor(c, sensor_id)

    @staticmethod
    def _scope(c, scope_id):
        row = c.execute("""SELECT s.*,l.network_id FROM authorized_scopes s
            LEFT JOIN network_scope_links l ON l.scope_id=s.id WHERE s.id=?""", (scope_id,)).fetchone()
        if row is None:
            raise RemoteSensorError("Scope not found.")
        scope = dict(row)
        scope['authorized'], scope['enabled'] = bool(scope['authorized']), bool(scope['enabled'])
        row = c.execute("SELECT * FROM networks WHERE id=?", (scope['network_id'],)).fetchone()
        network = dict(row) if row else None
        if network:
            network['authorized'], network['enabled'] = bool(network['authorized']), bool(network['enabled'])
        try:
            require_private_network_scope(network, scope)
        except ValueError as exc:
            raise RemoteSensorError("An enabled, confirmed private network scope is required.") from exc
        private_lan(scope['canonical_target'])
        return scope

    def assign_scope(self, sensor_id, scope_id):
        with self._connection(write=True) as c:
            sensor = self._sensor(c, sensor_id, active=True)
            scope = self._scope(c, scope_id)
            binding = c.execute("SELECT site_id FROM remote_scope_sites WHERE scope_id=?", (scope_id,)).fetchone()
            if binding and binding[0] != sensor['site_id']:
                raise RemoteSensorError("Scope is already bound to another site.")
            now = self._now().isoformat()
            c.execute("INSERT OR IGNORE INTO remote_scope_sites (scope_id,site_id,created_at) VALUES (?,?,?)", (scope_id, sensor['site_id'], now))
            existing = c.execute("SELECT * FROM sensor_scope_assignments WHERE sensor_id=? AND scope_id=?", (sensor_id, scope_id)).fetchone()
            if existing and existing['canonical_target'] != scope['canonical_target']:
                raise RemoteSensorError("Assignment target changed; remove and explicitly reassign.")
            inserted = c.execute("""INSERT OR IGNORE INTO sensor_scope_assignments
                (sensor_id,scope_id,site_id,canonical_target,created_at) VALUES (?,?,?,?,?)""",
                (sensor_id, scope_id, sensor['site_id'], scope['canonical_target'], now))
            if inserted.rowcount:
                record_event(c, event_type="SENSOR_SCOPE_ASSIGNED", entity_type="SENSOR_SCOPE_ASSIGNMENT",
                             entity_id=f"{sensor_id}:{scope_id}", site_id=sensor['site_id'],
                             scope_id=scope_id, sensor_id=sensor_id, actor_type="LOCAL_OPERATOR",
                             new_state="ASSIGNED")
            result = dict(c.execute("""SELECT a.*,s.name AS scope_name,s.scope_type,
                s.enabled AS scope_enabled,s.authorized AS scope_authorized
                FROM sensor_scope_assignments a JOIN authorized_scopes s ON s.id=a.scope_id
                WHERE a.sensor_id=? AND a.scope_id=?""", (sensor_id, scope_id)).fetchone())
            result['scope_enabled'] = bool(result['scope_enabled'])
            result['scope_authorized'] = bool(result['scope_authorized'])
            return result

    def list_assignments(self, sensor_id, limit=100, offset=0):
        self._page(limit, offset)
        with self._connection() as c:
            self._sensor(c, sensor_id)
            rows = c.execute("""SELECT a.*,s.name AS scope_name,s.scope_type,
                s.enabled AS scope_enabled,s.authorized AS scope_authorized
                FROM sensor_scope_assignments a LEFT JOIN authorized_scopes s ON s.id=a.scope_id
                WHERE a.sensor_id=? ORDER BY a.scope_id LIMIT ? OFFSET ?""", (sensor_id, limit, offset)).fetchall()
            assignments = []
            for row in rows:
                assignment = dict(row)
                if assignment['scope_enabled'] is not None:
                    assignment['scope_enabled'] = bool(assignment['scope_enabled'])
                if assignment['scope_authorized'] is not None:
                    assignment['scope_authorized'] = bool(assignment['scope_authorized'])
                assignments.append(assignment)
            return assignments

    def list_eligible_assignment_scopes(self, site_id, sensor_id, limit=100, offset=0):
        """Return a bounded selector projection using the same policy as assignment."""
        if (type(limit) is not int or not 1 <= limit <= 100
                or type(offset) is not int or not 0 <= offset <= 100000):
            raise RemoteSensorError("Invalid eligible-scope pagination.")

        def eligible(scope_type, canonical_target, authorized, enabled,
                     confirmed_at, confirmation_version, authorization_source,
                     scope_network_id, network_id, network_cidr,
                     network_authorized, network_enabled):
            scope = {
                'scope_type': scope_type, 'canonical_target': canonical_target,
                'authorized': bool(authorized), 'enabled': bool(enabled),
                'authorization_confirmed_at': confirmed_at,
                'authorization_confirmation_version': confirmation_version,
                'authorization_source': authorization_source,
                'network_id': scope_network_id,
            }
            network = {
                'id': network_id, 'cidr': network_cidr,
                'authorized': bool(network_authorized), 'enabled': bool(network_enabled),
            }
            try:
                require_private_network_scope(network, scope)
                private_lan(canonical_target)
                return 1
            except (RemoteSensorError, ValueError, TypeError):
                return 0

        with self._connection() as c:
            site = c.execute("SELECT enabled FROM sites WHERE id=?", (site_id,)).fetchone()
            if site is None:
                raise LookupError("Site not found.")
            sensor = c.execute("SELECT site_id,enabled,credential_revoked_at FROM remote_sensors WHERE id=?", (sensor_id,)).fetchone()
            if sensor is None:
                raise LookupError("Sensor not found.")
            if sensor['site_id'] != site_id:
                raise RemoteSensorError("Sensor does not belong to this site.")
            if not site['enabled'] or not sensor['enabled'] or sensor['credential_revoked_at'] is not None:
                raise RemoteSensorError("An active sensor and site are required for assignment.")

            c.create_function("remote_scope_eligible", 12, eligible, deterministic=False)
            rows = c.execute("""
                SELECT s.id, s.name, s.canonical_target, s.scope_type,
                       s.enabled, s.authorized
                FROM authorized_scopes s
                JOIN network_scope_links l ON l.scope_id=s.id
                JOIN networks n ON n.id=l.network_id
                LEFT JOIN remote_scope_sites binding ON binding.scope_id=s.id
                WHERE s.scope_type='PRIVATE_NETWORK' AND s.authorized=1 AND s.enabled=1
                  AND s.authorization_confirmed_at IS NOT NULL
                  AND s.authorization_confirmation_version IS NOT NULL
                  AND s.authorization_source IS NOT NULL
                  AND n.authorized=1 AND n.enabled=1
                  AND (binding.site_id IS NULL OR binding.site_id=?)
                  AND NOT EXISTS (
                      SELECT 1 FROM sensor_scope_assignments a
                      WHERE a.sensor_id=? AND a.scope_id=s.id
                  )
                  AND remote_scope_eligible(
                      s.scope_type,s.canonical_target,s.authorized,s.enabled,
                      s.authorization_confirmed_at,s.authorization_confirmation_version,
                      s.authorization_source,l.network_id,n.id,n.cidr,n.authorized,n.enabled
                  )=1
                ORDER BY s.id ASC LIMIT ? OFFSET ?
            """, (site_id, sensor_id, limit + 1, offset)).fetchall()
        items = []
        for row in rows[:limit]:
            item = dict(row)
            item['enabled'] = bool(item['enabled'])
            item['authorized'] = bool(item['authorized'])
            items.append(item)
        return {
            'items': items,
            'limit': limit, 'offset': offset, 'has_more': len(rows) > limit,
        }

    def get_sensor_grants(self, sensor_id):
        """Return only this active sensor's current, valid PRIVATE_NETWORK grants."""
        with self._connection() as c:
            sensor = self._sensor(c, sensor_id, active=True)
            declared = set(sensor['capabilities'])
            grants = []
            rows = c.execute(
                "SELECT * FROM sensor_scope_assignments WHERE sensor_id=? AND site_id=? ORDER BY scope_id LIMIT 101",
                (sensor_id, sensor['site_id']),
            ).fetchall()
            if len(rows) > 100:
                raise RemoteSensorError("Sensor grant count exceeds the supported bound.")
            for assignment in rows:
                try:
                    scope = self._scope(c, assignment['scope_id'])
                except RemoteSensorError:
                    # An assignment whose scope/network is no longer valid is never issued.
                    continue
                if assignment['canonical_target'] != scope['canonical_target']:
                    continue
                grants.append({
                    'scope_id': assignment['scope_id'],
                    'scope_type': 'PRIVATE_NETWORK',
                    'cidr': scope['canonical_target'],
                    'capabilities': sorted(declared & {'HOST_DISCOVERY', 'SERVICE_DISCOVERY'}),
                })
            return grants

    def remove_assignment(self, sensor_id, scope_id):
        with self._connection(write=True) as c:
            sensor = self._sensor(c, sensor_id)
            row = c.execute("SELECT site_id FROM sensor_scope_assignments WHERE sensor_id=? AND scope_id=?", (sensor_id, scope_id)).fetchone()
            if row is not None:
                record_event(c, event_type="SENSOR_SCOPE_UNASSIGNED", entity_type="SENSOR_SCOPE_ASSIGNMENT",
                             entity_id=f"{sensor_id}:{scope_id}", site_id=row['site_id'] or sensor['site_id'],
                             scope_id=scope_id, sensor_id=sensor_id, actor_type="LOCAL_OPERATOR",
                             previous_state="ASSIGNED", new_state="UNASSIGNED")
                c.execute("DELETE FROM sensor_scope_assignments WHERE sensor_id=? AND scope_id=?", (sensor_id, scope_id))

    def validate_assigned_target(self, sensor_id, credential, scope_id, target):
        """Core policy precondition only; does not authorize a job or ingest evidence."""
        with self._connection() as c:
            sensor = self._authenticate(c, sensor_id, credential)
            scope = self._scope(c, scope_id)
            assignment = c.execute("SELECT * FROM sensor_scope_assignments WHERE sensor_id=? AND scope_id=? AND site_id=?", (sensor_id, scope_id, sensor['site_id'])).fetchone()
            if assignment is None or assignment['canonical_target'] != scope['canonical_target']:
                raise RemoteSensorError("No current assignment authorizes this target.")
            return LocalScopeGrant(sensor['sensor_uuid'], scope_id, assignment['canonical_target']).validate_target(sensor['sensor_uuid'], scope_id, target)
