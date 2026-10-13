# Remote Sensor 10B: registration and enrollment

10B adds three bounded HTTP endpoints to the 10A foundation. It does not install
or deploy a sensor agent, run background transport loops, discover networks,
execute scans/jobs/programs/shell commands, or ingest results. Capabilities remain
metadata. Public Internet scanning from sensors is not available.

## Register a sensor

1. The local administrator calls `POST /sites/{site_id}/sensor-enrollments`
   with `{ "ttl_seconds": 900 }` (optional; range 60–3600). Save the returned
   `token` securely: it is shown only once. `GET` on the same route lists safe
   metadata, including `created_at`, `expires_at`, `consumed_at`, and `revoked_at`.
2. During sensor installation/provisioning, generate and retain a UUID. Submit
   `POST /sensor-enrollment/register` with the following JSON over HTTPS:

   ```json
   {
     "enrollment_token": "<one-time token>",
     "sensor_uuid": "dd03f49d-37d7-41b1-8c06-95b74c5d935a",
     "sensor_name": "Office sensor",
     "platform": "linux",
     "version": "1",
     "capabilities": ["HOST_DISCOVERY"]
   }
   ```

3. A successful response is HTTP 201 with bounded sensor identity and a
   `credential`, returned only once. Protect that credential in sensor-local
   secret storage. No installer or secret-storage client is supplied in 10B.
4. Discard the enrollment token. Future requests use both
   `Authorization: Bearer <credential>` and `X-Sensor-UUID: <registered UUID>`.
   The UUID selects an identity; only verification of its credential authenticates
   it. UUID and site ID alone never authenticate. Existing 10A credentials also
   work with this header contract.

The token determines the site; requests cannot specify site, scope, target,
command, or scanner flags. Names are bounded to 128 characters; platform and
version to 64. Unknown fields are rejected. UUIDs are canonicalized. Every
already-registered UUID, including disabled/revoked identities, returns HTTP 409
when presented with an otherwise valid invitation. It never replaces an existing
credential or reactivates an identity, and the new invitation remains unused.
Unknown, expired, revoked, consumed, or disabled-site invitations return HTTP 400.
Malformed metadata returns HTTP 422 (blank metadata may return HTTP 400).

A single SQLite `BEGIN IMMEDIATE` transaction validates the invitation/site,
checks UUID uniqueness, inserts the sensor, and marks the invitation consumed.
Concurrent uses have exactly one winner; failure rolls back all writes. A lost
successful response cannot be replayed to recover the credential: the local
administrator must revoke that identity and provision a new UUID/invitation.

## Credential-authenticated endpoints

| Method | Route | Behavior |
|---|---|---|
| GET | `/sensor/self` | Read the authenticated sensor's identity only |
| POST | `/sensor/heartbeat` | Update bounded platform/version/capability metadata and server receipt time |

Heartbeat JSON is `{ "platform": "linux", "version": "1", "capabilities": [] }`.
No client timestamp or ONLINE state is accepted. Status remains derived from the
server receipt time and the existing five-minute threshold. Heartbeat does not
modify scopes, assignments, or network authorization. GET self has no write effects.

Both return only `id`, `sensor_uuid`, `site_id`, `name`, `platform`, `version`,
`enabled`, `capabilities`, `registered_at`, `last_seen_at`, and derived `status`.
Missing/invalid credentials, disabled sensors/sites, and revoked credentials return
HTTP 401. No secrets or hash/verifier fields appear in read responses. Machine
responses use `Cache-Control: no-store`; validation failures do not echo inputs.

The whitelist is LOCAL_NETWORK_DISCOVERY, HOST_DISCOVERY, SERVICE_DISCOVERY,
and LOG_COLLECTION. At most four entries are accepted, sorted and deduplicated.
Unknown values, including SHELL, EXEC, SCRIPT, RUN_COMMAND and ARBITRARY_NMAP,
are rejected. Declaring a capability grants no scope or executable operation.

## Trust and transport

Tokens and machine credentials each contain 256 random bits. Enrollment tokens
are stored as domain-separated SHA-256 digests; credentials as salted
PBKDF2-SHA256 verifiers with constant-time digest comparison. Tokens authorize
exactly one registration into one site and cannot authenticate machine requests.
Credentials authenticate one sensor and never grant management or execution rights.

Remote machine requests require HTTPS. Only direct loopback requests with a
loopback Host may use HTTP for local development. Browser Origin and forwarding
headers are rejected; query parameters are not accepted. Use a TLS-serving ASGI
configuration that preserves the actual peer/scheme (disable proxy-header trust).
Proxy deployment/trusted forwarding is not implemented. Sensors must verify the
server certificate. Do not log request bodies, Authorization headers, invitation
responses, or registration responses. Bound request sizes and request rates in the
serving infrastructure before exposing this service; 10B does not add a rate limiter.

Local management retains the 10A direct-loopback boundary. Requests carrying
machine authentication headers are explicitly rejected even on loopback.
`DELETE /sensor-enrollments/{id}` revokes an invitation.
`PATCH /sensors/{id}` with `{ "enabled": false }` blocks machine authentication.
`DELETE /sensors/{id}/credential` permanently revokes the credential and disables
the identity; re-enabling cannot restore it. Disabling a site blocks its sensors.
Rotation and replacement of credentials on an existing identity are deferred.
Scope assignments remain administrator-controlled and cannot be mutated by sensors.

## Storage and verification

No migration is needed: schema version remains 30. Existing 10A credentials,
enrollment records and assignments remain intact, as does 09D evidence.

Run `.venv/bin/python -m pytest -q tests/test_sensor_enrollment.py` for 10B.
Existing 10A tests remain in `tests/test_remote_sensors.py`,
`tests/test_remote_sensor_api.py`, and `tests/test_remote_sensor_migration.py`.
Tests use temporary databases and synthetic credentials, never network scanning.
Use the established outside-sandbox runner for TestClient tests.
