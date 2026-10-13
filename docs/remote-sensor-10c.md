# Remote Sensor 10C: secure machine transport

10C hardens the existing registration, `/sensor/self`, and heartbeat endpoints.
It adds no scans, jobs, command execution, shell access, scanner, result ingestion,
public Internet scanning, or deployed sensor agent.

## Authenticated request contract

Every authenticated machine request supplies each of these headers exactly once:

```http
Authorization: Bearer <sensor credential>
X-Sensor-UUID: <registered sensor UUID>
X-Sentinel-Timestamp: <10-digit Unix time in seconds>
X-Sentinel-Nonce: <43-character URL-safe random nonce>
```

Use `services.sensor_transport.authenticated_sensor_headers` as the platform-neutral
header helper, or construct the same fields in a future Linux/Windows client. It is
transport-only. Generate a new nonce for every attempt, including retries. Do not
reuse request headers after a timeout. The server authenticates the credential,
loads the sensor by UUID, and checks that the sensor and its site remain enabled
and its credential has not been revoked. UUID and site ID are lookup/metadata only.

Core allows timestamps within 300 seconds of its current UTC time, including the
exact ±300 second boundary. Missing or malformed timestamp/nonce returns 400;
stale or future timestamp returns 408. Invalid/missing credentials and inactive
identities return the same 401 response. A reused nonce returns 409. Rate limit
returns 429 with `Retry-After: 60`; global replay-storage exhaustion returns 503.
The client timestamp is only a transport freshness value. Core time remains the
authoritative heartbeat/receipt time.

## TLS and local development

Machine requests require HTTPS for a non-loopback peer. Direct loopback requests
with a loopback Host may use HTTP for development. Forwarded headers do not change
the decision: 10C trusts the ASGI request scheme and direct peer only, with no
trusted-proxy mode. A reverse proxy must provide HTTPS to clients and a deployment
configuration that passes the verified HTTPS scheme and actual peer safely; do
not enable generic proxy-header trust. Sensors must verify Core's TLS certificate.

## Replay and storage bounds

A nonce has 256 bits of entropy. Core records `(sensor_id, nonce, request timestamp,
server receipt time)` in the new SQLite table. A write transaction authenticates,
checks replay/rate limits, and inserts the nonce atomically. The database enforces
one use per sensor; the same nonce from another sensor is independent. Restarting
Core preserves replay records. Rows are removed once their request timestamp is
more than 300 seconds old. Since Core accepts at most 300 seconds of future skew,
records may remain for up to 600 seconds after receipt. Cleanup runs during later
authenticated requests.

Core accepts at most 50 authenticated requests per sensor in any rolling 60-second
window, retains at most 512 live replay records per sensor, and caps the global
nonce table at 100,000 records. Over-limit requests do not consume their nonce.
The global cap fails closed with 503 if reached. Operators should monitor database
capacity and keep the service available so authenticated traffic can clean expired
rows. Apply connection/concurrency controls and unauthenticated request limits in
the serving proxy as well; the in-process per-sensor limiter cannot prevent floods
from unknown credentials or work across multiple Core replicas.

## Payload and endpoint behavior

Sensor routes and the registration route accept at most 16 KiB of request body,
including streamed requests without `Content-Length`; larger requests return 413
before JSON validation or credential hashing. Query parameters are rejected on
machine routes. No binary uploads are supported.

| Method | Route | Transport behavior |
|---|---|---|
| POST | `/sensor-enrollment/register` | Bounded body; one-time enrollment still authorizes only one registration |
| GET | `/sensor/self` | Requires all authentication, timestamp, and nonce headers |
| POST | `/sensor/heartbeat` | Same checks; heartbeat fields remain bounded metadata |

Each authenticated call, including GET, consumes a nonce. Heartbeat updates
`last_seen_at` using Core time and cannot set client status, alter assignments, or
execute jobs. `/sensor/self` returns no credential material.

## Credential protection and signatures

Credentials are bearer secrets; keep them in OS-protected sensor secret storage,
redact Authorization headers from logs, and use TLS with certificate verification.
Credential rotation is deferred. Existing revocation remains immediate; a future
rotation must replace the verifier atomically without changing sensor identity or
allowing multiple active credentials.

10C does not add request signatures. TLS protects the bearer credential in transit
and authenticates Core to the client; the credential authenticates the sensor to
Core. Timestamp and persisted nonce checks limit captured-request replay. A standard
HMAC signature with a separately derived key may be considered if a later threat
model requires message integrity beyond correctly configured TLS. No custom
signature protocol is introduced here.

Enrollment tokens cannot authenticate machine requests. Sensor credentials cannot
manage sites, enrollment tokens, or scope assignments. Sensors cannot self-assign
scopes. This transport does not authorize targets, issue jobs, run scans, execute
commands, or ingest results.

## Storage and verification

Migration 31 adds only the bounded nonce/replay table and indexes. It preserves all
10A/10B data and existing 09D network/scope/device evidence. Initialization is
repeat-safe; the nonce table has a sensor foreign key with cascade semantics if an
identity is ever removed.
