# Legacy Telemetry Ingestion Contract (Phase 24)

Phase 24 bounds the existing sensor-authenticated legacy ingestion endpoints
and makes duplicate delivery atomic. The work addresses resource use from
untrusted request bodies and nested metadata, plus duplicate races. It does not
add a telemetry endpoint or change the newer `/sensor/*` transport.

## Endpoints and request bodies

The contract covers only `POST /telemetry/web` and `POST /telemetry/dns`.
Their raw request body limits are 65,536 bytes and 16,384 bytes respectively.
The ASGI middleware checks an oversized declared `Content-Length` before
reading. When the length is absent or the body is chunked, it counts bytes
cumulatively and returns on the first overflow without reading later chunks or
entering the downstream application. Within the limit it replays the received
ASGI request messages in order, preserving bytes, message fields,
`more_body`, and a supplied terminal empty message. The existing `/sensor/*`
16,384-byte behavior and error text remain unchanged.

The body cap runs before JSON parsing and sensor authentication. For an
in-limit body, the existing FastAPI parse/validation order remains: request
parsing and Pydantic validation happen before route credential checks. The
routes retain their existing sensor credential, enabled-state, and sensor-type
checks.

## Field limits

Text bounds are measured using strict UTF-8 encoding. Invalid Unicode and
oversized values are rejected; values are never truncated.

| Field | Maximum |
| --- | ---: |
| `external_event_id` | 128 bytes |
| textual `observed_at` input | 64 bytes |
| Web `event_type` | 32 bytes |
| Web `url` | 32,768 bytes |
| Web referrer and redirect domains | 1,024 raw bytes each; normalized hostname at most 253 ASCII bytes |
| Web `browser_session_id` | 128 bytes |
| Web `tab_id` | 64 bytes |
| DNS `queried_domain` | 1,024 raw bytes; normalized hostname at most 253 ASCII bytes |
| DNS `query_type` | 32 bytes |
| DNS `response_status` | 16 bytes |
| DNS `resolved_addresses` | At most 256 entries, each at most 45 bytes |
| DNS `resolver` | 45 bytes; literal IP validation and normalization remain |
| DNS `ttl` | 0 through 2,147,483,647 |

Existing timestamp parsing, event enums, URL scheme rules, hostname/IP
normalization, and privacy modes remain in effect. `DOMAIN_ONLY` continues to
omit the stored URL path. `STANDARD` continues to store the normalized path
without the query or fragment. The DNS producer continues to canonicalize IP
addresses and provide `{"source": ...}` metadata.

## Metadata

Metadata remains an object or `null`; an empty object remains valid. Its
compact, sorted persistence-form JSON is limited to 8,192 UTF-8 bytes. The
existing forbidden-key privacy policy remains active.

Validation first traverses the parsed tree iteratively and applies its
structural and scalar limits. The root object is depth 1; a nested object or
list increments depth, while scalar children do not. The limits are:

- depth 4;
- 64 keys per object;
- 256 items per list;
- 1,024 total nodes/values, including the root;
- 64 UTF-8 bytes per key;
- 4,096 UTF-8 bytes per string value.

Allowed values are `null`, strings, booleans, integers, finite floats, objects,
and lists. Non-finite numbers, invalid Unicode, non-string keys, unsupported
Python values, and exceeded limits are rejected. After the structural checks,
the forbidden-key check runs; only then is the bounded tree serialized for the
8,192-byte check. Deep model metadata is therefore rejected before recursive
serialization.

Raw JSON parsing precedes metadata model validation. A syntactically valid deep
JSON body that fits the request cap can be parsed and then rejected by the
bounded metadata validator. If framework JSON parsing itself raises, FastAPI
wraps the parser failure as HTTP 400; telemetry-specific handling converts it
to the fixed 422 response. Neither path returns parser details or writes an
observation.

## Errors and side effects

- `413`: `Telemetry request exceeds the allowed size.` for an oversized raw body.
- `422`: `Invalid telemetry request.` for malformed JSON, schema/field
  validation, metadata limits, and invalid telemetry values.
- `401`: existing missing or invalid sensor credential behavior.
- `403`: existing disabled sensor or wrong sensor type behavior.
- `500`: `Telemetry ingestion failed.` for unexpected ingestion/database
  failures.

Telemetry validation and error handlers apply only to these two routes. Other
API routes retain the framework’s default validation and HTTP exception
handling. Telemetry error bodies do not include request data, rejected values,
tokens, SQL, database exception text, or stack traces.

Body, JSON, schema, field, metadata, authentication, and authorization
rejections write no telemetry observation and do not update `last_seen_at`.
Successful inserts and successful duplicate deliveries update
`last_seen_at`.

## Idempotency and concurrency

The existing `UNIQUE(sensor_id, external_event_id)` constraint remains the
identity boundary for web and DNS observations. Each successful ingestion uses
one SQLite connection and transaction: `BEGIN IMMEDIATE`, targeted
`INSERT ... ON CONFLICT(sensor_id, external_event_id) DO NOTHING`, selection of
the persisted row, then the sensor liveness update. Insert-vs-duplicate status
comes from the insert statement’s SQLite cursor `rowcount`. The transaction
commits only after all steps succeed; an exception rolls it back and the
connection closes.

Both first delivery and duplicates return HTTP 202 with the existing response
shape. The first stored row returns `idempotent: false`; a duplicate returns
`idempotent: true` and the existing row identity. Identity is based only on
sensor ID and external event ID. The first payload wins: a later payload with
the same identity does not overwrite or add a row, and it still updates
`last_seen_at`. Concurrent duplicate tests cover web and DNS delivery.

## Client compatibility and security boundary

The browser extension’s navigation, redirect, form-signal, and download
builders remain compatible. Generated event/session IDs and browser tab IDs
fit the new bounds. A `STANDARD` URL of exactly 32,768 UTF-8 bytes is accepted;
larger URLs are rejected. The endpoint body cap also rejects oversized bodies
before credentials are checked or JSON is parsed.

The DNS sensor continues to use UUID event IDs, UTC timestamps, normalized
hostnames, canonical IPv4/IPv6 addresses, literal resolver IPs, bounded TTLs,
and flat source metadata. A maximum producer-compatible request fixture with a
253-byte domain and 256 long IPv6 answers serializes to 11,026 bytes, below the
16 KiB body limit.

Phase 24 preserves the legacy sensor credential and authorization behavior,
privacy storage behavior, and `/sensor/*` transport. It introduces no remote
endpoint, enrollment change, proxy/auth redesign, or operator UI change.

## Schema, verification, and scope

The database schema remains version 45. No migration or index was added; the
existing web and DNS unique constraints support atomic idempotency.

Focused Phase 24 backend, browser extension, and DNS sensor tests passed. The
authoritative backend TestClient/AnyIO suite remains incomplete in this
environment: requests stall before router entry, a limitation previously
reproduced on a clean baseline. This is not reported as a full-suite pass.

Out of scope: `/sensor/*` protocol redesign, enrollment redesign, retention,
Incident Review, exports, SSH collection, detector changes, operator frontend,
authentication/proxy redesign, pagination, background exports, schema/index
changes, and Phase 25 work.
