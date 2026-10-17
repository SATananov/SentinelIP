# Remote Sensor Fleet Operations 16A — Fleet Inventory and Health

## Purpose

16A adds a bounded, read-only, all-sites operator inventory at `GET /sensors` and one **Remote Sensor Fleet** panel. Operators can inspect sensor identity, site context, declared platform/version and capabilities, registration and heartbeat timestamps, fleet status, and assignment count.

The route reuses `local_management`, the same direct-local dependency used by the existing sensor management routes. It requires a loopback client and an allowed localhost URL hostname, rejects `Authorization`, `X-Sensor-UUID`, `X-SentinelIP-Sensor-ID`, and `X-SentinelIP-Sensor-Token`, rejects `Forwarded`, `X-Forwarded-For`, and `X-Forwarded-Host`, allows only no origin or the two local frontend origins, and sets `Cache-Control: no-store`. This boundary is direct-local access, not user authentication. Proxy headers are not trusted.

## Fleet response

The JSON response contains `evaluated_at`, `items`, `limit`, `offset`, and `has_more`. Each row contains only:

`id`, `sensor_uuid`, `name`, `site_id`, `site_name`, `site_enabled`, `platform`, `version`, `enabled`, `registered_at`, `last_seen_at`, `status`, `heartbeat_age_seconds`, `capabilities`, and `assignment_count`.

Credentials, enrollment tokens/hashes, token hashes, credential hashes/salts/iterations, raw heartbeat bodies, raw task payloads/results, and arbitrary machine metadata are not returned. Capabilities are allowlisted canonical values, sorted and unique. An empty list is valid; malformed legacy capability data is represented as `null` so the UI can show it as unavailable.

## Status semantics

Fleet status is a read-only display projection and does not change `SensorStatus`, heartbeat processing, or task eligibility:

1. Non-null `credential_revoked_at` → `REVOKED`.
2. Disabled sensor → `DISABLED`.
3. Missing site record → `UNKNOWN`.
4. Disabled site → `DISABLED`.
5. Null heartbeat → `PENDING`.
6. Valid non-future heartbeat age from 0 through 300 seconds inclusive → `ONLINE`.
7. Valid heartbeat age greater than 300 seconds → `OFFLINE`.
8. Malformed or future-dated heartbeat → `UNKNOWN`.

One aware UTC `evaluated_at` is captured per fleet request and used for every row. `heartbeat_age_seconds` is null for absent, malformed, or future heartbeat timestamps; otherwise it is a non-negative integer rounded up to the next whole second. The browser displays the backend status without recomputing it.

## Site, platform, capabilities, and assignments

Every valid sensor row has a required `site_id`; the query joins its site name and enabled state. If historical corruption leaves a missing site, the row is retained safely with unavailable site context and `UNKNOWN` status unless a higher-precedence revoked/disabled state applies.

Platform and version are sensor-declared metadata, not cryptographically verified operating-system identity. Capabilities are also sensor-declared; they are not inferred from platform. The UI uses the canonical capability identifiers and does not claim capabilities are verified or active.

Assignment count is calculated for the paginated sensor rows using a grouped aggregate. Full assignments are not loaded by the inventory.

## Filters, ordering, and pagination

Supported exact filters are `site_id`, `status`, `platform`, and `enabled`. Status accepts only `REVOKED`, `DISABLED`, `PENDING`, `ONLINE`, `OFFLINE`, or `UNKNOWN`; `enabled` accepts only the query strings `true` and `false`. Unknown `site_id` returns 404. Ordering is fixed by site ID, normalized name, then sensor ID.

`limit` defaults to 100 and is bounded from 1 to 100. `offset` defaults to 0 and is bounded from 0 to 100000. The response uses `has_more` rather than an unbounded count query.

## Read-only boundary and phase boundary

16A contains no enrollment creation/token display, assignment changes, enable/disable, credential revocation, task history, task creation, arbitrary commands, or raw sensor payload display. The fleet panel and its API service issue read requests only. Future lifecycle and task operations belong to later Phase 16 subphases.

No migration is added. Schema remains version 43.
