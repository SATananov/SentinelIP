# Management Audit History API (19C)

`GET /management-audit-events` exposes a bounded read-only view of the append-only management audit trail introduced in 19B. It uses the existing `local_management` dependency. Successful responses use `Cache-Control: no-store`; this endpoint does not initialize, write, or otherwise mutate the database.

## Filters and paging

Supported filters are `event_type`, `entity_type`, `entity_id`, and `site_id`. They combine with AND semantics and exact equality. `entity_id` requires `entity_type`. Unknown or repeated query parameters are rejected. No date range, actor filter, fuzzy search, or caller-selected order is supported.

`limit` defaults to 50 and is capped at 100. `offset` defaults to zero and must be nonnegative. The query fetches at most `limit + 1` rows, returns no more than `limit`, and derives `has_more` from the extra row. Ordering is always `occurred_at DESC, id DESC`; the timestamp and ID provide stable newest-first ordering for ties. There is no total-count query.

## Projection and privacy

Each result uses a fixed allowlist of audit columns. Actor values are the source classes `LOCAL_OPERATOR`, `API_CLIENT`, and `SENSOR`; they do not identify a person. Event rows are read directly without joining current entities, so network, assignment, and exposure-policy removal history remains available after the entity or relationship is deleted.

Expected TCP port arrays are decoded to integer arrays only after validating the stored JSON shape, length, range, uniqueness, and order. Invalid stored serialization is represented as `null`, never returned as raw text. Cleanup records expose aggregate class, time, counts, and batch limit only. Task records expose task type and fixed relationship identifiers, not task payloads or results. Enrollment records expose the enrollment ID and expiry only, never token material. The endpoint does not select or return credentials, secrets, telemetry, DNS/web content, or arbitrary database columns.

## Query plan

SQLite uses the four schema-44 indexes for the intended access paths:

- Unfiltered newest-first reads scan `idx_management_audit_events_time` in order.
- Site filtering searches `idx_management_audit_events_site_time`.
- Entity type plus ID searches `idx_management_audit_events_entity_time`.
- Event type filtering searches `idx_management_audit_events_type_time`.

The tested plans did not require a temporary sort. SQLite uses table lookups for the fixed multi-column projection because these indexes are intentionally not wide covering indexes. The indexes are ascending, and SQLite scans them in reverse for the fixed descending order. No schema change or additional index is needed for 19C. Offset pagination is acceptable for the currently low-volume change history; 19D can add a compact manually refreshed view using these same fixed filters and pages.

Schema remains version 44. This API introduces no mutation, migration, or audit retention policy change.
