# Bounded Incident Review JSON Report (20A)

`GET /incident-reviews/{review_id}/report.json` generates a current-state Incident Review handoff report on demand. The report is not persisted and is not an immutable evidence object. It has `report_schema_version: 1` and one server-generated UTC `generated_at` timestamp.

## Access and response

The endpoint uses the same access boundary as the existing Incident Review read endpoints; it does not add `local_management` or a human identity model. Successful responses use `Cache-Control: no-store`, JSON media type, and an attachment filename of `sentinelip-incident-review-{numeric-id}-{UTC timestamp}.json`. The review title is never used in a filename. Missing reviews return 404, invalid/nonpositive IDs return 422, and unexpected database failures return a safe 500. Generated output above 4 MiB returns 413 with a fixed safe error.

## Snapshot and root projection

The assembler opens one connection, enables SQLite `query_only`, and starts a read transaction before the first report query. Review fields, child collections, and source availability therefore use one SQLite read snapshot. It does not initialize or migrate the database and issues no writes.

The fixed root contains `report_schema_version`, `generated_at`, `review`, `evidence`, `notes`, and `timeline`. The review projection is limited to `id`, `incident_key`, `title`, `summary`, `state`, `priority`, `confidence`, `disposition`, `site_id`, `scope_id`, `device_id`, `final_summary`, `created_at`, `updated_at`, `closed_at`, `first_evidence_at`, and `last_evidence_at`. `incident_key` is the repository’s stored review key. No analyst identity is inferred.

## Evidence projection

Supported types remain `PERIMETER_DETECTION`, `PERIMETER_POLICY_CORRELATION`, `PERIMETER_HOST_CORRELATION`, `EXTERNAL_EXPOSURE_CHANGE`, `THREAT_DETECTION`, `THREAT_CORRELATION`, and `WEB_DETECTION`.

Each link returns `evidence_link_id`, `evidence_type`, `evidence_id`, `observed_at`, `added_at`, and `source_status`. A source with an existing row is `AVAILABLE` and adds only fixed `site_id`, `scope_id`, and `device_id` context fields from the existing safe Incident Review evidence projection. A missing source remains as a link with `source_status: MISSING`; this means the source row is unavailable, not that corruption is proven. Source lookups are grouped by type, at most one query per type. Evidence-link `reason` is excluded.

No source payload, raw telemetry, DNS/web content, task output, credentials, arbitrary metadata, or source free text is projected. The report does not use source table rows as response objects.

## Notes and timeline

Notes return only `id`, `created_at`, `actor_source`, and note `text`. The stored `OPERATOR` source class remains unchanged; no person is identified.

Timeline entries return only `id`, `created_at`, `event_type`, `actor_source`, `field_name`, `evidence_type`, `evidence_id`, and the existing bounded `summary`. `old_value` and `new_value` are omitted.

## Caps, truncation, and ordering

Evidence is capped at 200, notes at 50, and timeline entries at 50. Each collection reports `total`, `returned`, `omitted`, `truncated`, and `items`; `omitted = total - returned` and `truncated` is true exactly when omitted is positive. No text field is silently truncated.

For a capped collection, the newest entries are selected by its canonical timestamp and descending ID tie-break, then returned in ascending chronological order with ascending ID ties. Evidence uses SQLite `julianday(observed_at)` semantics; notes and timeline use their stored `created_at` ordering. Malformed optional timestamps are preserved and do not cause application timestamp parsing failures; SQLite's null sort behavior plus ID tie-break remains deterministic.

The report query shape is one review projection, evidence count and bounded link read, up to seven batched source lookups, notes count and bounded read, and timeline count and bounded read: at most 14 report `SELECT` statements. There is no per-evidence-row query. Existing review child indexes support collection selection; evidence chronological ordering may use a temporary sort because it uses `julianday(observed_at)`. No index or migration is added.

## Schema and next step

Schema remains version 44. There is no report table, artifact storage, HTML, PDF, CSV, frontend change, or migration 45 in 20A. 20B can render this same bounded projection as fixed, escaped, printable HTML with a restrictive CSP and no scripts.
