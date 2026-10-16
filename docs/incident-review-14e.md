# Incident Review 14E — Analyst Review Activity & Operations Feed

## Purpose

14E adds a bounded, read-only cross-review activity feed for Analyst Operations. It is a compact navigation and workflow-history view. `IncidentReviewSection` remains the authoritative full timeline for an individual review. The feed does not imply attack, compromise, threat severity, analyst performance, or audit certification.

## Source and event types

The feed reads `incident_review_events`, the existing append-only event source. It supports the existing 13 event types:

- `REVIEW_CREATED`, `STATE_CHANGED`, `REVIEW_CLOSED`, `REVIEW_REOPENED`
- `PRIORITY_CHANGED`, `CONFIDENCE_CHANGED`, `DISPOSITION_CHANGED`, `REVIEW_FIELD_CHANGED`
- `FINAL_SUMMARY_CHANGED`, `ANALYST_NOTE_ADDED`, `ANALYST_NOTE_CLEARED`
- `EVIDENCE_ATTACHED`, `EVIDENCE_DETACHED`

Summaries are generated deterministically from event type. State, priority, confidence, and disposition summaries include old/new values only when both values match the current corresponding enum. Invalid or missing values use a generic event-specific summary. Stored event summaries are not returned. `REVIEW_FIELD_CHANGED` uses “Review field updated”; its old/new values are never exposed.

The feed does not return analyst note bodies, final-summary text, source evidence payloads, or review summary bodies. Note events may include `note_id`. Evidence attach/detach events may include only the evidence type and ID already stored on the event; source records are not fetched.

## Attribution

Site, scope, and device IDs come from the review’s **current stored attribution**. They are not event-time snapshots, and the feed does not infer historical attribution. `site_name` is resolved with a fixed join to `sites`; a null site ID is labeled “Unattributed.” Scope, device, and evidence relationships are not used to infer a site.

## Filters, ordering, and pagination

`GET /incident-review-operations/activity` supports fixed filters for event type, review ID, site ID, scope ID, device ID, `since`, and `until`. IDs must be positive integers and event type must be one of the 13 supported values. Time filters must be timezone-aware ISO-8601 timestamps; they are normalized to UTC and inclusive (`created_at >= since`, `created_at <= until`). A range with `since > until` is rejected.

Results are always ordered by `created_at DESC, event_id DESC`. Pagination uses `limit` 1–100 and `offset` 0–100000. The response is `{ "activity": [...], "pagination": { "limit", "offset", "total" } }`, including a valid empty result.

## Frontend and read-only behavior

The Analyst Operations feed shows time, review key/title, deterministic summary, current site label, and actor source. Selecting an event opens the existing review detail workflow without changing queue or workload filters. Loading, error, and empty states are provided.

The endpoint performs reads only and does not mutate reviews, events, notes, evidence links or source evidence, sites, scopes, or devices. It does not expose usernames or analyst identities; the current event model records `OPERATOR` as `actor_source`.

## Performance and deferred issues

The query joins events to reviews and left-joins sites, selects only feed fields plus old/new scalar values needed to build safe summaries, and never loads note bodies or evidence source records. Pagination bounds returned rows, while the total count evaluates all matching events. The existing timeline index is review-first, so a global newest-first feed may scan the event index and use a temporary B-tree for ordering. No index migration is added in 14E; consider one only after measuring a concrete operational need.

The related-evidence suggestion-query scaling issue and the `REVIEW_FIELD_CHANGED` database event/field pairing gap remain separate deferred work.
