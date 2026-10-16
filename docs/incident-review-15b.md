# Incident Review 15B — Atomic Evidence Promotion

## Purpose

15B adds an explicit analyst-initiated operation that creates an Incident Review and attaches exactly one initiating evidence reference atomically. The review remains an investigation record; promotion does not establish an attack or compromise.

## API

`POST /incident-reviews/from-evidence` accepts a nested `review` object and an `evidence` object. Review fields are limited to title, summary, priority, confidence, and optional site/scope/device IDs. Evidence fields are limited to the canonical evidence type and positive evidence ID. Unknown fields are rejected.

The response is HTTP 201 with the created review and the compact evidence type/ID reference. It does not return source evidence payloads.

The existing manual `POST /incident-reviews` and existing `POST /incident-reviews/{incident_id}/evidence` contracts remain unchanged.

## Transaction and events

A shared connection-taking create helper and evidence-attach helper are used by the existing public operations and by the promotion operation. Promotion opens one connection, begins one immediate transaction, creates the review, attaches evidence, and commits once. Any exception before commit rolls back all staged rows and timestamp updates.

Successful promotion creates the events in deterministic order:

1. `REVIEW_CREATED`
2. `EVIDENCE_ATTACHED`

No new event type or client-side event is generated. A database-trigger failure test aborts evidence insertion after review creation and verifies that the review, both events, and evidence link do not persist.

## Supported evidence and timestamps

The fixed supported types are `PERIMETER_DETECTION`, `PERIMETER_POLICY_CORRELATION`, `PERIMETER_HOST_CORRELATION`, `EXTERNAL_EXPOSURE_CHANGE`, `THREAT_DETECTION`, `THREAT_CORRELATION`, and `WEB_DETECTION`. Each resolves through a static server-side query; request data cannot select a source table.

Evidence timestamps reuse existing link behavior. `first_evidence_at` and `last_evidence_at` are recomputed from the linked source record's `observed_at` value. Attachment time is stored separately as `added_at`.

## Attribution

The analyst supplies review attribution explicitly. Existing review-creation validation checks supplied site/scope/device relationships, and existing evidence-link validation checks compatibility. Evidence-side attribution may be resolved through existing unambiguous relationships for validation only. It does not populate or snapshot review attribution. If review attribution is omitted, the review remains unattributed even when the source has attribution.

## Reuse, retries, and source immutability

A source evidence record may be linked to multiple reviews. The existing uniqueness rule is per review and source reference; no global ownership is introduced. Existing per-review duplicate-link behavior remains idempotent.

There is no backend idempotency key. The reused form submission lock prevents normal concurrent duplicate clicks. A retry after an ambiguous network failure can create another review, matching the current manual creation semantics.

Promotion only reads source evidence. It does not update or delete detections, correlations, exposure changes, or other source records.

## Frontend reuse and race behavior

The existing `CreateIncidentReviewForm` is reused. Without initiating evidence, it continues to call the manual creation endpoint. With an immutable initiating-evidence context, it shows the type and reference and submits one atomic promotion request. It does not issue a follow-up evidence-attach request or copy source text into the form.

Successful creation follows the existing upsert, list-request invalidation, guarded review selection, detail loading, and targeted Analyst Operations refresh flow. The existing create-attempt guard continues to block duplicate in-flight submissions and prevent stale responses from overriding later analyst selection.

## Scope boundary and schema

15B establishes the atomic API and reusable form/service path. It adds no source-surface “Start Review” actions; those belong to 15C. There is no migration. Schema remains version 43.
