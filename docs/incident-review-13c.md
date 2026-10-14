# Incident Review 13C: Timeline and Analyst Notes

13C adds an append-only history of analyst review actions. It records changes to a review, explicit evidence-link actions, and analyst notes. The history describes the review workflow; it does not establish an attack, compromise, intrusion, exploitation, vulnerability, or root cause.

## Persistence and history

Migration 42 adds `incident_review_events` and `incident_review_notes`. Both are scoped to an incident review, use server-generated timestamps, and identify the action source as `OPERATOR`. The current review routes do not have authenticated user identity, so this label identifies an operator-triggered action without claiming which person performed it.

Events and notes are append-only. There are no event or note edit/delete endpoints. A review mutation and its event records are written in the same database transaction. A newly created review receives `REVIEW_CREATED`; pre-13C reviews receive no fabricated history and remain without history until a real post-13C action occurs.

Timeline reads are bounded to 100 events per page with an offset no greater than 100,000, and are returned newest-first, ordered by `created_at DESC, id DESC`. Notes use the same bounded newest-first ordering. Event values and summaries are bounded; source evidence payloads are never copied into history.

## Event types

The timeline uses `REVIEW_CREATED`, `STATE_CHANGED`, `REVIEW_CLOSED`, `REVIEW_REOPENED`, `PRIORITY_CHANGED`, `CONFIDENCE_CHANGED`, `DISPOSITION_CHANGED`, `REVIEW_FIELD_CHANGED`, `ANALYST_NOTE_ADDED`, `ANALYST_NOTE_CLEARED`, `EVIDENCE_ATTACHED`, and `EVIDENCE_DETACHED`.

Closing and reopening emit only their dedicated event, not an additional `STATE_CHANGED`. Other state transitions use `STATE_CHANGED`. `REVIEW_FIELD_CHANGED` is limited to title, summary, and site/scope/device attribution. PATCH events are emitted only for actual changes; multiple changed fields produce one event each in stable field order. Invalid patches do not persist either the review update or events.

Evidence events describe only adding or removing a review link. An idempotent duplicate attachment produces no event. Detaching a stale link remains supported and records the detach action. Source evidence remains authoritative and unchanged.

## Analyst notes

The existing `incident_reviews.analyst_note` field and PATCH behavior remain for compatibility. Actual text changes emit `ANALYST_NOTE_ADDED`; clearing it emits `ANALYST_NOTE_CLEARED`. This does not create a separate immutable note record from its prior value.

The notes API provides a separate append-only record for each explicit analyst note. Note text is plain text, trimmed, non-empty, and limited to 4,000 characters. Creating a note and its `ANALYST_NOTE_ADDED` event are atomic. Explicit notes do not overwrite the legacy `analyst_note` field.

## API

- `GET /incident-reviews/{incident_id}/timeline?limit=100&offset=0`
- `GET /incident-reviews/{incident_id}/notes?limit=100&offset=0`
- `POST /incident-reviews/{incident_id}/notes` with `{ "note_text": "..." }`

There is no arbitrary event-creation API. Existing attach/detach endpoints remain the only way to change review evidence links, preserving 13A attribution and source validation. The 13B related-evidence endpoint remains read-only and suggestions still require explicit operator attachment.

## Analyst UI

The timeline, review-field save controls, and note controls appear only in the analyst incident-review section. Legacy `/incidents` remains separate. State, priority, confidence, and disposition changes require an explicit Save Review action. Adding a note and attaching or detaching evidence also require explicit operator actions; loading the panel does not mutate reviews. Successful changes refresh the history. History entries describe review actions and evidence references, not confirmed relationships or conclusions about an attack.
