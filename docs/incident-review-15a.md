# Incident Review 15A — Review Intake Foundation

## Purpose

15A adds one explicit manual Incident Review creation flow to the existing Incident Reviews area. Reviews are analyst investigation records; creating one does not confirm an attack or compromise.

## Form and server defaults

The form accepts a required Review Title (trimmed, at most 160 characters), optional Summary (at most 4,000 characters), Review Priority, Review Confidence, and optional site, scope, and device IDs. Priority and confidence default visibly to `MEDIUM`.

The frontend sends only `title`, `summary` when non-empty, `priority`, `confidence`, and selected `site_id`, `scope_id`, and `device_id`. It does not send state, disposition, notes, final summary, generated identifiers or timestamps, or evidence.

The existing API supplies `OPEN`, `UNREVIEWED`, empty summary when omitted, null `closed_at`, and null evidence timestamp bounds. The database creates the ID, `IR-` key, and timestamps. It records exactly one `REVIEW_CREATED` event atomically with the review insert.

## Attribution

Attribution is optional and uses explicit positive IDs. The form does not load broad catalogs or infer relationships. The existing backend validates that provided records exist and that supplied site/scope/device combinations are consistent. Server validation errors remain visible in the form.

## Duplicate submissions and request races

The form disables submission and cancellation while a create request is active. An attempt guard prevents a second concurrent submission and ignores responses after the form has been invalidated or unmounted. If the analyst selects another review while creation is pending, the new review is added to the list but does not replace that deliberate selection.

Creating a review invalidates any older pending list response before inserting the returned review locally. A later fresh list request may reconcile the list with server state.

On the normal success path, the returned review is selected through the existing selection callback and request guard, opening the existing IncidentReviewSection detail. A targeted refresh signal refreshes the operations queue, site workload, and any active scope/device workload. Activity and trends are not refetched for review creation.

## Evidence and safety boundary

15A does not attach evidence, inspect source detections, run scans, or mutate source evidence. It does not create timeline events client-side, choose a disposition, close a review, or make attack or compromise claims. Source-to-review promotion is deferred to 15B/15C.

## Schema

No migration is required. Schema remains version 43. The existing `POST /incident-reviews` contract is reused.
