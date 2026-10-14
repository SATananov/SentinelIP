# Incident Review 13D: Disposition and Resolution Workflow

13D makes closing an incident review an explicit analyst workflow decision. A
review disposition is a structured analyst outcome, and `final_summary` is the
analyst's bounded explanation of that outcome. Neither is source evidence or
proof of an attack, compromise, intrusion, exploitation, vulnerability, root
cause, or malicious attribution. Existing source evidence remains authoritative
and unchanged.

## Closure and reopening

New reviews begin in `OPEN` or `IN_REVIEW`; they cannot be created directly as
`CLOSED`. A review may be closed through the existing
`PATCH /incident-reviews/{id}` endpoint only when the merged result has a
disposition other than `UNREVIEWED` and a non-empty final summary. The summary
is plain text, trimmed by the service, and limited to 4,000 characters. It may
be null while the review is open. `closed_at` is set by the server when the
review closes.

An already-closed review remains readable even if it predates 13D and has no
final summary. Such reviews are not backfilled or assigned synthetic history.
While a review is closed, no-op PATCH is safe; reopen it before making edits.
Reopening is an explicit PATCH to `OPEN` (or `IN_REVIEW` through the API),
clears `closed_at`, and retains disposition and final summary. The retained
summary describes the previous closure until changed. A later closure validates
the current disposition and summary again and sets a new `closed_at` value.

## Timeline

Migration 43 adds the nullable, 4,000-character-bounded
`incident_reviews.final_summary` field and allows `FINAL_SUMMARY_CHANGED` in the
append-only timeline. The event-table migration copies all prior event rows,
including IDs and references, and restores the timeline index and append-only
triggers. It creates no historical events.

An actual normalized final-summary change emits `FINAL_SUMMARY_CHANGED` with
`old_value` and `new_value`; clearing a summary while open is also recorded.
An unchanged normalized value emits nothing. Disposition changes emit
`DISPOSITION_CHANGED`. Closing emits exactly one `REVIEW_CLOSED` lifecycle
event, and reopening emits exactly one `REVIEW_REOPENED`; neither also emits
`STATE_CHANGED`. When a PATCH changes multiple fields, event insertion follows
the database helper's stable field order: state, priority, confidence,
disposition, final summary, title, summary, site, scope, device, then legacy
analyst note. Timeline reads remain newest-first by persisted timestamp and ID.

The review mutation and its generated events commit in one transaction. A
validation failure changes neither the review nor its history. Previous
closure, reopening, disposition, note, and evidence-link history is retained.
The event actor remains `OPERATOR`, since the review routes do not have an
authenticated user identity.

## Analyst interface

Open reviews provide explicit Save Draft and Close Review actions. The close
action asks the operator to select a disposition and provide a final summary;
the server repeats these checks. Closed reviews show their disposition, final
analyst summary, and `closed_at`, with an explicit Reopen Review action. After
reopening, the retained closure summary is identified as belonging to the
previous closure. These controls describe completion of a review workflow and
do not present a security conclusion.
