# Phase 30C: Perimeter evidence retention

Perimeter retention is a manual, local-operator action. A complete perimeter
evidence component is eligible only when every member event has a valid,
timezone-aware server `received_at` at or before the cutoff of 180 elapsed days.
`observed_at`, detection timestamps, and correlation timestamps do not control
retention. Future, malformed, naive, or otherwise ambiguous timestamps are
preserved.

Events, detections, policy correlations, and host correlations are classified as
one transitive graph using all stored membership lists and primary-event links.
Current Incident Review links and historical `EVIDENCE_ATTACHED` or
`EVIDENCE_DETACHED` records preserve the complete linked component. Malformed or
unresolvable graph/reference data blocks cleanup for that classification run.

Preview is non-destructive. Apply recomputes under `BEGIN IMMEDIATE`, selects at
most 25 eligible components oldest-first, and deletes each selected component
whole in a single transaction. A failure rolls back the entire apply. Large
components are not split or rejected by a numeric size threshold; preview shows
their row counts because a large component can hold SQLite's writer lock longer.

The classifier streams rows in fixed batches and keeps graph state in
connection-local SQLite TEMP tables configured for file-backed TEMP storage
with a 200-page TEMP cache. Python retains only the current fixed row batch and
its expanded memberships; membership lists are capped at 256 IDs and input JSON
fields are byte-capped during classification. TEMP storage and total process
resources still scale with graph size; this is not a whole-process memory or
disk bound.

The request is available only through the existing `local_management` boundary.
Apply requires explicit confirmation. The operation is not recorded in the
typed management cleanup audit because that schema only represents DNS and web
cleanup; no migration was added for audit convenience. A recent verified backup
is strongly recommended before apply, but backup absence does not block it.
Cleanup does not run `VACUUM`, and the SQLite file may not shrink immediately.

After deletion, a sensor redelivery of the same event identity may be accepted
as new evidence and receives a new server receipt time. No tombstone is kept.
Perimeter ingestion logic and schema 46 are unchanged.
