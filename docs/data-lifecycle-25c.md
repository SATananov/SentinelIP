# Phase 25 — Legacy event retention close-out

Phase 25 adds a manual retention workflow for legacy raw SSH events. The
90-day window is an explicit operator/product policy. It is not an automatic
cleanup schedule or a hard database-growth limit.

## Policy and eligibility

Event timestamps remain naive server-local wall-clock values. For each preview
or apply, the service establishes one local evaluation time and computes the
cutoff as that time minus 90 days. A valid timestamp at or before the cutoff is
age-eligible; a timestamp after the cutoff is retained. Future timestamps and
malformed timestamps are retained and reported as skipped. Required row fields
that cannot be classified safely also make the row malformed and ineligible.
Age is never inferred from the event ID.

Only an event without a live `threat_evidence.ssh_event_id` reference can be
deleted. Referenced raw events are preserved regardless of age, including their
message and severity. The existing `ON DELETE SET NULL` foreign key behavior is
not used as the retention policy. No threat snapshot, correlation, or Incident
Review behavior is changed.

The timestamps cannot distinguish the repeated local hour at a daylight-saving
transition. A clock rollback can delay eligibility; a forward clock jump can
make events eligible earlier in wall-clock terms. These legacy timestamp
semantics are unchanged; no timestamp migration is included.

## Preview and apply

The local operator loads a read-only preview before cleanup. It reports the
90-day policy, evaluation time and cutoff, total rows, eligible unreferenced
rows, protected references, malformed and future rows, oldest valid retained
and eligible timestamps where available, and a maximum next batch of 100. The
preview does not authorize or perform deletion.

Each apply is explicitly confirmed by the local operator and recomputes
eligibility. It deletes at most 100 selected IDs, oldest timestamp first with
ID ascending as the tie-break. A second batch requires another explicit apply;
there is no loop-to-completion, scheduler, startup cleanup, periodic task, or
cleanup on reads or writes.

An apply opens a SQLite connection, starts `BEGIN IMMEDIATE`, classifies the
event table, selects at most 100 candidates, checks references, deletes only
the selected unprotected IDs, verifies the affected-row count, and commits.
Exceptions roll back the batch, and the connection is closed on all paths. The
classification and its counts share the write transaction's consistent view;
counts are adjusted by the number deleted without a second full scan before
commit. A failed write, reference check, delete, or row-count check does not
commit a partial batch.

### Writer-lock tradeoff

The candidate collection is bounded to at most 100 entries and database rows
are streamed rather than fully materialized. However, the classification pass
scans and classifies every event while `BEGIN IMMEDIATE` holds SQLite's writer
reservation. Timestamp parsing and the correlated reference check occur during
that pass. The reference lookup uses the existing
`idx_threat_evidence_ssh` index. The operation does not rescan all events after
deletion before commit.

This bounds deletion and Python candidate memory, but it does **not** bound the
number of rows scanned or the writer-lock duration independently of event-table
size. No claim of bounded scan work or production-scale latency is made. Any
future lock-scope or query optimization requires representative scale evidence
and is outside Phase 25.

## Evidence, audit, and recovery

Cleanup permanently removes the raw event row, including its message and
severity. Threat-referenced rows remain untouched. The immediate apply response
reports deleted, remaining eligible, protected, malformed/skipped, and
future/skipped counts.

Schema 44's append-only management-audit table permits lifecycle cleanup audit
classes only for `DNS_OBSERVATIONS` and `WEB_OBSERVATIONS`. Successful DNS/web
cleanup appears in Management History. Legacy-event cleanup is **not** stored
in that management cleanup audit table in schema 45. The Phase 25 operator
contract does not promise that every destructive data class appears there; the
apply response reports the result. No migration is added to extend the audit
class allowlist.

Cleanup is destructive. Before applying it, operators should maintain and test
a database backup using the [SQLite backup and restore procedure](database-upgrade-safety.md).
The documented procedure uses SQLite's online backup API and checks integrity
and schema version. Restore replaces the database with its backup-time state,
so it can discard writes made after the backup.

Deleting rows makes SQLite pages available for reuse; it does not guarantee
that the database file shrinks or that filesystem space is reclaimed
immediately. Retention does not run `VACUUM` or change `auto_vacuum`.

## Operator history and scope

The event-history UI says **All retained history**. The API preset remains
`all`, meaning all matching rows currently present in the retained `events`
table. Event history, source-IP filters, overview/statistics, and Phase 23
exports keep their existing query and export contracts.

The lifecycle routes remain local-management operations with no-store
responses. Phase 18 DNS/web retention eligibility, snapshot protection,
100-row batching, and management-audit behavior are unchanged. The schema stays
at version 45; Phase 25 adds no migration or index.

The established authoritative backend TestClient/AnyIO stall occurs before
router entry and is also known on the clean baseline. Phase 25 focused tests
and regressions passed, but this close-out does not claim that the authoritative
full backend suite completed.

Out of scope: automatic cleanup, hard row-count or disk-size limits, SSH
subprocess or parser/input bounds, query pagination/index changes, DNS/web
retention redesign, Incident Review changes, exports, telemetry, and changes to
authentication or proxy behavior.
