# Manual legacy SSH event retention

Legacy raw SSH events are retained for 90 days. The cutoff uses server-local
naive wall-clock time, matching the timestamp written by the legacy monitor.
The boundary is inclusive: a valid event timestamp at or before the displayed
cutoff is age-eligible.

Cleanup is manual. Load a fresh lifecycle preview, review the cutoff and counts,
then explicitly confirm each apply. An apply recomputes eligibility and deletes
at most 100 rows, oldest timestamp first with event ID as the tie-breaker. Run a
new preview and confirm another apply to remove a later batch. No scheduler or
startup cleanup runs.

This 90-day policy does not impose an event-rate, row-count, or database-file
size cap. A burst can add events before they reach the cutoff; SSH input-size
bounds remain outside this phase.

Only valid, unreferenced event rows are eligible. Events referenced by
`threat_evidence.ssh_event_id` remain preserved regardless of age. Malformed
rows and future timestamps are preserved and counted as skipped. Raw event
deletion removes the event-level message and severity; derived threat and
correlation records remain. Naive timestamps cannot distinguish the repeated
local hour at a daylight-saving transition. Clock rollback can delay cleanup;
a forward clock jump can make rows eligible earlier in wall-clock terms.

Before destructive cleanup, maintain and test a database backup using the
[SQLite backup and restore procedure](database-upgrade-safety.md). Restoring
replaces the whole database with its backup-time state, including later writes.

Deletion makes SQLite pages reusable internally. It does not guarantee that
the database file shrinks immediately. Cleanup does not run `VACUUM` or change
`auto_vacuum`.

The current append-only management-audit schema restricts cleanup classes to
DNS and web observations. Legacy-event cleanup is therefore not written to that
audit table in schema 45; it is not mislabeled as another data class. Adding a
legacy-events audit class would require a separate schema change.

The event-history range labeled “All retained history” means all currently
retained matching rows. The API preset remains `all`. Export response caps and
complete-or-rejected behavior are unchanged.
