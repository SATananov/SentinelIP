# Phase 18C — Bounded Evidence-Aware Retention Cleanup

## Scope and operation

Manual `POST /data-lifecycle/cleanup` can delete only expired `DNS_OBSERVATIONS` or `WEB_OBSERVATIONS`. Request JSON contains exactly one field, `data_class`, set to one of those values. Extra fields and query parameters are rejected. The server fixes `MAX_CLEANUP_BATCH` at 100. There is no row selector, custom date, retention override, delete-all mode, scheduler, startup task, background worker, ingestion hook, or sensor trigger.

The endpoint uses `local_management`: loopback client and local Host/Origin checks apply, forwarded headers, Authorization, and sensor identity/token headers are rejected, and successful responses carry `Cache-Control: no-store`.

## Eligibility and evidence

One aware UTC `evaluated_at` is captured for each cleanup execution. Expiry is inclusive (`retention_until <= evaluated_at`). Null, malformed, and future retention values are preserved and omitted from cleanup counts.

DNS observations have no direct review evidence dependency. A web observation is deletable only when every dependent web detection has a valid persisted typed snapshot containing that observation. The shared `web_observation_protected_by_dependency` policy uses the same 18B typed detection/evidence validation and dependency classification for preview and cleanup. An incomplete, malformed, invalid, or omitting snapshot protects the observation once, even if multiple dependent links exist.

Web deletion relies on existing `ON DELETE SET NULL` foreign keys for `web_detections.primary_observation_id` and `web_detection_observations.observation_id`. Detection rows and their `structured_evidence` remain. Incident Review evidence links point to `WEB_DETECTION`, so the reviewed source remains available.

## Transaction and result

Cleanup starts `BEGIN IMMEDIATE`, classifies current expired rows, counts all eligible rows before the batch limit, selects at most 100 eligible IDs oldest first (`julianday(retention_until) ASC, id ASC` semantics), rechecks row presence/deadline and current web dependency policy, deletes only those selected IDs, then recomputes protected and remaining-eligible counts before commit. Any failure rolls back the complete batch. Repeated or empty cleanup succeeds; preview is informational and never authorizes deletion.

The response contains only `data_class`, `evaluated_at`, `eligible_before`, `deleted_count`, `protected_count`, `remaining_eligible`, and `batch_limit`. `eligible_before` is the pre-limit eligible count. `protected_count` is expired web observations withheld due to unsafe dependencies (normally zero for DNS). `remaining_eligible` is recomputed from current state in the transaction.

The UI requires a successful current-generation preview with eligible rows, disables duplicate submissions, and requests explicit confirmation that describes the irreversible bounded action and server revalidation. After success it shows the result and performs one fresh preview; there is no polling.

## Operational limits

No cleanup history table, archival, `VACUUM`, auto-vacuum change, or migration is introduced. Schema remains version 43.

There is no `retention_until` index. Deadline classification scans the observation table; the 100-row limit bounds writes, not scan cost. Primary web-detection references require one detection scan; explicit observation links use the existing observation-link index. This is linear work and should be checked against bounded synthetic data. No index or migration is included in 18C.

On the local 30,000-row synthetic check (15,000 expired rows per class, no detections), both deadline query plans were full table scans. DNS cleanup selected/deleted 100 and recomputed 14,900 remaining in about 0.13 seconds; web cleanup did the same in about 0.19 seconds. Web dependency classification scans detections for primary references during initial eligibility, selected-ID revalidation, and post-delete remaining counts. This is a local smoke measurement, not a timing guarantee.
