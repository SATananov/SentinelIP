# Incident Review 14F — Review Workload Trends & Aging Overview

## Purpose and endpoint

`GET /incident-review-operations/trends` provides a bounded read-only historical workload series alongside a separate present-state snapshot. It uses existing review rows and append-only events. It does not create snapshots, historical state estimates, predictions, anomaly scores, threat or risk trends, SLA scores, or analyst performance measures.

The response contains `window`, `bucket`, `window_start`, `window_end`, `series`, and `current_snapshot`. Supported windows are exactly `24h`, `7d`, `30d`, and `90d`; the default is `30d`.

## Historical series

One timezone-aware UTC request clock defines `window_end`; `window_start` is the selected duration earlier. Buckets are contiguous, zero-filled, and half-open (`bucket_start <= timestamp < bucket_end`). The overall window is also half-open, so timestamps at `window_end` and future timestamps are excluded.

| Window | Bucket size | Bucket count |
| --- | --- | ---: |
| 24h | 1 hour | 24 |
| 7d | 1 day | 7 |
| 30d | 1 day | 30 |
| 90d | 1 day | 90 |

Each series row contains only `bucket_start`, `bucket_end`, `reviews_created`, `review_close_events`, and `review_reopen_events`.

- **Reviews created** counts `incident_reviews.created_at`, once per review. `REVIEW_CREATED` events are not counted for this metric, so legacy reviews without a creation event are included without double-counting.
- **Review closures** counts recorded `REVIEW_CLOSED` events. It is event volume, not unique reviews closed; repeated closures count separately.
- **Review reopens** counts recorded `REVIEW_REOPENED` events. It is event volume and does not label a reopen as a failure.

Close and reopen series reflect events present in the event log. Older transitions from before append-only history existed may be absent; the series is not a complete lifecycle reconstruction.

## Current snapshot

`current_snapshot` contains `as_of`, `open_count`, `in_review_count`, `closed_count`, `unresolved_count`, `reviews_needing_attention`, `age_buckets`, and `oldest_active_age_seconds`. These values describe present state at `as_of`; they are not historical series.

Attention reuses the established 14B rules and counts active reviews with at least one of the six existing attention signals. Active age is the 14A definition: UTC `as_of` minus `created_at` for OPEN and IN_REVIEW reviews. The five age keys are `LT_1H`, `H1_24`, `D1_3`, `D3_7`, and `GT_7D`; closed reviews do not contribute. Oldest active age is based on the minimum active review creation time and is null when there are no active reviews. Age is workload age, not severity.

Historical unresolved and attention values are explicitly excluded. Current rows and incomplete legacy event history do not support exact reconstruction of past state or past attention.

## Scope and read-only behavior

14F is global in this phase. It has no site, scope, device, search, or arbitrary expression filters; this also avoids presenting current attribution as historical attribution. GET does not mutate reviews, events, notes, evidence links or source evidence, sites, scopes, or devices.

The Analyst Operations UI presents the three historical series—Reviews Created, Review Closures, and Review Reopens—separately from Current Workload and Current Aging. Window selection only refetches this view. The chart uses Recharts and contains no predictive series or threat language.

## Performance and deferred work

The trend queries group timestamp/count pairs in SQL, then map the compact groups into the fixed, bounded bucket set. This avoids fetching full review or event histories and avoids one query per bucket. Current snapshot values use the shared 14A/14B review rollup. SQLite `julianday` precision near sub-millisecond boundaries is handled by fetching a one-second coarse margin and applying exact UTC, half-open bucket membership in Python.

Query plans use scans for review creation timestamps and recorded lifecycle events; available indexes do not provide a global timestamp range for these sources. Current attention uses the existing grouped child rollups. No migration is added for temporary grouping or sorting alone; assess measured scale before proposing indexing work.

The related-evidence suggestion-query scaling issue, `REVIEW_FIELD_CHANGED` database event/field pairing gap, and global activity-feed index optimization remain deferred.
