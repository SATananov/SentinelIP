# Incident Review 14B: Review Triage and Attention Signals

## Purpose and boundaries

14B adds deterministic, computed workflow attention signals to the existing read-only `GET /incident-review-operations` response. Signals help analysts find reviews that may need attention. They do not change analyst priority, state, confidence, disposition, or evidence; they do not create, close, or reopen reviews; and they do not imply attack, compromise, vulnerability, or threat severity.

There are no signal levels, numeric scores, or hidden severity ranking. The fixed signal order below is display order only.

## Signal allowlist and rules

Signals apply only to active (`OPEN` or `IN_REVIEW`) reviews. Closed reviews always return an empty `attention_signals` list, zero count, and `has_attention=false`.

| Display order | Code | Rule | Label | Reason |
| --- | --- | --- | --- | --- |
| 1 | `HIGH_PRIORITY_UNRESOLVED` | Analyst priority is `HIGH` or `CRITICAL`, and state is not `CLOSED`. | High-priority unresolved | High-priority analyst review remains unresolved |
| 2 | `AGING_REVIEW` | 14A age is at least 86,400 seconds, using request UTC time minus `created_at`. | Review aging | Active review has been open for at least 24 hours |
| 3 | `NO_RECENT_ACTIVITY` | 14A `latest_activity_at` is at or before the request UTC time minus seven days. | No recent activity | Active review has had no recorded review activity for at least 7 days |
| 4 | `REOPENED_REVIEW` | Latest `REVIEW_REOPENED` is after latest `REVIEW_CLOSED`, comparing event time and then event ID. | Reopened review | Active review was reopened after its latest closure |
| 5 | `MISSING_SOURCE_EVIDENCE` | At least one linked evidence source row is unavailable under its fixed evidence-type mapping. | Missing source evidence | One or more linked evidence sources are no longer available |
| 6 | `NO_LINKED_EVIDENCE` | The active review has zero linked evidence records. | No linked evidence | Review has no linked evidence |

The `attention_signals` array contains only `code`, `label`, and `reason`, in this fixed order, with at most six entries and no duplicates.

## API additions

Queue rows add `attention_signals`, `attention_signal_count`, and `has_attention`. Summary adds global `reviews_needing_attention` and a zero-filled `signal_distribution`. The latter counts reviews per signal, not review events. Existing 14A summary remains global; queue filters affect queue rows and pagination total only.

New allowlisted filters are `has_attention` and `attention_signal`. `has_attention=false` combined with any `attention_signal` is rejected as contradictory. `has_attention=true` may be combined with a signal code. The existing five sort modes and pagination limits are unchanged.

## Performance

Attention values are derived in the 14A aggregation service using the same single UTC request clock as age and 24-hour metrics. Reopen status uses grouped event ranking by event time and ID. Evidence availability uses a fixed `UNION ALL` across supported evidence types, joining linked IDs to the corresponding source tables, then groups the result per review. No user-controlled table names, payload loading, or per-review/per-link lookup loop is used. Queue limit remains 1–100 and offset 0–100000.

## Deferred issues

The related-evidence suggestion-query scaling issue and the `REVIEW_FIELD_CHANGED` database constraint pairing gap remain tracked separately and are unchanged by 14B.
