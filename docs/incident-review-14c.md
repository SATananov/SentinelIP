# Incident Review 14C: Cross-Site Workload

## Purpose

14C adds a read-only **Site Workload** view to Analyst Operations. It summarizes where existing review workload is attributed so analysts can navigate to the existing Review Queue. It does not score sites, infer attacks or compromise, assign severity, or change analyst decisions.

## Endpoint and response

`GET /incident-review-operations/sites` returns a bounded page:

```json
{
  "sites": [],
  "pagination": { "limit": 20, "offset": 0, "total": 0 }
}
```

Site metrics are global and are not filtered by Review Queue filters. The endpoint includes only site groups with at least one review. `total` counts groups, including the unattributed group when present.

Each site row contains exactly:

- `site_id`, `site_name`
- `total_reviews`, `unresolved_reviews`, `open_reviews`, `in_review_reviews`, `closed_reviews`
- `reviews_needing_attention`, `high_priority_unresolved`
- `oldest_active_created_at`, `oldest_active_age_seconds`
- `latest_review_activity_at`

Attributed names are joined from `sites.name`. A null `site_id` forms one `Unattributed` group without creating a site record. If an attributed site name cannot be resolved, the name remains null.

## Metric definitions

- State counts use the matching review state. `unresolved_reviews` is `state != CLOSED`; `total_reviews` includes all states.
- `high_priority_unresolved` exactly follows 14B: non-closed reviews with priority `HIGH` or `CRITICAL`.
- `reviews_needing_attention` counts active reviews with one or more of the six 14B signals: `HIGH_PRIORITY_UNRESOLVED`, `AGING_REVIEW`, `NO_RECENT_ACTIVITY`, `REOPENED_REVIEW`, `MISSING_SOURCE_EVIDENCE`, or `NO_LINKED_EVIDENCE`. Closed reviews do not count. The shared operations rollup is reused so the rules match queue attention semantics.
- Active means `OPEN` or `IN_REVIEW`. `oldest_active_created_at` is the minimum active `created_at` in the group. Age is one request's UTC time minus that timestamp. Both fields are null for a group with no active reviews. This is workload age, not severity.
- Per-review latest activity is the maximum timestamp of its review events and notes, falling back to `incident_reviews.updated_at`. Site latest activity is the maximum per-review value. Full histories are not loaded.

## Sorts and pagination

Only these sort values are accepted:

- `unresolved_desc`: unresolved count descending
- `attention_desc`: attention count descending, then unresolved count descending
- `oldest_active`: active groups first, then oldest active timestamp ascending
- `recent_activity`: latest activity descending, nulls last
- `site_name`: case-insensitive name ascending, null names last

All sorts finish with the same deterministic identity order: attributed site IDs ascending, then the null/unattributed group. Limits are 1–100; offsets are 0–100000. Values are validated at the API and service boundaries.

## Queue drill-down

Selecting a site applies `site_id=<id>` to the existing queue. Selecting Unattributed uses the queue filter `unattributed_only=true`, which means `site_id IS NULL`. Combining `unattributed_only=true` with `site_id` is rejected. Scope and device drill-down continue to use the existing queue filters; 14C adds no global scope or device workload tables and no duplicate review detail flow.

## Read-only and performance behavior

The endpoint is GET-only and does not mutate reviews, evidence, notes, timeline, site, scope, device, or source evidence data. It uses the existing grouped evidence, note, event, and attention rollup, then groups once by site and joins site names once. It does not issue per-site or per-review lookups or load full child collections. Schema remains version 43; no migration was added.

The related-evidence suggestion query scaling issue and the `REVIEW_FIELD_CHANGED` field/event database constraint gap remain deferred and are unchanged by 14C.
