# Incident Review 14D: Scope and Device Workload

## Purpose

14D adds read-only scope and device workload drill-down beneath the selected Site Workload context. Both views help navigate existing review workload into the existing Review Queue. They do not score or rank threats, infer compromise, change analyst decisions, or create another review or detail workflow.

## Site context

The endpoints are:

- `GET /incident-review-operations/scopes`
- `GET /incident-review-operations/devices`

Each requires exactly one context: a positive `site_id`, or `unattributed_only=true`. Missing context and conflicting context are rejected. A supplied site ID must exist. There is no global scope/device aggregation.

The Unattributed site context selects only reviews whose stored `incident_reviews.site_id` is null. Those reviews may still have a stored scope or device ID, which is included in the corresponding workload view. No site is inferred from scope, device, network, or relationship tables.

Both responses contain the relevant row array (`scopes` or `devices`) and `pagination` with `limit`, `offset`, and the number of matching attribution groups. Limits are 1–100 and offsets are 0–100000.

## Grouping and row fields

Scope rows are grouped strictly by `incident_reviews.scope_id`, with one fixed join to `authorized_scopes`. They return `scope_id`, `scope_name`, `scope_type`, `canonical_target`, total/open/in-review/closed/unresolved counts, attention and high-priority unresolved counts, oldest active timestamp and age, and latest review activity. A null scope is one `scope_id: null` group named `Unattributed`, with null type and canonical target. A blank stored scope name is returned as null; canonical target remains available as separate context.

Device rows are grouped strictly by `incident_reviews.device_id`, with one fixed join to `devices`. They return `device_id`, `device_label`, `hostname`, total and unresolved counts, attention and high-priority unresolved counts, oldest active timestamp and age, and latest review activity. The label uses hostname, then stable key, then `Device #<id>`. The ID fallback identifies a device row; it is not an inferred hostname. A null device is one `device_id: null` group labeled `Unattributed`, with null hostname.

Scope and device grouping does not infer attribution through network membership, IP matching, `network_scope_links`, `remote_scope_sites`, or other inventory relationships. A review missing scope or device attribution remains in the null group for that dimension.

## Metrics

- Active reviews have state `OPEN` or `IN_REVIEW`; unresolved means state is not `CLOSED`.
- High-priority unresolved follows the established rule: unresolved and priority `HIGH` or `CRITICAL`.
- Attention counts reuse the 14B rollup and its six existing signals. A group counts active reviews with one or more signals; no new rule, level, or score is introduced.
- Oldest active time is the minimum `created_at` among active reviews in the group. Age uses one timezone-aware UTC request clock. Closed-only groups have null age fields. Age is workload age, not severity.
- Per-review activity is the maximum review event and note timestamp, falling back to `incident_reviews.updated_at`. Group activity is the maximum per-review value; full child histories are not loaded.

## Sorting and queue drill-down

Scope sorts are `unresolved_desc`, `attention_desc`, `oldest_active`, `recent_activity`, and `name`. Device sorts are `unresolved_desc`, `attention_desc`, `oldest_active`, `recent_activity`, and `label`. Sorts use deterministic ID tie-breaks, with null attribution last for ties; null timestamps sort last. Blank scope names sort after non-empty names. Arbitrary columns and directions are not accepted.

The frontend shows Scope Workload and Device Workload only after a Site Workload row is selected. It uses tabs and fetches only the active view. Changing sites resets both workload offsets, clears stale scope/device drill-down selections, and resets queue pagination. Selecting a scope or device applies its ID to the existing queue while preserving site context. Selecting an unattributed group uses `unattributed_scope_only=true` or `unattributed_device_only=true`; these mean the respective review field is null and cannot be combined with that field's ID filter.

Review selection still opens the existing `IncidentReviewSection`. The new queue flags do not change existing 14A–14C filters or sorts.

## Read-only and performance behavior

The endpoints are GET-only and do not mutate reviews, evidence, notes, events, sites, scopes, devices, or source evidence. They scope the shared 14A/14B rollup to the selected site context before grouped child aggregates, then group by the stored review attribution field and join the matching scope or device once. Evidence source availability uses the existing static, batched mapping. The endpoints do not load full evidence, note, or timeline collections and do not issue per-row lookups.

Schema remains version 43; no migration was added. The related-evidence suggestion-query scaling issue and the `REVIEW_FIELD_CHANGED` field/event constraint gap remain deferred.
