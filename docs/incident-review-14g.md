# Incident Review 14G — Analyst Operations Consolidation

## Purpose

14G consolidates the existing Analyst Operations workspace after 14A–14F. It adds no review workflow, API, or backend capability. The goal is to keep queue and detail navigation reliable, make independent resource requests race-safe, and place secondary activity/trend views behind clear native disclosures.

## Controlled selection and request safety

Queue and activity buttons pass a review ID through the existing controlled `selectedReviewId` interface to `IncidentReviewSection`. Before it starts the controlled detail request, the component synchronizes the ID in the existing review request guard and begins a new generation. Selecting another review invalidates earlier work; closing the detail invalidates pending requests. Only the current generation may update selected review, timeline, notes, evidence, errors, or mutation results.

Analyst Operations resources use a small per-resource generation guard together with `AbortController`. Only the current generation may update data, errors, or loading state. Queue results are associated with their exact filter/sort/page query key. A query change makes old queue rows unavailable for display immediately; the current request shows a loading state. A refresh of the same query can retain its rows with an explicit updating status.

## Component and state ownership

- `IncidentReviewOperations` coordinates the operations summary, sites, queue, selected site context, attribution drill-down, and review navigation.
- `ReviewActivitySection` owns activity filters, pagination, request lifecycle, and its loading/error/empty states.
- `WorkloadTrendsSection` owns the trends window and request lifecycle, including current snapshot and aging display.
- Scope/device sort and pagination remain independent in the coordinator; only the active attribution tab is fetched.
- Queue, site, scope, device, and activity pagination remain independent. Site selection intentionally resets queue/scope/device offsets and clears incompatible attribution filters. Scope or device selection intentionally resets only queue offset while preserving site context.

Activity and Trends use native collapsed disclosures and fetch only while open. The Review Queue remains directly visible, and the authoritative `IncidentReviewSection` is placed immediately after the queue. Legacy Security Incidents remain a separate section.

## Site context

Selected real sites display their stored name when available, falling back to `Site #<id>`. The unattributed group displays `Unattributed`. Scope/device workload remains constrained by the selected real or unattributed site context. Activity row selection only selects the review; it does not change queue or workload filters.

## Backend, API, and schema

No backend files or API contracts changed. The six 14A–14F operations endpoints, attention rules/order, activity summary policy, current-attribution semantics, trend windows/buckets, and read-only semantics are unchanged. No migration was added; schema version remains 43.

## Deferred items

- Related-evidence suggestion query scaling remains tracked separately.
- `REVIEW_FIELD_CHANGED` event/field database constraint pairing remains tracked separately.
- Global activity-feed ordering/index optimization remains measurement-driven.
- Repeated rollup cost across overview and trends has not been optimized in 14G.
- The overall frontend bundle warning remains; no code splitting or new chart dependency was introduced.

## Phase 14 closure criteria

Phase 14 can close after the controlled queue/activity selection and rapid A→B paths are verified; stale detail, mutation, and operations responses are rejected; queue context changes do not display old rows; queue/site/scope/device/activity/trend state stays independent; selected site context remains visible and preserved; 14A–14F contracts and 13A–13D workflows regress cleanly; the full backend suite, frontend lint/build/Node tests, and `git diff --check` pass; and schema remains at version 43.
