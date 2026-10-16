# Incident Review 14A: Analyst Operations

## Purpose

Analyst Operations provides a read-only workload overview and Review Queue over the existing incident review records. It helps operators find reviews needing attention and understand their state, analyst priority, disposition, age, and recent review activity. It does not create reviews, change evidence or dispositions, close reviews, run detection, or establish attack or compromise.

Priority is an analyst workload priority, not an automatically assigned threat severity.

## Queue and age

The queue returns compact review metadata and aggregate evidence/note counts. It does not include source evidence payloads, full notes, or full timelines.

For `OPEN` and `IN_REVIEW` reviews, age is the integer number of seconds from `created_at` to one timezone-aware UTC request time. Closed reviews have null `age_seconds` and `age_bucket`. Buckets are `LT_1H` (< 1h), `H1_24` (1h–24h), `D1_3` (1d–3d), `D3_7` (3d–7d), and `GT_7D` (> 7d). Age describes workload age, not severity.

`latest_activity_at` is the later of the latest event and latest note timestamps. Reviews without either fall back to `incident_reviews.updated_at`.

## Filters and sorting

Filters are allowlisted: state, priority, disposition, site ID, scope ID, device ID, evidence presence, active age bucket, and unresolved-only. `unresolved_only=true` means state is not `CLOSED`; combining it with `state=CLOSED` is rejected. Age buckets match active reviews only.

Sorts are `newest` (creation descending), `oldest` (creation ascending), `priority` (CRITICAL, HIGH, MEDIUM, LOW, then creation ascending), `recently_updated` (update descending), and `oldest_open` (active reviews first by creation ascending, then closed reviews by creation ascending). All have deterministic ID tie-breakers.

Pagination accepts limits from 1 to 100 and offsets from 0 to 100000.

## Overview metrics

The endpoint includes global total and state counts, unresolved count, all priority and disposition distribution values (including zero counts), active age buckets, reviews created in the last 24 hours, reviews closed in the last 24 hours, counts by site (a null `site_id` represents unattributed reviews), and at most 20 recent activity events. Queue filters apply to the queue and its pagination total; summary metrics remain global. Time-window metrics share one UTC request clock. Recent activity contains compact event fields only.

## Deferred issue

The related-evidence suggestion-query performance issue remains tracked separately and is not changed by 14A.
