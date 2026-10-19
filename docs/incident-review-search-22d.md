# Incident Review Search 22D — Verification Closure

## Verified behavior

Migration 45 initializes the title-only external-content FTS5 index and its insert, title-update, and delete triggers. Fresh initialization is idempotent and records schema versions 1 through 45 once. The 44→45 migration rebuilds the index from existing review titles without changing review rows or identifiers. Search, update, delete, rebuild, and FTS integrity checks are covered against temporary databases.

`GET /incident-reviews/search` continues to use the bounded 22B contract: Unicode token-prefix terms joined with AND, optional structured and date filters, fixed candidate projection, `updated_at DESC, id DESC` ordering, a limit-plus-one `has_more` check, and no total-count query. The route remains under `local_management` and inherits `Cache-Control: no-store`. Existing review list, operations, exact lookup, reports, and lifecycle behavior remain separate.

The frontend search remains inside the Incident Review section. It uses the centralized API base, fixed GET endpoint, `cache: no-store`, explicit query-field allowlisting, a fixed 20-row page, and abort/generation protection. Calendar date inputs are converted from local midnight to explicit UTC timestamps; the inclusive end date is represented by the next local day’s exclusive boundary. Selecting a result passes the review ID through the existing controlled detail-selection callback. Search criteria and results are held only in component memory.

## Query plans

Representative `EXPLAIN QUERY PLAN` results for one-token, multi-token, created-range, site, and disposition-plus-closed-range searches all showed:

```text
SCAN incident_reviews_fts VIRTUAL TABLE INDEX 0:M1
SEARCH r USING INTEGER PRIMARY KEY (rowid=?)
USE TEMP B-TREE FOR ORDER BY
```

The FTS virtual-table index is used for title filtering. SQLite sorts matching candidates to preserve the stable updated-time order; that temporary sort is expected.

## Synthetic performance sanity check

The check used two isolated temporary SQLite databases initialized through the application migration path: 10,000 and 50,000 review rows. Titles included common and selective Latin tokens, two-token matches, Cyrillic titles, and generated identifiers. State, priority, disposition, timestamps, and valid site/scope/device attribution contexts varied. Each bounded search used `limit=20`, `offset=0`, and five timed calls through `search_reviews`; values below show median and slowest call in milliseconds. They include normal database initialization/check overhead and are environment-specific, not a production SLA.

| Search | 10k median / max ms | 50k median / max ms |
| --- | ---: | ---: |
| Common one-token prefix | 15.80 / 19.01 | 19.32 / 35.41 |
| Selective one-token prefix | 8.71 / 15.44 | 3.49 / 5.13 |
| Two-token AND | 11.52 / 14.57 | 11.82 / 21.42 |
| Title plus created range | 17.46 / 21.94 | 36.26 / 48.90 |
| Title plus site | 17.21 / 32.02 | 15.84 / 29.70 |
| Title plus disposition and closed range | 14.43 / 22.22 | 19.04 / 63.23 |
| No match | 10.95 / 12.66 | 3.12 / 5.65 |

The indexed insert batches took about 1.57 seconds for 10k rows and 6.07 seconds for 50k rows. On the 50k database, common-term offset pages at 1,000 and 10,000 returned 20 rows in about 47.83 ms and 119.85 ms. Rebuilding the FTS index followed by the external-content integrity check succeeded, and sampled review rows were unchanged. These measurements show bounded result materialization and no pathological jump at 50k in this local synthetic run; they do not predict production latency or concurrent workload behavior.

## Local verification limits

The search and migration test files passed locally. A larger combined backend regression run stalled in this TestClient environment after partial progress and was interrupted; this is not a completed full-suite result. The latest authoritative full backend result remains the 22B baseline of 1,426 passing tests. A completed authoritative Kali run is still required before Phase 22 closure.

## Known limitations

- Matching is title-only token-prefix search, not arbitrary substring matching.
- No fuzzy, typo-correction, semantic, or relevance-ranked search.
- No search of summaries, notes, evidence, or timeline content.
- Search remains local-operator-only; remote operator search is unsupported.
- Pagination uses bounded offset pagination.
- SQLite FTS5 is required; there is no LIKE-scan fallback.
- Synthetic results are not a production performance SLA.
- Legacy JSON/CSV/PDF export bounding, spreadsheet formula handling, and PDF markup escaping remain deferred maintenance.
