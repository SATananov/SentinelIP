# Phase 34 — Source-IP Dashboard Scaling Close-Out

## Selected risk

Phase 33 selected unbounded source-IP enumeration and recurring dashboard source-IP scaling. Before Phase 34, the dashboard requested `/source-ips` on every five-second refresh. The route selected every distinct historical `events.source_ip`; the client serialized the full response into one native select. The recurring top-IP summaries also grouped the complete event history.

Phase 33's synthetic one-million-distinct-source baseline was approximately 1.023 seconds for query/fetch, 14.47 MB of JSON, and 147 MiB of traced Python peak allocations during fetch, projection, and serialization. This measurement covered the full catalog path and is not directly comparable to the final point lookups or sample summaries below.

## Contract and implementation

### Exact source lookup

`GET /source-ips` remains local-management protected and retains the `no-store` behavior from that dependency. The optional `q` has a raw maximum length of 32 characters. Missing, empty, or whitespace-only input returns `{"items":[]}` without calling the database lookup. Nonempty input is trimmed, limited to 15 characters, and accepted only if it is canonical dotted-decimal IPv4. Invalid, noncanonical, partial, or IPv6 input follows the HTTP 422 validation path.

The route calls `find_source_ip()`, whose SQL is parameterized exact equality with `LIMIT 1`. It returns zero or one address. The query plan on the migrated schema is:

```text
SEARCH events USING COVERING INDEX idx_events_threat_window (source_ip=?)
```

There is no source-IP catalog enumeration in the API or frontend.

### Recurring top-IP summaries

`get_recent_top_source_ips()` first selects at most 10,000 rows by descending event ID, then groups by source IP, sorts by `event_total DESC, source_ip ASC`, and applies the route's result limit. The inner query uses the events table's rowid-backed `id` ordering and stops at its limit. `EXPLAIN QUERY PLAN` reports a bounded subquery scan and temporary B-trees for grouping and ordering the subquery output; it does not group the full event history. The VM plan for the inner query uses `Last`, `DecrJumpZero` with 10,000, and `Prev` to walk the newest rowids and stop at the fixed bound.

For `/overview`, the result limit is five. `/stats/top-ips` retains its caller limit of 1–100; that value does not change the 10,000-row input sample. Each returned `event_total` is the count for that source IP within the sample. Both routes identify the basis as:

```json
{"mode":"latest_events","sample_size":10000}
```

`overview.total_events` remains a separate historical count. The explicit all-history `get_top_source_ips()` helper remains in use by `report.py` and was not switched to the recent sample.

### Dashboard filter

The frontend no longer stores or renders a source catalog and does not request `/source-ips`. Its filter is a text input with Apply/Enter and Clear IP actions. `ipDraft` holds editable text; `ipFilter` holds the applied exact filter. Only Apply, Enter, Clear IP, or Clear filters changes the applied value. Event queries and export queries use `ipFilter`, never the draft. Client-side canonical IPv4 validation is for operator feedback; the backend remains authoritative.

The five-second dashboard refresh leaves both filter values intact. A request-generation guard suppresses stale dashboard responses, errors, and loading completion. The top-IP panel reads the sample description from backend metadata; its item counts are labelled as recent events. Missing or malformed metadata produces no fabricated sample size. The historical overall event total retains its existing meaning.

## Verification evidence

### Disposable large-data measurements

Measurements used disposable databases initialized with the repository schema and `idx_events_threat_window`, with one distinct IPv4 source per event. Times include opening the helper connection and executing the query. Python peak is `tracemalloc` for the helper call only; it is not process RSS. JSON sizes include the API-shaped wrapper and, for top-IP results, basis metadata.

| Event rows | Operation | Time | Rows returned | JSON bytes | Traced Python peak |
|---:|---|---:|---:|---:|---:|
| 100,000 | Exact source hit | 0.002306 s | 1 | 22 | 1,522 B |
| 100,000 | Exact source miss | 0.002740 s | 0 | 13 | 1,690 B |
| 100,000 | Recent top 5 | 0.014603 s | 5 | 312 | 3,517 B |
| 100,000 | Recent top 100 | 0.012307 s | 100 | 4,864 | 37,929 B |
| 1,000,000 | Exact source hit | 0.003457 s | 1 | 22 | 1,866 B |
| 1,000,000 | Exact source miss | 0.002972 s | 0 | 13 | 1,490 B |
| 1,000,000 | Recent top 5 | 0.016341 s | 5 | 317 | 3,970 B |
| 1,000,000 | Recent top 100 | 0.014506 s | 100 | 4,877 | 28,398 B |

These timings are observations, not a latency SLA or a claim that all dashboard queries are constant-time. The top aggregation input is structurally capped at 10,000 rows independent of table cardinality; exact lookup output is structurally capped at one row.

### Sample and edge cases

- A disposable proof changed a source value only on a row older than the newest 10,000. The recent top-IP result remained unchanged.
- Inserting a new event rotated the sample; the oldest formerly sampled event dropped out and sample-local counts changed accordingly.
- Existing database tests cover sample boundary/rotation, tie ordering, limits 1 and 100, small/empty databases, exact lookup hit/miss, and report all-history behavior.
- An additional close-out check confirmed an empty overview returns `top_ips: []`, `total_events: 0`, and valid latest-events basis metadata.
- Source response cardinality and dashboard top-IP rendering are bounded independently of historical distinct-source count. The frontend contains no data-driven source option list; the top list is limited to five by `/overview`.

### Test and tooling results

- Focused database filters, recent top-IP aggregation, overview, and migration/schema tests: **22 passed**.
- Database export tests: **2 passed**.
- Frontend Node test suite: **17 passed**.
- Frontend production build: **passed**; Vite emitted its existing large-chunk warning.
- Frontend lint: **passed**.
- `python -m py_compile database/db.py api/main.py`: **passed**. Importing `report.py` and the database helpers: **passed**.
- `git diff --check`: **passed**.

HTTP route suites were not verified in this environment. `api.main` import and route test collection fail because `reportlab` is unavailable, although `requirements.txt` declares `reportlab==5.0.1`. The known TestClient/AnyIO pre-router stall is a separate limitation; no HTTP integration PASS is claimed. Route behavior was reviewed in source and covered by direct database and frontend helper tests, but HTTP middleware/status mapping was not exercised here.

## Scope and remaining limitations

The Phase 34 change is limited to source lookup, recurring top-IP summaries, and the dashboard's source filter. Event totals and event pagination remain as before: `/events` still performs its existing exact count and offset pagination, and deep offsets are not addressed here. Historical device-list scaling and inventory/history retention are also separate concerns. `report.py` intentionally retains all-history top-IP ranking for manual report generation. The direct filter requires the operator to know or type an address; autocomplete was intentionally not added.

The Node tests exercise pure filter/query/guard logic, not a mounted React component. Actual browser clicks, Enter dispatch, timer polling, rendered accessibility behavior, focus, and responsive visual layout were not directly tested. Measurements do not establish a hard transaction or query latency guarantee. No claim is made that all dashboard history queries are bounded.

Schema remains **46**. No migration, index, table, or column was added. Phase 34 did not modify Phase 23 export safety, Phase 25 retention behavior, or Phase 32 inventory/task atomicity; no regression evidence requiring those phases to reopen was found.
