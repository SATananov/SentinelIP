# Incident Review Search 22B — Bounded Search API

`GET /incident-reviews/search` provides bounded historical discovery of Incident Reviews from title terms. It is a separate endpoint from the existing review list and operations queue.

## Search contract

The required `title` parameter is limited to 160 input characters and tokenized using Unicode letter, number, and mark characters. Leading/trailing whitespace is trimmed, internal whitespace is collapsed, and punctuation separates tokens. The query must contain at least three searchable characters overall, with at least two characters per token. Each token is a prefix term; multiple terms are combined with AND semantics. Matching is case-insensitive according to SQLite FTS5 `unicode61`. Interior substrings, fuzzy matching, typo correction, and relevance ranking are not supported.

The FTS index contains titles only. Summaries, final summaries, analyst notes, note rows, evidence, and timeline entries are excluded. The query is converted to quoted FTS terms by the database layer; caller input is never passed through as raw FTS syntax.

Optional filters are `state`, `priority`, `disposition`, `site_id`, `scope_id`, `device_id`, `created_from`, `created_until`, `closed_from`, and `closed_until`. All supplied filters combine with AND. Timestamps require an explicit ISO-8601 timezone, are normalized to UTC, and use inclusive start / exclusive end bounds. A range with both ends may not exceed 366 days. Supplying either closed bound excludes reviews with a null `closed_at`.

Results use a fixed candidate projection: ID, incident key, title, state, priority, confidence, disposition, site/scope/device IDs, and created/updated/closed timestamps. The endpoint does not return summaries, notes, evidence, or timeline content. Results sort by `updated_at DESC, id DESC`; pagination defaults to 20, allows at most 100, and caps offset at 100,000. It reads one extra row for `has_more`, without a total-count query.

## Storage and access

Schema migration 45 creates an external-content FTS5 table over `incident_reviews.title`, keyed by review ID. Insert, title-update, and delete triggers keep the index synchronized. The migration rebuilds the index from existing reviews so historical titles are searchable immediately. FTS5 creation failures fail migration; there is no LIKE-scan fallback.

The route uses the existing `local_management` dependency and inherits its direct-local operator boundary and `Cache-Control: no-store` behavior. Search is read-only and creates no management audit or review timeline events. Existing list, operations, exact ID/key lookup, detail, evidence, and reports remain unchanged.

## Non-goals

This endpoint does not search summary, final summary, notes, evidence, or timeline; provide full-text case search; expose remote operator search; accept arbitrary FTS syntax, regex, or wildcard queries; or implement fuzzy/semantic search. Frontend search controls are deferred to 22C.
