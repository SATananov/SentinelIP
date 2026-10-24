# Phase 27: SSH detector and ingestion resource contract

## Purpose and evidence

Phase 27 addresses demonstrated resource-growth paths in the legacy SSH event
pipeline. The Phase 27A audit found that detector timestamps were pruned only
when their source returned, leaving stale source keys in memory. Synthetic
tracemalloc measurements reported about 8.3 MB for 10,000 unique preauth
sources, 85.3 MB for 100,000 unique sources, and 4.8 MB for 100,000 timestamps
on one source. These are local Python measurements, not production capacity
claims.

The operator decision in Phase 27B kept `event_count` exact and prohibited
saturating counts, capping active per-source history, or evicting active
sources. Phase 27C then changed only the detector's elapsed-time basis and
global stale-state reclamation. Phase 27D set explicit product limits of
8,192 raw line bytes and 256 UTF-8 username bytes. Phase 27E implemented those
limits at the raw reader, live application, and persistence boundaries.

## Detector clock and exact count semantics

Live persistence timestamps remain server-local wall-clock values. `app.py`
uses `datetime.now()` and persists ordinary event timestamps with
`isoformat(timespec="seconds")`. These values remain the source for event
history and stored evidence.

`SSHDetector` uses `time.monotonic()` by default for in-memory rolling expiry.
Tests and historical replay can inject a deterministic clock. Monotonic values
are process-local and are never persisted. Wall-clock rollback or forward
adjustment therefore does not change live rolling membership. Detector state
resets on process restart; it is not restored from the database.

The live detector window is 60 elapsed seconds. An event remains in the
window while its elapsed age is at most 60 seconds; it expires only when older
than 60 seconds. For rolling count thresholds, 1–2 are `INFO`, 3–4 are
`WARNING`, and 5+ are `ALERT`; counts above the threshold remain exact.
Existing suspicious-username behavior remains unchanged, and messages and
result shape are unchanged. The live app continues not to pass usernames into
the detector.

Historical threat replay sorts evidence by stored timestamp and evidence ID,
then maps timestamp differences from the earliest selected row to elapsed
seconds for a deterministic detector instance. Equal timestamps remain
equal, sub-second precision is preserved when present in stored evidence, and
the inclusive 60-second boundary and threshold sequence remain equivalent to
the previous timestamp-based replay for ordered evidence.

## Stale-state reclamation and active-state limitation

The detector maintains separate count maps for failed logins and preauth
events, plus a global chronological expiry deque with one record per rolling
event. On each detector analysis it expires records whose monotonic age is
greater than 60 seconds. Each record decrements exactly one source and event
class. A source key is removed when its count reaches zero. When a class map
becomes empty, it is cleared in place so its existing object identity is
preserved and its large dictionary table can be released. Later events reuse
that same map object. Cleanup does not require the expired source to return;
any subsequent detector analysis can reclaim stale records. No background
task is used.

Phase 27 does **not** impose a hard active-memory bound. Unique active source
cardinality and event volume within the 60-second window remain unbounded.
Exact counts and expiry require retaining information for active events. No
active source is evicted, there is no source-count cap, and there is no
memory-budget overflow behavior. If no detector events arrive, event-driven
cleanup does not run.

Local synthetic cleanup runs reported approximately 5.3 ms for 10,000 stale
records and 50 ms for 100,000 stale records; earlier local runs varied (about
2.5 ms and 63.8 ms, respectively). Work is proportional to the records
expiring on that call, so a large backlog can cause a cleanup spike. These
measurements are local observations only; no hard latency bound is claimed.

## Raw SSH line bound and decoding

`MAX_SSH_LOG_LINE_BYTES` is 8,192. The cap is measured on raw subprocess
stdout bytes before decoding and includes the logical line terminator. LF,
CRLF, lone CR, and an unterminated final line at EOF are recognized. For
example, 8,191 content bytes plus LF fit; 8,192 plus LF do not. CRLF counts as
two bytes. An unterminated final line of exactly 8,192 bytes fits; 8,193 does
not. No input is truncated and parsed as partial evidence.

SSH stdout is binary with `bufsize=0`. The production reader requests at most
1,024 bytes per read. Its candidate bytearray never exceeds 8,192 bytes. On
overflow it clears the candidate and discards through the logical
terminator, then resumes with following bytes from the same chunk or later
reads. No part of an oversized line is decoded or yielded.

Reader-local raw input is bounded by the 8,192-byte candidate, at most a
1,024-byte read chunk and segment, and a decoder staging copy no larger than
the line cap. Accepted decoded text and parser values are also limited by the
line cap, though Python string representation and transient copies add
constant-factor memory. This is an input-path bound, not a whole-process
memory bound. A local synthetic stream generated a 16 MiB oversized line in
1,024-byte chunks, observed an 8,192-byte candidate maximum, recovered the
following valid line, and reported about 11.9 KiB peak `tracemalloc` allocation.
This is local evidence only, not a portable memory guarantee.

Accepted lines use the effective platform-default encoding used by the
previous subprocess text mode: UTF-8 mode selects UTF-8; otherwise the active
locale encoding is used. Decoding is strict. Invalid bytes reject the whole
line, are not replacement-decoded or surrogate-escaped, and do not reach the
parser. Monitoring continues with the next logical line. Universal newline
normalization is preserved for LF, CRLF, and lone CR, including CRLF split
across reads. The previous trailing-whitespace `rstrip()` behavior is also
preserved.

## Username and rejection contract

`MAX_SSH_USERNAME_BYTES` is 256, measured as
`len(username.encode("utf-8"))`. A value of exactly 256 bytes is accepted;
larger values are rejected without truncation or normalization. `None`
remains valid, and an IP-shaped username remains ordinary username content.

The live pipeline is:

```text
raw bytes → line bound → strict decode → Phase 26 parser
          → username bound → detector → persistence
```

An oversized line is rejected before decode, parsing, detector analysis, or
database work. A decoding failure is rejected before parsing. An oversized
username may have produced an `SSHEvent`, but is rejected before detector
analysis and persistence. Expected rejection does not stop monitoring.

The same username validator runs in `save_event()` before a connection is
opened, providing defense in depth for direct callers. It raises a fixed
`SSHUsernameValidationError` with no username content. There is no database
`CHECK` constraint or schema migration.

The operator reporter has three fixed categories: oversized raw line,
invalid encoding, and oversized username. It emits at most one warning per
category per reporter, keeps cumulative integer counters without
per-source/payload keys, and includes no attacker content. The app reports
totals in its `finally` block; a standalone stream reports totals when its
generator finalizes. Abrupt process termination does not guarantee a summary.

## Compatibility and remaining limits

The Phase 26 parser contract is unchanged. In particular,
`Failed password for invalid user 192.0.2.99 from 203.0.113.7 port 55555
ssh2` keeps `192.0.2.99` as the username and `203.0.113.7` as the source used
for detector grouping and persistence. No IPv6 support was added.

Phase 25 retention is unchanged: legacy raw SSH events become eligible after
90 days only when unreferenced and classifiable, cleanup remains manual, and
each apply deletes at most 100 rows. Referenced, malformed, and future rows
remain protected/skipped under that policy.

Phase 27 bounds the raw bytes retained for one input line, persisted
attacker-controlled username length, and lifetime of stale rolling detector
state while events continue. It does **not** bound valid event arrival rate,
total valid event count, same-day database growth, total database file size,
active detector state within 60 seconds, total process memory, or query/output
cost. It does not provide a general denial-of-service guarantee.

The switch to binary Popen mode also makes stderr a binary stream; stderr
remains unused. Phase 27 did not add stderr draining, child wait/reap,
reconnect, keepalive, termination sequencing, or EOF restart behavior. No
claim of subprocess lifecycle reliability is made. The authoritative
TestClient/AnyIO pre-router environment issue was not used for Phase 27
acceptance.

Schema remains version 45. No migration, index, or column-type change was
added. Event rate limiting, hard active-memory limits, hard database-size
limits, SSH subprocess lifecycle work, IPv6, and history-query redesign remain
out of scope.

## Phase 27F verification

Focused final verification on the close-out checkout:

- detector and threat replay: 48 passed
- reader, username, and Phase 26 parser/integration: 76 passed
- threat pipeline: 34 passed
- persistence and exports: 46 passed
- Phase 25 lifecycle and management audit regressions: 44 passed
- Python compile/import checks and `git diff --check`: passed

These disjoint focused groups total 248 passed tests. The authoritative
backend suite was not run for Phase 27F; the known TestClient/AnyIO stall
remains an environment limitation and is not reported as a pass.
