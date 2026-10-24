# Phase 26: SSH Source Attribution

## Purpose and original defect

The legacy SSH parser previously searched the complete log line for the first
IPv4-shaped token before identifying the event form. A remote SSH client could
therefore use an address-shaped login name to make SentinelIP attribute the
event to that name. For example:

```text
Failed password for invalid user 192.0.2.99 from 203.0.113.7 port 55555 ssh2
```

could be attributed to `192.0.2.99` instead of the actual address in the
`from` field, `203.0.113.7`.

The parser now first matches a supported log form and reads the address only
from that form's source field. This corrects attribution for those supported
forms. It does not authenticate network-layer source addresses or prevent
general source spoofing.

## Supported parser contract

`collectors/ssh_logs.py` accepts these forms, including the repository's
syslog-style prefixes:

| Log form | Event type | Username | Source field |
| --- | --- | --- | --- |
| `Accepted password for <user> from <IPv4> port <port> ...` | `LOGIN_SUCCESS` | Required; exact non-whitespace token | Token after `from` |
| `Accepted publickey for <user> from <IPv4> port <port> ...` | `LOGIN_SUCCESS` | Required; exact non-whitespace token | Token after `from` |
| `Failed password for <user> from <IPv4> port <port> ...` | `LOGIN_FAILED` | Required; exact non-whitespace token | Token after `from` |
| `Failed password for invalid user <user> from <IPv4> port <port> ...` | `LOGIN_FAILED` | Required; exact non-whitespace token | Token after `from` |
| `Unable to negotiate with <IPv4> port <port>: ... [preauth]` | `SSH_PREAUTH` | `None` | Token after `with` |
| `Connection closed by <IPv4> port <port> ...` | `CONNECTION_CLOSED` | `None` | Token after `by` |

Ports are structural only: they must be decimal integers in `1..65535`, but
are not included in `SSHEvent` or persisted. Extra text after a valid port is
accepted. Login usernames are independent of source parsing; IP-shaped and
dotted usernames remain ordinary username tokens and are not normalized.

The parser validates captured source tokens with `ipaddress.IPv4Address` and
stores the canonical IPv4 string. Invalid octets, malformed tokens, IPv6
literals, and IPv4-mapped IPv6 literals are rejected. IPv6 source support is
not part of this contract and would require a separate explicit product
decision.

The generic rule “any line containing `[preauth]` and an IP” has been removed.
Only the fixture-backed `Unable to negotiate ... [preauth]` grammar is
accepted as `SSH_PREAUTH`. A connection-closed form remains
`CONNECTION_CLOSED`, even when its accepted suffix contains `[preauth]`.

Unsupported or malformed lines return `None`; they do not produce partially
trusted events or use another address-looking token as a fallback. This
includes missing source markers/tokens, invalid addresses or ports, missing
login usernames, unsupported authentication methods, standalone `Invalid
user` lines, unrelated lines, and IPv6 source lines. `SSHEvent` retains its
existing fields: `event_type`, `source_ip`, `username`, and `raw_line`.

## Downstream behavior and historical data

The application continues to skip a line when parsing returns `None`, so the
line causes no detector update or event insert. For a parsed line,
`event.source_ip` continues to be passed to `SSHDetector` and persisted as the
event's `source_ip`; username persistence and detector behavior are otherwise
unchanged. The integration regression confirms that the example above keeps
`192.0.2.99` as the username while grouping and persisting under
`203.0.113.7`.

Existing events are not rewritten. Raw source log lines are not stored with
legacy events, and a stored IP-shaped username alone cannot prove which rows
were misattributed. No heuristic repair, cleanup script, schema migration, or
index was added. The database schema remains version 45.

## Verification and scope

Phase 26C close-out verification on the current checkout ran:

- SSH parser tests: 43 passed
- parser/detector/persistence integration tests: 2 passed
- detector, threat-engine, and threat-rule regressions: 48 passed
- Python compile/import checks: passed
- `git diff --check`: passed

The parser-focused tests do not require the known TestClient/AnyIO environment
that stalls before router entry; the authoritative backend suite was not run
for this parser-focused close-out. Phase 26 changes do not claim IPv6 support,
SSH line-size bounds, username-size bounds, detector-state bounds, event-rate
limits, or subprocess reliability.

Explicitly out of scope are SSH collector subprocess lifecycle and stderr
handling, child wait/reap and reconnect behavior, raw log-line and username
size bounds, detector source-map bounds, burst/event-rate handling, IPv6
support, and the separate authoritative TestClient reproducibility issue.
