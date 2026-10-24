# Phase 28: SSH collector lifecycle and session liveness

## Purpose and Phase 28A findings

Phase 28 addresses local SSH child lifecycle and established-session
liveness. The Phase 28A audit found that the SSH child wrote to an undrained
stderr pipe, cleanup did not establish a consistent wait/reap and stdout-close
contract, stream end status was not clearly surfaced, and the app relied on
generator finalization timing when its consumer stopped early.

Phase 28 does not make SSH monitoring fully reliable, guarantee that events
cannot be missed, prevent every possible child leak under OS-level failure, or
recover network failures automatically.

## Process configuration

`stream_ssh_logs()` starts one local child with an argument array equivalent to:

```text
ssh -i <key> -o BatchMode=yes -o ConnectTimeout=5 \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 <user>@<host> \
  journalctl -u ssh -f -n 0 --no-pager
```

`subprocess.Popen` uses `stdout=PIPE`, `stderr=DEVNULL`, and `bufsize=0`.
Text mode is off, so stdout is binary. No `shell=True`, custom stdin, custom
environment, new session, or process group is requested; stdin and environment
retain subprocess defaults. Host-key verification settings and key selection
behavior remain unchanged. `TCPKeepAlive` is not overridden.

Using `DEVNULL` means there is no unread local stderr pipe that can fill and
block the child. SSH stderr diagnostics are discarded, however, so the exit
status cannot reliably distinguish authentication, host-key, DNS, network, or
remote-command causes. Status messages do not include stderr or secrets.

## Ownership and cleanup

`stream_ssh_logs()` owns the SSH child: it terminates, escalates to kill when
needed, waits/reaps, and closes the owned stdout pipe. `app.py` owns the
iterator lifetime and event consumption; it explicitly closes the iterator
from `finally` and does not terminate or wait on the process directly.

On local generator shutdown while the child is running, cleanup calls
`terminate()`, waits up to 2.0 seconds, then calls `kill()` if the wait times
out and waits up to 2.0 additional seconds. It attempts a final wait in the
already-exited race. Stdout is closed after the cleanup attempt, including on
consumer exceptions and Ctrl+C. A kill followed by a final wait timeout emits
`SSH log collector cleanup failed; child exit could not be confirmed.` and
does not claim that the child was reaped. There is no endless cleanup loop.

On ordinary lifecycle paths, the child is deterministically reaped. A final
OS-level kill/wait failure remains an exceptional residual risk. Lifecycle
cleanup and pipe closure run before lifecycle or rejection-summary printing,
so a reporting failure does not skip those cleanup steps.

When stdout reaches EOF and the child has already exited, its status is
observed and waited, without an unnecessary terminate/kill. Exit code zero
prints `SSH log stream ended.` A nonzero status prints
`SSH log collector exited unexpectedly (code N).` If an EOF status is
unavailable, the fixed message is `SSH log collector exited unexpectedly.`
The one-session stream then ends; no child is started again. Local iterator
closure does not report its resulting signal status as an unexpected remote
failure.

## Session and liveness policy

SentinelIP uses one SSH session per monitor invocation. There is no reconnect
loop, retry/backoff, journal catch-up, cursor replay, SSH monitor service
manager contract, or daemon behavior. After the stream ends, the app ends and
the operator can restart it manually.

`ConnectTimeout=5` covers connection establishment and the initial SSH
handshake. `ServerAliveInterval=15` and `ServerAliveCountMax=3` apply to
responsiveness after establishment by sending encrypted SSH-level probes.
They are SentinelIP policy values; their failure-detection window is
approximately 15 × 3, or 45 seconds, not a hard timing guarantee. These probes
are independent of sshd log output. A quiet stream is valid and there is no
application-level stdout idle timeout.

The remote command remains `journalctl -u ssh -f -n 0 --no-pager`: it follows
new entries without requesting historical entries at startup. Events during
a disconnect may be missed. Keepalive can shorten detection of an
unresponsive session, but it does not replay logs, recover missed events,
guarantee continuous monitoring, or eliminate evidence gaps.

## Compatibility and remaining risks

Phase 28 does not change Phase 27 bounded stdout behavior: binary reads remain
at most 1,024 bytes, raw lines remain capped at 8,192 bytes including their
terminator, LF/CRLF/lone-CR framing remains supported, decoding remains strict,
and the 256-byte UTF-8 username bound and rejection reporting remain in place.
Phase 26 source attribution is unchanged; the IP-shaped username regression
continues to preserve `192.0.2.99` as username and `203.0.113.7` as source.
Detector semantics, persistence timestamps, schema, and database behavior are
unchanged. Schema remains version 45; no migration or index was added.

Remaining limitations:

- There is no automatic reconnect; the operator must restart after stream end.
- There is no journal catch-up or cursor replay; disconnects can leave evidence
  gaps.
- SSH stderr diagnostics are discarded, limiting failure-cause classification.
- The final kill wait can theoretically fail at the OS/process boundary.
- Keepalive timing is approximate and does not guarantee gap-free monitoring.
- Remote `journalctl` availability, permissions, and configuration remain
  external requirements.
- No SSH monitor service-manager supervision contract exists in the repository.
- IPv6 SSH source parsing remains unsupported.
- The known TestClient/AnyIO pre-router environment issue is separate from
  collector lifecycle verification.

Phase 28 improves stderr backpressure handling, ordinary child cleanup and
reaping, pipe closure, end-state visibility, iterator finalization, and
established-session failure detection. It does not promise automatic network
recovery or continuous evidence capture.
