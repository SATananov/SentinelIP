# Phase 28D: SSH session liveness policy

SentinelIP runs one SSH log session per CLI invocation. When that stream ends,
the collector reaps the local SSH child, closes its stdout, reports the fixed
end state, and the application stops. The operator can start it again
manually. There is no automatic reconnect, retry/backoff, daemon behavior, or
journal catch-up.

The SSH command keeps `ConnectTimeout=5` for connection establishment and the
initial SSH handshake. It also sets:

```text
-o ServerAliveInterval=15
-o ServerAliveCountMax=3
```

These SentinelIP policy values ask OpenSSH to probe an established session
after 15 seconds without server data and to disconnect after three unanswered
probes. The resulting detection window is approximately 45 seconds; it is an
operational estimate, not a protocol timing guarantee. This liveness check is
independent of SSH log output. A quiet log stream alone is never treated as a
failure. `TCPKeepAlive` is not overridden, and host-key verification settings
remain controlled by existing OpenSSH configuration.

If the SSH session ends, Phase 28B cleanup and fixed operator status handling
apply. No new child is started. The remote command remains
`journalctl -u ssh -f -n 0 --no-pager`; a manual restart follows new entries
only. Keepalive can shorten detection of an unresponsive session, but it does
not recover events missed during an interruption, replay logs, guarantee
continuous monitoring, or eliminate evidence gaps.
