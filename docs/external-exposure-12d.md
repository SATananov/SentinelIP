# External Exposure Change Detection — 12D

SentinelIP 12D adds deterministic change tracking for already authorized public TCP exposure evidence.

## Change types

- `NEW_EXPOSURE` — a new stable open TCP endpoint enters the external exposure inventory after 12D is active.
- `SERVICE_CHANGED` — the normalized service identity changes on the same stable endpoint.
- `FINGERPRINT_CHANGED` — product/version/extra/confidence evidence changes without a service-identity change.
- `EXPOSURE_DISAPPEARED` — a previously present endpoint is absent from a later successful bounded service scan of the same authorized public device.
- `EXPOSURE_REAPPEARED` — a previously absent endpoint is observed open again.

These records are evidence of observed state change only. They do not claim vulnerability, exploitability, intrusion, or compromise.

## Safety and determinism

Change detection consumes the existing normalized authorized service-scan result. It does not add scanner options, arbitrary targets, exploit checks, credentials, brute force, stealth behavior, or Internet-wide discovery. Exact observation replay is idempotent, and an older out-of-order scan cannot mark a newer exposure absent.

Migration 40 creates presence state and change history. Existing 12A–12C exposures are initialized as `PRESENT` without inventing historical `NEW_EXPOSURE` events.

## Read-only API

- `GET /external-exposure-changes`
- `GET /external-exposure-changes/{change_id}`

The list endpoint supports bounded filters for scope, change type, public IPv4, TCP port, and current presence state.
