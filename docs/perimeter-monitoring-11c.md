# Perimeter Monitoring 11C — Deterministic Inbound Attempt Detection

11C turns persisted inbound perimeter evidence into bounded **review signals**. It does not label an event as an attack, intrusion, or compromise.

## Rules

Only persisted `INBOUND` events whose type is `CONNECTION_ATTEMPT` or `POLICY_DECISION` are eligible.

For each eligible primary event, SentinelIP compares only events from the same Site with the same source IP, destination IP, destination port, protocol, and policy action inside an inclusive five-minute window.

- fewer than 5 matching events → `INBOUND_ATTEMPT`;
- 5 or more matching events → `REPEATED_INBOUND_ATTEMPTS`.

`ALLOW`, `BLOCK`, `REJECT`, and `UNKNOWN` remain distinct evidence. 11C deliberately does not collapse them into a generic threat state. 11D adds a separate deterministic allowed-vs-blocked correlation model while preserving the original action evidence.

## Identity and replay

Each detection is anchored to its primary persisted perimeter event and rule version. Exact ingestion replay re-evaluates the same evidence and resolves to the same stable detection key. Conflicting evidence cannot overwrite an existing detection.

## API

Review is read-only:

- `GET /perimeter-detections`
- `GET /perimeter-detections/{id}`

Supported list filters include Site, detection type, action, protocol, source IP, destination IP, and destination port.

The machine ingestion response may include IDs of deterministic detections produced from the accepted event batch.

## Boundaries

11C adds no packet capture, active scanning, blocking, firewall changes, reputation lookup, geolocation, exploit claims, or compromise claims. It also does not create incidents. A detection means only that the normalized perimeter evidence matched a documented deterministic rule and deserves review.
