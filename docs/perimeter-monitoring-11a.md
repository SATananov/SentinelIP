# Perimeter Monitoring 11A — Perimeter Event Model

11A introduces the normalized **factual evidence layer** for perimeter activity. It does not claim that an event is an attack and it does not add router/firewall collectors yet. Adapter-specific ingestion belongs to 11B; deterministic inbound-attempt detection belongs to 11C.

## Evidence flow

```text
router / firewall / gateway evidence
        ↓  (11B adapters, future)
normalized PerimeterEvent
        ↓
perimeter_events
        ↓
read-only review API
        ↓
11C+ deterministic detection/correlation
```

## Normalized fields

Each event is site-scoped and records:

- source provenance: `source_type`, `source_key`, optional `sensor_id`, optional `source_reference`;
- identity/idempotency: `external_event_id` unique per site/source;
- observation: `observed_at`, `event_type`, `direction`, `action`, `protocol`;
- network facts: source/destination IP and bounded ports;
- optional interface, SHA-256 raw-event digest, and bounded non-sensitive metadata;
- server receipt timestamp.

Supported directions are `INBOUND`, `OUTBOUND`, `LATERAL`, and `UNKNOWN`. Supported policy actions are `ALLOW`, `BLOCK`, `REJECT`, and `UNKNOWN`. These are observations from perimeter evidence, not security conclusions.

## Safety and data boundaries

11A deliberately does **not** provide a public write/ingestion route. `persist_perimeter_event()` is an internal persistence boundary for later trusted adapters. The public API is read-only:

- `GET /perimeter-events`
- `GET /perimeter-events/{id}`

The model rejects secret-like metadata keys, bounds metadata size, requires canonical IP addresses, validates TCP/UDP ports, and stores only an optional SHA-256 digest of raw evidence rather than an unrestricted raw log blob.

A perimeter event must belong to a persisted Site. If it is attributed to a remote sensor, the database enforces that the sensor belongs to the same Site. This keeps overlapping private networks at separate sites distinguishable for later correlation.

## Idempotency

`(site_id, source_key, external_event_id)` is the stable external identity. Exact replay is idempotent. Reusing that identity with changed evidence is rejected rather than overwriting history.

## What 11A does not do

- no syslog listener;
- no router/firewall vendor parser;
- no claim that blocked traffic is an attack;
- no threat/correlation/incident generation;
- no remediation or firewall changes;
- no raw packet capture;
- no public-target scanning.

The next phase, 11B, can map authorized router/firewall logs into this model without changing the core evidence semantics.

## Follow-up

11B now provides the authenticated Remote Sensor ingestion boundary and the first bounded adapter contract described above; see `docs/perimeter-monitoring-11b.md`.
