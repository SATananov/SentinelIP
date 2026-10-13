# Perimeter Monitoring 11B — Router / Firewall Log Ingestion

11B adds the trusted ingestion boundary that maps authorized router, firewall, and gateway evidence into the normalized `PerimeterEvent` model introduced in 11A.

It still does **not** claim that an event is an attack. Detection begins in 11C.

## Evidence path

```text
authorized router / firewall / gateway log source
        ↓
trusted local adapter
        ↓
normalized bounded perimeter observation
        ↓
Remote Sensor with LOG_COLLECTION
        ↓  10C authenticated machine transport
POST /sensor/perimeter-events
        ↓
server derives Site + Sensor identity
        ↓
atomic PerimeterEvent persistence
        ↓
GET /perimeter-events review API
        ↓
11C deterministic inbound-attempt detection
```

## Machine ingestion API

`POST /sensor/perimeter-events` accepts a batch of 1–32 normalized events. It is a machine endpoint and therefore inherits the existing sensor transport controls:

- machine credential + sensor UUID;
- timestamp freshness and nonce replay protection;
- HTTPS for non-loopback peers;
- per-sensor transport rate limiting;
- the existing 16 KiB machine-request body limit;
- disabled/revoked sensors and disabled Sites fail closed.

The authenticated sensor must currently declare `LOG_COLLECTION`.

The request body cannot supply `site_id` or `sensor_id`. Core derives both from the authenticated machine identity. The endpoint accepts only `FIREWALL`, `ROUTER`, and `GATEWAY` source types. Arbitrary commands, scan targets, files, packet captures, and raw log blobs are not accepted.

## Atomicity and idempotency

A batch is persisted inside one SQLite write transaction. Exact replay remains idempotent by the 11A identity:

```text
(site_id, source_key, external_event_id)
```

If any item reuses an identity with different evidence, violates a foreign key, or otherwise conflicts, the complete batch is rolled back. A retry therefore cannot leave a half-accepted batch.

## Raw evidence handling

11B does not store unrestricted raw log text. A trusted adapter can provide the optional SHA-256 `raw_event_hash` and bounded non-sensitive metadata. Secret-like metadata remains rejected by the 11A model.

This preserves the factual evidence needed for review without turning SentinelIP into an unbounded log archive.

## Adapter contract

`services/perimeter_ingestion.py` provides a site-neutral `PerimeterObservation` contract and a first bounded adapter for Linux netfilter-style key/value records.

`NetfilterKeyValueAdapter` extracts only factual network fields such as:

- `SRC` / `DST`;
- `PROTO`;
- `SPT` / `DPT`;
- `IN` / `OUT` interface names.

Direction and policy action are **not guessed from text**. They are fixed adapter configuration associated with the known log stream or firewall rule. The adapter hashes the raw line rather than placing the line in the transmitted event.

The first adapter is intentionally narrow. It is not a universal router/firewall parser and does not claim compatibility with vendor formats that have not been explicitly implemented and tested.

## Sensor capability

The sensor configuration and enrollment CLI now recognize `LOG_COLLECTION` in addition to discovery capabilities. The default enrollment capabilities remain host and service discovery so existing installs do not silently gain a new capability.

A sensor that has only `LOG_COLLECTION` does not require Nmap. Nmap remains required when `HOST_DISCOVERY` or `SERVICE_DISCOVERY` is enabled.

The shared `CoreClient.submit_perimeter_events()` method exposes only the fixed normalized batch endpoint; it does not add a generic arbitrary-path transport method.

## Current boundaries

11B deliberately does not add:

- an unauthenticated Internet-facing syslog listener;
- arbitrary UDP/TCP socket listeners;
- automatic router credential use;
- SNMP credential collection;
- packet capture;
- vendor-specific parsers not backed by test fixtures;
- attack/threat/incident conclusions;
- firewall changes or automated blocking;
- public-target scanning.

A future collector can wire an explicitly supported vendor/syslog source to the adapter contract and submit normalized observations through the authenticated sensor path without changing the 11A evidence schema.

## Next phase

11C can consume these factual events to identify deterministic **inbound attempt** patterns while preserving the distinction between `BLOCK`, `REJECT`, and `ALLOW` evidence.
