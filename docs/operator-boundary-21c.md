# Operator Boundary 21C — Analyst and Sensitive Reads

Phase 21C applies the existing `local_management` dependency to the analyst plane and other sensitive operator reads. It enforces the direct-local boundary from the Phase 21 contract; it does not add human identity or authentication.

## Protected route families

- Incident Review list, detail, creation, update/close/reopen, notes, evidence, timeline, related evidence, and JSON/HTML reports.
- Incident Review operations, activity, trends, and site/scope/device workload.
- Investigation lookup (already protected) and sensitive device/network inventory: network device listings, device detail, ports, services, findings, and CVE matches.
- Legacy overview, events, source IPs, alerts, statistics, and JSON/CSV/PDF event exports. This change only adds the access boundary; export size, buffering, PDF escaping, CSV formula handling, and cache behavior remain separate maintenance items.
- Threats and correlations, perimeter events/detections/correlations/dashboard, external exposures and observations, assessments, changes, classifications and dashboard, web detections, and legacy incidents.
- `GET /network-candidates`, which exposes passive local-network candidate information and is treated as operator-sensitive.

Control-plane routes protected in 21B and existing fleet, lifecycle, and management-audit guards remain as they were. `GET /health` remains outside the boundary and its response remains minimal.

## Sensor routes

Sensor enrollment, sensor identity/grant/heartbeat, perimeter-event ingestion, task claim/start/fail/result, and web/DNS telemetry retain their existing machine authentication and grant checks. They do not use `local_management`, so remote sensors remain compatible with the sensor-enabled Core topology. No sensor protocol or telemetry behavior changes here.

## Locality behavior

The routes reuse the existing `local_management` dependency without changing its peer, Host, Origin, or forbidden-header checks. Successful local reads inherit its `Cache-Control: no-store` behavior. Historical tests modeling a local operator use `tests/local_operator_client.py`; boundary-denial tests explicitly vary peer, Host, Origin, or headers. Production code does not allow `testserver` or synthetic non-loopback peers.

The current local frontend origins remain `http://127.0.0.1:5173` and `http://localhost:5173`, calling the loopback API at `http://127.0.0.1:8000`. Frontend files, CORS, TLS setup, proxy support, and remote human administration are unchanged and remain outside this subphase.

## Review and audit semantics

Incident Review `OPERATOR` source values remain a generic source class and do not identify a person. This work adds no management-audit events for reads or Incident Review mutations, and does not change review timeline semantics. Legacy and inventory reads remain read-only.

## Schema and next step

No migration is added; schema version remains 44. Phase 21D is expected to close deployment documentation/configuration and route-boundary regression coverage, including the sensor exception model and the absence of human identity and trusted-proxy support.
