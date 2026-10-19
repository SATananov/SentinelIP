# Phase 21B: Control-Plane Operator Boundary

Phase 21B applies the existing `local_management` dependency to network and
scope configuration, explicit target-authorization workflows, operator discovery
triggers, and external-exposure policy configuration. It does not protect the
analyst/read plane; Incident Review, general findings, threat/perimeter reads,
legacy exports, and exposure history remain for 21C.

## Protected route families

- Network list/detail, create, update, and delete: `/networks` and
  `/networks/{network_id}`.
- Network discovery: `POST /networks/{network_id}/discover`.
- Scope configuration reads: `GET /scopes`, `GET /scopes/{scope_id}`, and
  `GET /scopes/{scope_id}/devices`.
- Public target configuration and preview: `POST /scopes/public-ipv4`,
  `/scopes/public-cidr`, `/scopes/public-cidr/preview`, `/scopes/hostname`,
  `/scopes/hostname/preview`, and
  `/scopes/{scope_id}/hostname/reauthorize`.
- Scope discovery: `POST /scopes/{scope_id}/discover` and
  `/scopes/{scope_id}/devices/{device_id}/discover-services`.
- Device service-discovery trigger: `POST /devices/{device_id}/discover-services`.
- Exposure policy configuration: GET, PUT, and DELETE on
  `/scopes/{scope_id}/external-exposure-policy`.

Other analyst reads, including `GET /networks/{network_id}/devices`, are not
included in this subphase.

## Boundary and behavior

Routes reuse `local_management` from `api.remote_sensors`; its semantics were not
changed. It requires a loopback peer and loopback URL hostname, allows absent
Origin or the two configured local Vite origins, rejects Authorization and
sensor identity headers, rejects `Forwarded`, `X-Forwarded-For`, and
`X-Forwarded-Host`, and sets `Cache-Control: no-store` on successful responses.
This is a direct-local boundary, not human authentication. Local CLI requests
without Origin continue to work when Host and peer are loopback.

Route guards do not alter target authorization, scan bounds, scanner behavior,
scope validation, policy semantics, or response data. Target authorization
continues to constrain what SentinelIP may assess; it does not authenticate the
caller. Read requests do not create management-audit events.

## Audit actors

New management-audit events emitted by guarded network, scope-authorization,
and exposure-policy mutation routes use `LOCAL_OPERATOR`. Direct domain/database
callers retain the `API_CLIENT` default for compatibility. The actor vocabulary
is unchanged, and historical `API_CLIENT` events are neither rewritten nor
invalidated. Event types, entity types, and the fixed before/after exposure port
arrays remain unchanged.

## Sensor and deployment boundaries

Sensor routes remain outside `local_management`: enrollment registration, sensor
self/grant/heartbeat, perimeter ingestion, task claim/start/fail/result, and
browser/DNS telemetry retain their existing transport and credential checks.
No sensor authentication, task, telemetry, or target-grant behavior changed.

This phase does not enable sensor-facing network deployment. There is no TLS
configuration, proxy support, trusted-proxy mode, or frontend API-base change.
There is no remote human administration or human identity model. Local
development remains the documented loopback HTTP setup. Sensor-enabled Core
deployment requires the later Phase 21 deployment closure.

## Compatibility and schema

Non-loopback ordinary clients can no longer call the protected control-plane
routes; this is intentional. The documented local frontend origins and local
CLI access remain compatible. CORS was not changed. Schema remains version 44;
there is no migration 45. `API_CLIENT` remains a valid actor for historical
rows and other compatible direct API mutation paths.

## 21C expectations

21C will apply the direct-local boundary to the analyst/read plane, including
Incident Review, reports, investigation and sensitive inventory/detection
reads, while retaining the sensor protocol exceptions and the same local
operator semantics.
