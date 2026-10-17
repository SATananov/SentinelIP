# Phase 17B — Bounded Investigation API

## Purpose and boundary

`GET /investigation-lookup` provides exact, typed, read-only lookup across selected existing SentinelIP records. It returns a fixed projection for navigation into existing detail surfaces. It does not mutate records or perform searches over arbitrary fields.

The route reuses `local_management`: loopback client and local host/origin checks, forwarded-header rejection, Authorization and sensor identity/token header rejection, and `Cache-Control: no-store`. This aggregate lookup remains local-operator-only.

## Supported query types

- `IP_ADDRESS`
- `DEVICE_ID`
- `SENSOR_ID`
- `SITE_ID`
- `SCOPE_ID`
- `INCIDENT_REVIEW_ID`
- `INCIDENT_REVIEW_KEY`
- `TASK_ID`
- `EVIDENCE_REFERENCE`

Inputs are exact. Numeric IDs must be positive base-10 integers. Task IDs must be canonical lowercase UUIDs. Review keys must match `IR-` followed by 32 lowercase hexadecimal characters. IP input must be canonical IPv4 dotted decimal. Evidence lookup requires a positive `evidence_id` and a fixed evidence type; it does not accept `value`.

Hostname, IPv6, CIDR, wildcard, regex, partial IP, fuzzy text, and arbitrary table/field lookup are unsupported. Device observations are not searched by historical IP because their existing index is network-first. Remote task targets are not searched by IP because `target_ip` lacks an index.

## Evidence allowlist

Supported evidence references are `PERIMETER_DETECTION`, `PERIMETER_POLICY_CORRELATION`, `PERIMETER_HOST_CORRELATION`, `EXTERNAL_EXPOSURE_CHANGE`, `THREAT_DETECTION`, and `THREAT_CORRELATION`. `WEB_DETECTION` remains unsupported until it has a safe direct detail destination. IDs never select table names dynamically.

## IP source matrix

Exact IP lookup checks current `devices.last_ip_address`, legacy `events.source_ip`, threat and threat-correlation `source_ip`, both source and destination fields for perimeter events, perimeter detections and policy correlations, perimeter-host correlation destination, `external_exposures.target_ip`, exposure changes joined through the exposure target, and exact `PUBLIC_IPV4` scope targets. It does not search arbitrary text or infer review/device/site relationships from IP coincidence.

## Response contract

The top-level response is:

```json
{"query_type":"IP_ADDRESS","items":[],"truncated":false}
```

Every item uses only these fields: `entity_type`, `entity_id`, `label`, `context_label`, `site_id`, `site_name`, `scope_id`, `scope_name`, `device_id`, `sensor_id`, `occurred_at`, `destination_kind`, and `destination_id`. Entity and destination IDs are strings. The backend returns no URL and no arbitrary metadata object.

The typed result taxonomy includes device, sensor, site, scope, Incident Review, sensor task, legacy event, perimeter event, threat detection/correlation, perimeter detection/policy correlation/host correlation, external exposure, and external exposure change. The destination kind maps to a UI surface; 17C supplies panel selection/navigation callbacks.

## Limits, ordering, and context

Primary/key and evidence-reference queries return zero or one item. IP lookup is capped at five records per source/entity type and 25 globally. `truncated` is true if a source exceeded its cap or the merged set exceeded 25. Exact duplicates are removed only by `(entity_type, entity_id)`; different evidence types remain distinct.

IP results sort by normalized `occurred_at` descending, null timestamps last, `entity_type` ascending, then string entity ID descending. Per-domain timestamp meaning varies. Site, scope, device, and sensor context is included only from a stored field or explicit relationship; missing context is null.

`occurred_at` is based on the selected record timestamp: device last-seen, sensor last heartbeat, task creation, review creation, threat/correlation last-seen, perimeter observation/first-seen, exposure last-seen or change observation time. Site/scope identity results have no occurrence time.

## Excluded data and mutations

The projection excludes event message bodies, raw perimeter metadata, arbitrary JSON, task result/digest/creator/error text, credentials, enrollment tokens, hashes/salts, analyst notes, final summaries, and source evidence payloads. Unknown IDs and evidence return an empty `items` array. Invalid inputs return 422. The endpoint performs no INSERT, UPDATE, DELETE, or state transition.

## Schema and Phase 17C

No migration is added; schema remains version 43. 17C can use the fixed `destination_kind` and `destination_id` to select existing panels. Some panel selection hooks and exact task selection are not yet exposed and will need bounded frontend/API wiring; no URL is fabricated by this endpoint.
