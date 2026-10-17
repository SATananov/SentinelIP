# Phase 18B — Lifecycle Inventory and Dry-Run Preview

## Purpose and boundary

The local operator can inspect current retention-policy coverage and counts through GET /data-lifecycle/preview. This is a counts-only preview: it does not delete, update, archive, vacuum, or rewrite any data. The endpoint and UI are direct-local, use local_management, and successful responses are Cache-Control: no-store.

Only DNS_OBSERVATIONS and WEB_OBSERVATIONS have an active retention policy. The preview uses the persisted retention_until deadline written at ingestion. Changes to a telemetry sensor's retention_days do not recalculate existing observation deadlines. Other task expiry, review closure, disabled state, or credential revocation is not treated as retention eligibility.

## Data-class inventory

Classes are returned in stable product/domain order. Grouped classes are explicit:

- DEVICE_OBSERVATIONS: device_observations and scope_device_observations.
- INVENTORY_HISTORY: ports, port observations, services, service observations, changes, findings, and CVE matches.
- WEB_DETECTIONS: web detections and their observation-link rows.
- THREAT_DETECTIONS: threat detections and threat evidence.
- THREAT_CORRELATIONS: correlations and correlation entities.
- LEGACY_INCIDENTS: legacy incidents and incident-correlation links.
- EXTERNAL_EXPOSURE_ASSESSMENTS: exposure policies, assessments, classifications, and presence state.
- SCOPES: authorized scopes and their site/network/CIDR/hostname bindings.

Other returned classes represent their named table: legacy events, networks, devices, CVE catalog, telemetry sensors, DNS/web observations, perimeter events/detections/correlations, external exposure rows/observations/changes, remote sensor tasks, remote sensors, enrollment tokens, sites, assignments, Incident Reviews, review evidence links, notes, timeline events, sensor transport nonces, and schema migration records.

Policy states:

- ACTIVE_RETENTION_POLICY: DNS and web observations only.
- PRESERVE: identity/configuration roots and Incident Review data, including devices, networks, sensors, sites, scopes, assignments, CVE catalog, reviews, evidence links, notes, timeline, and schema migration records.
- POLICY_UNDEFINED: operational/history classes without an approved retention rule. Their row count is reported as policy_undefined; no expiry is fabricated.
- TRANSIENT_INTERNAL: transport nonces, which already have opportunistic protocol cleanup and are not retention candidates in this preview.

## Deadline and dependency semantics

One request-wide aware UTC evaluated_at is used. A valid deadline is expired inclusively when retention_until <= evaluated_at. ISO timestamps with an explicit offset are normalized to UTC; legacy naive ISO timestamps are interpreted as UTC. Null deadlines count as policy-undefined for the row, and malformed deadlines count as invalid. Neither is eligible. The schema currently declares both observation deadlines NOT NULL; null handling is defensive for historical/corrupt schemas.

For DNS, all valid expired observations are currently preview-eligible. No direct review or downstream evidence dependency exists.

For web observations, direct review links target WEB_DETECTION, not WEB_OBSERVATION. A detection-linked expired observation is eligible only if the detection's persisted structured_evidence reconstructs the full typed WebDetection and WebEvidence contract: complete allowlisted snapshot fields, valid timestamps/domains/signals, matching sensor/device identity, matching primary hostname, unique observation identities, and a represented primary observation. If any linked detection fails validation or omits that observation from the snapshot, the observation is counted once as protected_by_dependency. Complete snapshots are safe to retain as the independent detection evidence while the FK uses ON DELETE SET NULL.

protected_by_review is zero for these observation classes. No IP or hostname coincidence is used to infer a review relationship.

## Response and UI

The response is { evaluated_at, items }. Each item has only class, policy state, counts, and oldest_eligible_at; no row IDs, telemetry content, hostnames, domains, URLs, or metadata are returned. Counts are SQL aggregates for inventory classes. The active-policy classes stream only id and retention_until in Python to classify supported timestamp forms without loading telemetry bodies. Web dependency checks use bounded batches and joined detection/link projections, not per-observation lookups.

The Data Lifecycle section is a compact local-operator panel with explicit Load/Refresh. It displays policy labels, counts, protected totals, invalid deadline counts, and oldest eligible deadline. It has no cleanup action, no date or batch controls, and no polling.

## Query-plan and volume notes

There is no index on retention_until. Expired counts and deadline classification therefore scan the two observation tables; total web-observation count uses the existing covering device/time index. The web dependency lookup scans web_detections once for primary-observation references because that field has no standalone index, then uses the existing web_detection_observations(observation_id) index for explicit related observations. It does not repeat the detection scan per observation. This is acceptable for the current local preview but merits measurement before large deployments. 18B adds no index or migration.

A local synthetic check with 15,000 DNS plus 15,000 web observations (30,000 total) completed in approximately 0.13 seconds in this development environment. It is a smoke check, not a production benchmark. Both active-class scans and the primary web-detection dependency check are linear; query plans show no retention index and no unexpected temporary sort.

## Phase boundary

Schema remains 43. No cleanup endpoint or UI exists. 18C must independently recheck deadlines and current review/dependency protection in the same deletion transaction; this preview is informational only. Initial cleanup should remain limited to approved DNS and snapshot-safe web observations, with bounded oldest-first batches and no deletion of review roots or undefined-policy classes.
