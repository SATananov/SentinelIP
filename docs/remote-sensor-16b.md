# Remote Sensor Fleet Operations — 16B

## Purpose

16B exposes the existing, bounded remote sensor management operations from the Remote Sensor Fleet operator panel. It covers site creation and enablement, enrollment lifecycle, sensor access state, and site-constrained scope assignments. All behavior remains server-authoritative.

## Approved actions

- Create a site; list and select sites; enable or disable a site.
- Issue and revoke sensor enrollment tokens.
- Enable or disable a selected sensor; revoke its credential.
- Inspect, add, and remove scope assignments for a selected sensor.

The UI does not edit site metadata after creation, rename or move sensors, delete sensors/sites, edit capabilities, or add task controls. Task history, creation, results, and commands are outside 16B.

## Site and sensor lifecycle

Disabling a site blocks sensor authentication and work, enrollment issuance and consumption, and task creation/claiming. It does not delete assignments or task rows, and does not cancel tasks. Re-enabling restores site-level eligibility only; each sensor’s own enabled and credential state still applies.

Disabling a sensor prevents authentication, heartbeats, task claiming, and new task creation. It can be re-enabled while its credential is active. Credential revocation rotates stored credential material, disables the sensor, and prevents that sensor record from being restored by re-enabling. Registration through a new enrollment creates a new sensor record. Revocation leaves assignments and task rows in place; it does not cancel tasks.

## Enrollment lifecycle and secret handling

Enrollment issuance is bound to an enabled site, is single-use, and accepts a TTL from 60 to 3600 seconds (default 900). The database stores a token hash. Registration creates a separate sensor credential. Tokens are not returned by enrollment history/list routes; issuing another token does not revoke earlier outstanding tokens.

The issued enrollment token is displayed only in the active issuance panel with the warning: “This token is shown only once. Copy it now; it cannot be retrieved later.” It exists in transient component state, is cleared when the panel closes, the selected site changes, or another issuance starts, and is not written to browser storage, URL/history, or logs. Enrollment history exposes only lifecycle metadata: ID, site context, creation/expiry/revocation/consumption times, and registered sensor ID when present.

Enrollment lifecycle labels are Pending, Consumed, Revoked, and Expired. Revoking an enrollment prevents its use to register a sensor; it does not revoke a registered sensor credential.

## Capabilities

Capabilities remain sensor-declared metadata and are displayed read-only. The supported values are `LOCAL_NETWORK_DISCOVERY`, `HOST_DISCOVERY`, `SERVICE_DISCOVERY`, and `LOG_COLLECTION`. They are not inferred from platform/version and cannot be edited by an operator in 16B.

## Assignment eligibility

Assignments are scoped to a sensor and site. A scope can be bound to one site and assigned to multiple sensors at that site. The eligible-scope selector is bounded and returns only scopes passing the existing remote sensor policy: authorized and confirmed `PRIVATE_NETWORK` scopes backed by enabled authorized networks, within RFC1918 IPv4 and `/24`-or-narrower limits, unbound or bound to the selected site, and not already assigned to the selected sensor.

The assignment POST accepts only a positive `scope_id`; the backend repeats eligibility and site checks at mutation time. Existing duplicate assignment behavior remains idempotent. Assignment removal is explicit and confirmed. The assignment list adds safe scope label, type, enabled, and authorized display fields to the existing assignment record.

## Confirmation and updates

Site creation and selection require no confirmation. Sensor enable/disable, assignment removal, and outstanding enrollment revocation use explicit confirmation. Site disablement explains its effect on all sensors and task/enrollment eligibility. Credential revocation requires stronger confirmation and explains that re-registration is required.

The UI waits for server confirmation; it does not optimistically report success. Successful writes refresh only the affected site/enrollment, selected sensor/fleet page, or assignment list/count. Stale results from an old site/sensor context are ignored.

## Security boundary

All management routes, including the eligible-scope projection, use the existing `local_management` dependency. It requires a loopback client and an allowed local hostname/origin, rejects Authorization and sensor identity headers, rejects forwarded headers, and sets `Cache-Control: no-store`. Proxy headers are not trusted.

Responses use explicit operator projections and do not expose enrollment token hashes, sensor credential material, raw heartbeat bodies, or task payload/results.

## Schema and phase boundary

16B adds no migration; schema remains version 43. It adds no delete, task, execution, or capability mutation operation. Phase 16C is the next design boundary for bounded task status/history and failure inspection, subject to its own review.
