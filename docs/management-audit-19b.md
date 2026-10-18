# Management Security Change Audit Trail — 19B

## Purpose and boundary

Schema 44 adds a durable, append-only record of selected management state changes. The audit is a change history, not an API access log. Reads, previews, dashboards, investigation lookups, Incident Review actions, sensor task lifecycle transitions, telemetry, detections, and assessment results are excluded.

No authenticated human identity exists. `LOCAL_OPERATOR` means a route passed the direct-local management guard; `API_CLIENT` means the route has no stronger caller identity; `SENSOR` means a successful enrollment registration proved possession of its one-time enrollment credential. These values do not identify a person. No `SYSTEM` or `UNKNOWN` actor is used.

## Event and entity types

Events are fixed to: `SITE_CREATED`, `SITE_ENABLED`, `SITE_DISABLED`, `NETWORK_CREATED`, `NETWORK_ENABLED`, `NETWORK_DISABLED`, `NETWORK_DELETED`, `SCOPE_AUTHORIZED`, `SCOPE_REAUTHORIZED`, `EXPOSURE_POLICY_CONFIGURED`, `EXPOSURE_POLICY_REMOVED`, `ENROLLMENT_ISSUED`, `ENROLLMENT_REVOKED`, `ENROLLMENT_CONSUMED`, `SENSOR_REGISTERED`, `SENSOR_ENABLED`, `SENSOR_DISABLED`, `SENSOR_CREDENTIAL_REVOKED`, `SENSOR_SCOPE_ASSIGNED`, `SENSOR_SCOPE_UNASSIGNED`, `SENSOR_TASK_CREATED`, and `DATA_LIFECYCLE_CLEANUP_EXECUTED`.

Entity types are fixed to: `SITE`, `NETWORK`, `SCOPE`, `EXTERNAL_EXPOSURE_POLICY`, `SENSOR_ENROLLMENT`, `SENSOR`, `SENSOR_SCOPE_ASSIGNMENT`, `SENSOR_TASK`, and `DATA_LIFECYCLE`.

Database CHECK constraints enforce event, entity, and actor allowlists. The typed insertion helper checks event/entity pairings, required context, fixed state values, cleanup fields, and exposure-policy ports. Events store scalar identifiers without cascading foreign keys so history survives deletion of the managed record.

## Atomicity and immutability

Each event is inserted using the same database connection and transaction as its mutation. An event insert failure rolls back that mutation; a mutation failure leaves no event. Existing `BEGIN IMMEDIATE` transactions are retained for sensor operations and lifecycle cleanup. Other stores insert the event within their existing connection transaction.

Database triggers reject updates and deletes from `management_audit_events`. Migration 44 adds only the audit table, four history indexes, and the append-only triggers.

## Included changes

- Site creation and actual enabled-state transitions.
- Enrollment issue/revoke and successful consumption.
- Sensor registration, actual enabled-state transitions, and credential revocation.
- Sensor scope assignment and unassignment; removals capture relationship IDs before deleting the assignment row.
- Operator-created remote task creation only.
- Network creation, enabled-state changes, and deletion; network creation/deletion retain the linked private scope ID.
- Public scope authorization and hostname reauthorization.
- External exposure policy configuration/removal with normalized expected TCP port arrays (maximum 64).
- Successful DNS/web lifecycle cleanup, including empty runs, with aggregate counts and its evaluated time.

Enrollment consumption and sensor registration produce two events because they describe distinct persisted entities; both are in the registration transaction. Credential revocation that also disables an enabled sensor emits both real transitions. No-op state requests, repeated revocations, existing assignments, absent assignment removals, and identical exposure policies do not emit transition events.

## Exclusions and redaction

The event table has no arbitrary metadata or summary field. It never stores enrollment plaintext or hash, sensor credential material or hash, authorization/token headers, request bodies, telemetry, DNS/web observation values, task target IP or execution payload, raw exception text, or review evidence payloads. Task claim/start/result/failure remain in task history; Incident Review actions remain in the review timeline.

Network/scope/exposure-policy routes currently use `API_CLIENT`, because they do not depend on `local_management`. This phase does not change those guards. Local-only history access is planned for 19C.

## Retention and future history API

Management audit history is `PRESERVE`; Phase 18 DNS/web cleanup does not apply to it. The event rate is expected to remain low relative to telemetry because only explicit state changes, task creation, and cleanup invocations are recorded.

19C may add a local-management-only, no-store history read API with fixed event/entity/site filters, bounded pagination, and deterministic `occurred_at DESC, id DESC` ordering. 19B adds no history API and no frontend UI.
