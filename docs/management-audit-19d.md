# Management History UI (19D)

The Remote Sensor Fleet operator workspace includes a compact **Management History** section. It reads the existing `GET /management-audit-events` API and shows security-relevant management changes in a bounded, read-only list. No new page, route, mutation, or schema was added.

## Use

The section loads its first page when mounted. Operators can filter by exact event type, entity type, entity ID (only when an entity type is selected), and positive site ID. Changing a filter resets the offset; changing entity type clears the previous entity ID. Pages remain fixed at 50 rows with Previous and Next controls. Refresh is explicit, and the section does not poll.

Each row shows the event label, stored entity type and scalar ID, occurrence time, and actor source class. Expanded details render only relevant fields from the fixed audit projection: state transition, expected port lists, enrollment expiry, task type and target device ID, cleanup aggregates, and related site/scope/sensor IDs. Rendering does not fetch the current entity, so history remains visible after a network, assignment, or exposure policy is removed.

`LOCAL_OPERATOR`, `API_CLIENT`, and `SENSOR` are shown as “Local operator,” “API client,” and “Sensor.” This is the caller source class, not a person’s identity. The UI does not imply a username, administrator, or analyst identity.

## Safety and request behavior

The API helper sends only the supported fixed query fields, uses GET with `cache: no-store`, validates the filters, and supports abort signals. Filter changes, pagination, and refresh abort/supersede previous work; generation checks ignore stale success and failure results. API errors are shown as concise messages. Unknown event/entity/source values have neutral fallback labels.

The UI has no event creation, edit, delete, replay, or rollback controls. Cleanup, task, and enrollment details remain aggregate or identifier-only; the UI does not display token material, task payload/result/error, target IP, DNS/web contents, or raw JSON.

There is no polling, migration, or schema change. Schema remains version 44. Phase 19 is complete when the existing append-only and atomic write behavior, bounded local history API, and this UI are verified together with the full backend and frontend suites. Phase 19D does not add a new persistence or identity model.
