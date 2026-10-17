# Remote Sensor 16C — Task History and Failure Inspection

## Purpose and boundary

16C adds an operator-facing, bounded, read-only view of remote sensor task lifecycle metadata. `GET /sensor-tasks` is registered with the same direct-local `local_management` dependency as the existing operator sensor routes and returns `Cache-Control: no-store`.

The route does not create, retry, cancel, reschedule, or otherwise mutate tasks. Task creation and sensor transport lifecycle routes remain unchanged. The UI refresh is manual; there is no polling engine or notification behavior.

## Persisted task model

The existing `remote_sensor_tasks` table stores task ID, sensor/site/scope IDs, task type and status, optional target device ID and target IP, creation/expiry/claim/start/completion/failure timestamps, attempt count, failure code/message, creation source, and result digest. It does not store a raw result body, `updated_at`, or a dedicated cancellation timestamp.

Persisted task types remain `DISCOVER_NETWORK` and `DISCOVER_SERVICES`. Persisted states remain `PENDING`, `CLAIMED`, `RUNNING`, `COMPLETED`, `FAILED`, and `CANCELLED`. 16C adds no stored `EXPIRED` state.

## History response

The bounded list response contains `evaluated_at`, `items`, `limit`, `offset`, and `has_more`. Each item is an explicit safe projection of task ID, sensor/site/scope context, target device/IP, task type, persisted status, lifecycle timestamps, attempt count, safe failure code/text, and derived `expired` state.

Sensor, site, and current scope names/target are joined in one query with left joins. Scope fields describe current context and are not guaranteed task-time snapshots. For service tasks, `target_ip` is the persisted task-time target. No device hostname is included.

The endpoint excludes result digests, creation source, raw payload/results, stored error messages, credentials, enrollment tokens, hashes, salts, authentication material, exception traces, and command/scanner output.

## Expiry and time

The response captures one aware UTC `evaluated_at` for all rows. `expired` is true only when `expires_at` is valid and earlier than that instant and the persisted status is nonterminal. `COMPLETED`, `FAILED`, and `CANCELLED` are never marked expired. A GET does not update task storage. The UI presents expiry as a derived indicator alongside the stored status.

Malformed timestamps are returned as unavailable (`null`); they do not imply expiry. Null lifecycle timestamps remain null for neutral UI labels.

## Failure taxonomy

Known failure codes are allowlisted: `TASK_EXPIRED`, `SENSOR_DISABLED`, `SCOPE_DISABLED`, `SCOPE_NOT_ASSIGNED`, `CAPABILITY_NOT_ALLOWED`, `TARGET_OUTSIDE_SCOPE`, `CANCELLED`, `SCANNER_TIMEOUT`, `SCANNER_FAILED`, `INVALID_RESULT`, and `RESULT_OUTSIDE_SCOPE`.

The database does not constrain `error_code`, so unknown/malformed values are projected as `UNKNOWN_FAILURE`. `error_message` is never serialized. The response maps codes to fixed, neutral operator text; unknown values map to “Unknown task failure.”

## Pagination, filters, and ordering

`limit` defaults to 100 and is bounded from 1 to 100. `offset` defaults to 0 and is bounded from 0 to 100000. Filters are exact: sensor, site, scope, device, task type, stored status, and a creation-time range. Creation bounds must both be provided, be timezone-aware, ordered, and span no more than 90 days. Results sort by `created_at DESC, id DESC`.

No arbitrary text search or user-selectable sort is supported. No total count is computed.

## Performance

The query uses one bounded joined projection and does not perform per-row lookups. Existing SQLite indexes do not provide the newest-first task ordering; SQLite may scan and use a temporary B-tree sort. This is acceptable for the initial expected task volume and bounded response. No migration or index was added. Revisit indexing based on measured history volume and query latency.

## Frontend

Task History appears inside Remote Sensor Fleet as one all-fleet view. Operators can filter by selected sensor, exact IDs, type, status, and local date/time bounds (converted to UTC). Pagination is independent of fleet pagination. A selected row opens inline lifecycle detail. Refresh is explicit and manual. Request generations and abort handling prevent stale responses/errors from replacing the current result.

No task mutation controls or task mutation API helpers are provided.

## Schema and phase boundary

No migration was added. Schema version remains 43. 16C does not implement task creation, retry, cancellation, rescheduling, raw result inspection, command execution, or notifications. Those remain outside this subphase and require separate approval/design.
