# Remote Sensor 16D — Bounded Task Operations

## Purpose and boundary

16D exposes operator creation of the two existing typed remote sensor tasks: `DISCOVER_NETWORK` and `DISCOVER_SERVICES`. Creation adds a `PENDING` task to a sensor's queue. It does not execute the task. Execution begins only if an eligible sensor later claims it.

The feature adds no arbitrary task type or payload, free-form target, command, scanner argument, custom port, retry, operator cancellation, rescheduling, or raw result view. The sensor claim, transition, result ingestion, executor, and scanner profiles are unchanged.

## Request and response

The existing direct-local routes remain strict:

- `POST /sensors/{sensor_id}/tasks/discover-network` with `{ "scope_id": positive_integer }`
- `POST /sensors/{sensor_id}/tasks/discover-services` with `{ "scope_id": positive_integer, "device_id": positive_integer }`

Unknown/extra request fields remain forbidden. The operator response is explicitly projected to `id`, `sensor_id`, `site_id`, `scope_id`, `task_type`, `status`, `target_device_id`, `target_ip`, `created_at`, `expires_at`, and `attempt_count`. Internal fields such as `result_digest`, `created_by_source`, and stored error text are not returned.

## Eligibility and capabilities

Network discovery requires the sensor-declared `HOST_DISCOVERY` capability. Service discovery requires `SERVICE_DISCOVERY`. The UI does not infer either capability from platform or version.

Both task types require an enabled sensor, active credential, enabled site, current sensor/site/scope assignment, unchanged assignment target, and a currently authorized, confirmed, enabled private network. The target must be RFC1918 IPv4 with prefix length `/24` or narrower. Service discovery additionally requires a persisted device in the linked network with a canonical current IPv4 address inside the assigned scope. The server derives and stores that address as the target snapshot.

The bounded direct-local selector routes return only currently eligible assigned scopes and eligible devices. Selector output is advisory. Task creation revalidates all conditions transactionally, so a scope or device that changes after selection is rejected safely.

## Fixed task lifetime and queue cap

Operator-created task lifetime is fixed at 900 seconds. There is no UI or request TTL setting. `expires_at` is created as the store clock plus 900 seconds.

`MAX_ACTIVE_TASKS_PER_SENSOR` is 20. A task counts only while its stored state is `PENDING`, `CLAIMED`, or `RUNNING` and `expires_at` is later than the creation request's store clock. `COMPLETED`, `FAILED`, and `CANCELLED` tasks do not count; expired nonterminal rows do not count even if they have not yet been cleaned up by sensor transport. The count and task insert occur in the same SQLite write transaction. At capacity, creation returns HTTP 409 with `TASK_QUEUE_FULL` and the neutral message “Sensor task queue is at capacity.”

This cap bounds the per-sensor active queue; it is not deduplication or API idempotency. Distinct requests for the same target may create distinct tasks. The UI prevents accidental repeat submission while one request is active.

## Offline and pending sensors

Heartbeat freshness is not a creation eligibility requirement. An otherwise eligible `OFFLINE` or `PENDING` sensor may receive a task. The UI explains: “Task queued. It will run only if the sensor claims it before expiry.” That wording does not claim the task has executed or that results exist. A disabled sensor, revoked credential, or disabled site is unavailable for task creation.

## Selector and confirmation flow

The operator selects a sensor in Remote Sensor Fleet, chooses one of the supported operations, selects a server-provided eligible assigned scope, and for service discovery selects a server-provided device/IP. No free-form target or scanner configuration is accepted. The UI asks for explicit confirmation naming the selected scope or IP and sensor, including the 15-minute claim window. Success is shown only after the server returns the created `PENDING` task.

After success, Task History receives one targeted refresh signal. Existing filters are retained; the created task is selected only if it appears in the current result page. No polling is added.

## Security and schema

All task selector and creation routes reuse the direct-local `local_management` boundary, including loopback/host/origin checks, forwarded-header rejection, sensor/auth-header rejection, and `Cache-Control: no-store`. They are not sensor transport routes.

No migration is required. Schema remains version 43. The bounded task model and queue cap complete the Phase 16 operator boundary; task retry/cancellation workflows, notifications, schedulers, and arbitrary execution remain outside Phase 16.
