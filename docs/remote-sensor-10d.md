# Remote Sensor 10D: assigned private LAN discovery

10D introduces a typed task flow for bounded private-network discovery. The Core
creates a task for a persisted sensor and rechecks the sensor, site, assignment,
authorized scope, linked network, device (for service discovery), and declared
capability at creation, claim, start, and result acceptance.

## Task flow

1. An administrator creates a `DISCOVER_NETWORK` or `DISCOVER_SERVICES` task for
a sensor and one of its current scope assignments.
2. The Core stores the task type, sensor/site/scope identity, expiry, and (for
service discovery) a persisted device ID and its current IP snapshot. Task API
requests do not accept a target, command, or scanner flags.
3. The sensor claims its next pending task over the authenticated 10C transport.
The claim contains the assigned canonical CIDR; service-task IP is derived by
Core from the device record. A task is claimed once and expires after at most
15 minutes.
4. The sensor validates the typed task against its independently installed
`LocalExecutorGrant`: sensor UUID, scope ID/type, exact CIDR, required capability,
and any derived device IP must match. It must fail closed before calling a
scanner on any mismatch.
5. The Linux adapter calls the existing bounded host/service discovery services.
Host discovery uses the existing fixed `-sn` profile. Service discovery uses the
existing fixed conservative TCP `-sT -sV --version-light --open` profile and
21-port allowlist, with existing bounded timeouts/output. No task field becomes
an executable argument.
6. The sensor submits bounded structured observations. Core checks task ownership
and state, current assignment/scope/device validity, result schema, and every
observed address before passing evidence into the existing device or service
inventory pipeline. Provenance includes sensor UUID and task ID.

Only confirmed, enabled `PRIVATE_NETWORK` assignments to RFC1918 networks with
prefix `/24` or narrower are eligible. Network discovery requires
`HOST_DISCOVERY`; service discovery requires `SERVICE_DISCOVERY`. A service task
is bound to a persisted device on that assigned network. Core and sensor both
reject an address outside the assigned CIDR.

## Machine API

All task routes use the 10C machine authentication, HTTPS, timestamp, nonce,
replay, payload-size, and per-sensor rate checks:

- `POST /sensor/tasks/claim`
- `POST /sensor/tasks/{task_id}/start`
- `POST /sensor/tasks/{task_id}/fail`
- `POST /sensor/tasks/{task_id}/result`

Local management creates tasks using:

- `POST /sensors/{sensor_id}/tasks/discover-network` with `scope_id`
- `POST /sensors/{sensor_id}/tasks/discover-services` with `scope_id` and
  persisted `device_id`

Management routes do not accept a target address. Sensors cannot call local
management routes or change assignments. A result is reserved by a digest before
inventory work; retries/duplicate submissions are rejected. Tasks expire after
15 minutes, have no automatic retry loop, and stale pending/claimed/running tasks
are marked failed when processed. An administrator may issue a new task after
review.

The inventory APIs currently record provenance in each observation's `source`
field as `remote-sensor:<sensor UUID>:task:<task UUID>`. Existing stable device
keys, change detection, and service/risk/CVE processing remain in the existing
inventory pipeline.

## Boundaries and limits

10D supports only `DISCOVER_NETWORK` and `DISCOVER_SERVICES`. It adds no arbitrary
execution, shell, user-selected Nmap arguments, raw target requests, public IPv4,
hostname or public CIDR scanning, exploit/brute-force/credential checks, scan
jobs, or arbitrary result/file uploads. The service scanner is TCP-only and uses
its existing fixed port profile; host discovery and service discovery remain
bounded by their existing scanner timeouts and output caps.

The task record references the site, sensor, authorized scope, and optional
persisted device; the live sensor-scope assignment is deliberately rechecked at
each transition so removing an assignment blocks further task work. Inventory
pipeline writes and task completion are not one cross-service atomic transaction:
a process failure during ingestion can leave partial inventory evidence while a
task remains reserved/running. Such tasks must be reviewed and, if needed,
reissued; the reservation prevents an automatic duplicate ingestion attempt.

Migration 32 adds only the typed task table and claim index. It preserves 09D
network/scope/device evidence and all 10A/10B/10C state. Database initialization
is repeat-safe and the task table has foreign keys to sensor/site, scope, and
optional device identity.
