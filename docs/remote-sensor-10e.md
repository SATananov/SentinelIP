# Remote Sensor 10E: deployed Linux runtime

10E adds a standalone process (`python -m sensor`) that uses the existing 10C
machine transport and 10D typed task contract. The runtime supports only
`DISCOVER_NETWORK` and `DISCOVER_SERVICES` for locally granted, assigned
`PRIVATE_NETWORK` scopes. It does not accept a raw target, command, shell,
arbitrary scanner flags, file upload, or script.

## Provision and configure

1. Create the sensor/site and one-time enrollment token using the local
   management API. Register the sensor using the 10B enrollment flow and save
   the returned machine credential in protected sensor-local storage.
2. Assign the sensor an authorized, confirmed, enabled private network scope.
   The Linux provisioning flow in 10F fetches the sensor's current protected
   grant from Core; the runtime cannot add or edit grants. See
   [Remote Sensor 10F](remote-sensor-10f.md).
3. Create a protected JSON config file, for example `/etc/sentinelip/sensor.json`:

   ```json
   {
     "core_url": "https://sentinelip.example.internal",
     "sensor_uuid": "dd03f49d-37d7-41b1-8c06-95b74c5d935a",
     "sensor_credential": "<machine credential>",
     "grant_file": "/etc/sentinelip/grants.json",
     "poll_interval": 10,
     "heartbeat_interval": 45,
     "request_timeout": 15,
     "capabilities": ["HOST_DISCOVERY", "SERVICE_DISCOVERY"],
     "platform": "linux",
     "version": "1.0.0"
   }
   ```

   Restrict both files to the sensor service account, with no group/other
   permissions (`chmod 600` on Unix). The runtime rejects files with broader
   permissions. The credential can instead be omitted from the JSON file and
   supplied via `SENTINEL_SENSOR_CREDENTIAL`; `SENTINEL_SENSOR_CONFIG` selects
   the config path. Environment variables are useful with a service manager's
   secret facility. OS keyring integration is deferred.

4. Check the local files and policy, then verify Core identity without scanning:

   ```sh
   python -m sensor --config /etc/sentinelip/sensor.json check-config
   python -m sensor --config /etc/sentinelip/sensor.json self-test
   ```

5. Start the runtime:

   ```sh
   python -m sensor --config /etc/sentinelip/sensor.json run
   ```

   A service manager may run this command under a dedicated unprivileged user.
   See [Remote Sensor 10F](remote-sensor-10f.md) for the Linux service packaging
   and first-run enrollment flow.

## Runtime behavior

At startup the process authenticates `GET /sensor/self` and verifies the
configured UUID. It sends a heartbeat immediately, then every 45 seconds by
default. It polls every 10 seconds by default, claims one task at a time, and
never starts a task until its typed claim matches the local sensor UUID, scope,
CIDR, and capability grant. It executes the existing fixed Linux discovery
profiles, then submits bounded structured results. On local validation,
scanner-timeout, or scanner failure it reports a bounded failure code. It does
not automatically re-execute a task after a transport failure; an administrator
can review and issue a new task.

Polling is bounded to 5–15 seconds, heartbeat to 30–60 seconds, and each HTTP
request has a 1–60 second timeout (defaults shown above). Core transport failures
use stepped 5, 10, 30, then 60 second backoff, capped at 60; a successful Core
exchange resets the backoff. The process has one synchronous worker and no
background scan threads. SIGINT/SIGTERM stops future claims; an active bounded
scanner call is allowed to finish and submit its result before shutdown.

Only `HOST_DISCOVERY` and `SERVICE_DISCOVERY` are enabled by this runtime. Task
capabilities and local grants must both permit the task. No public IPv4, public
CIDR, hostname, or out-of-assignment target can pass the local grant validator.
The Linux adapter reuses the existing fixed `-sn` host profile and conservative
TCP service profile with its fixed 21-port allowlist and bounded timeouts.

## TLS and credential handling

Deployed Core URLs must use HTTPS. TLS certificate verification is always on;
the client refuses redirects and offers no insecure-TLS option. HTTP is accepted
only when `development_mode` is explicitly true and the URL host is `localhost`,
`127.0.0.1`, or `::1`. Forwarded headers are never used. A reverse-proxy/Core
deployment must preserve the verified HTTPS scheme under the 10C requirements.

The client sends the 10C bearer credential, registered sensor UUID, fresh
timestamp, and a new 256-bit nonce for every request. It exposes only `/sensor/self`,
heartbeat, claim, start, result, and failure calls. Credentials and authorization
headers are not logged; logs contain timestamp, sensor UUID, task ID/type,
status, and bounded error codes only. Protect the credential and grants file,
redact Authorization headers at the serving proxy, and revoke a credential in
Core if a host is lost.

The runtime does not create a local authoritative inventory or persist task
results. Core remains authoritative for assignments, tasks, and inventory. A
network failure during result submission can leave a task incomplete; the runtime
does not repeat the scan automatically, and the operator should review task state
before creating a replacement task.
