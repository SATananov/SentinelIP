# Remote Sensor 10A: architecture and trust model

This document records the 10A foundation. [Remote Sensor 10B](remote-sensor-10b.md)
adds registration and authenticated self/heartbeat HTTP endpoints; its transport
and caller-supplied UUID contracts supersede the corresponding 10A limitations.

10A provides storage, local management and deterministic authorization primitives.
It does **not** install a sensor, open a remote channel, execute jobs, scan a
network, collect logs or accept remote inventory results. Network Workspace 09D
and browser/DNS telemetry behavior remain separate and unchanged.

## Domain and identity

- A **site** is a logical location with an operator-provided name, description,
  enabled state and server timestamps. It makes no security claim.
- A **remote sensor** belongs to one site and has a server-generated UUID,
  name, platform/version metadata, enabled state and registration/receipt times.
  It is distinct from `telemetry_sensors` (Browser/DNS Sensor 01).
- An **enrollment** is a site-scoped, expiring, one-time invitation. It does not
  grant any network scope. A new sensor has no assignments.
- An **assignment** links a sensor to an existing confirmed PRIVATE_NETWORK scope.
  It pins the canonical CIDR at assignment time. Reassigning an identical pair is
  idempotent. A changed CIDR invalidates the assignment until the operator removes
  and explicitly recreates it; the future local grant must also be renewed.
- `remote_scope_sites` binds each assigned legacy scope permanently to one site.
  Multiple sensors at that site may share it; another site cannot claim it even
  after all assignments are removed. Foreign keys prevent inconsistent site links.

Existing private `network_id` stable keys and public `scope_id` stable keys are
unchanged. No remote observations enter inventory in 10A. Existing network/CIDR
uniqueness cannot distinguish identical private CIDRs at different sites. Before
remote execution or ingestion, a later phase must introduce site-qualified remote
network identity and define device/change/finding/CVE provenance without reusing
legacy network identity across sites. This is a prerequisite, not an implemented
remote inventory capability. Public target scopes cannot be sensor assignments.
Assigned scopes cannot be deleted while site bindings reference them; no cascade
removes existing evidence or authorizations.

## Enrollment and credential lifecycle

The local operator creates an enrollment through the management API or
`RemoteSensorStore.create_enrollment`. It returns a 256-bit random URL-safe token
once. The database stores only its domain-separated SHA-256 digest (the input is
random, not a human password), server creation/expiration times and revocation /
consumption metadata. Default lifetime is 15 minutes; allowed lifetime is 1–60
minutes. Disabled sites cannot issue or consume invitations.

`consume_enrollment` is a **local domain method**, not a public HTTP endpoint.
It validates the invitation and site in a write transaction, creates a sensor,
marks the invitation consumed and returns a distinct 256-bit sensor credential
once. Concurrent redemption has exactly one winner. The dedicated credential is
stored as a salted PBKDF2-SHA256 verifier using the existing authentication hash
primitive; remote identity is never authenticated against browser/DNS tables.
Secret-bearing return objects exclude the secret from their representation.
Read/list APIs return neither secrets nor password verifiers. Creation responses
use `Cache-Control: no-store`. The application adds no secret logging; callers
must also avoid recording creation responses or secret-bearing return values.

Enrollment revocation prevents redemption. Sensor disablement suspends all
credential-backed operations; site disablement suspends every sensor at the site.
Credential revocation disables the sensor, records the server revocation time and
replaces the verifier with one for a discarded random secret. Re-enabling cannot
restore a revoked identity. Re-enrollment is required in 10A. Removing an
assignment immediately removes its core-side policy permission.

Future rotation should atomically replace a dedicated credential under an
authenticated, authorized rotation flow, with explicit revocation of the previous
credential and audit timestamps. No rotation transport exists in 10A. Future mTLS
can bind a certificate to the same sensor UUID without changing scope ownership.

## Management API boundary

The following routes require a **direct loopback peer** and a loopback Host.
Forwarded/proxy headers and unapproved browser origins are rejected. The supported
development origins are `http://localhost:5173` and `http://127.0.0.1:5173`.
This is local operator access, **not authenticated multi-user administration**.
Local OS users/processes can manage sensors. No user identity is fabricated.
Do not publish or reverse-proxy these routes; authenticated remote administration
and trusted-proxy configuration need their own design before deployment.

| Method | Route | Purpose |
|---|---|---|
| POST / GET | `/sites` | Create / list sites |
| GET / PATCH | `/sites/{id}` | Read / set enabled state |
| POST / GET | `/sites/{id}/sensor-enrollments` | Issue once / list safe metadata |
| DELETE | `/sensor-enrollments/{id}` | Revoke invitation |
| GET | `/sites/{id}/sensors` | List sensor metadata and derived status |
| GET / PATCH | `/sensors/{id}` | Read / set enabled state |
| DELETE | `/sensors/{id}/credential` | Permanently revoke credential |
| POST / GET | `/sensors/{id}/scope-assignments` | Assign persisted scope ID / list |
| DELETE | `/sensors/{id}/scope-assignments/{scope_id}` | Remove assignment |

Lists are paginated (default/max 100). Unknown request fields are rejected.
There are no remote enrollment, heartbeat, job, result, scanner or shell routes.
A sensor credential or site ID confers no management API privilege. Management
calls resolve their database at request time, allowing isolated temporary DB tests.

## Double enforcement contract

**Core:** `validate_assigned_target` authenticates the sensor's dedicated
credential, checks sensor/site enabled and revocation state, reloads the persisted
assignment, requires an enabled confirmed PRIVATE_NETWORK scope and its associated
authorized/enabled legacy network, and compares the pinned CIDR with the current
scope. The remote policy additionally requires RFC1918 IPv4 /24 or narrower.
A concrete target must belong to that CIDR. PUBLIC_IPV4, HOSTNAME and PUBLIC_CIDR
are never eligible. Capability metadata does not grant authorization.

**Sensor:** `LocalScopeGrant` is an immutable, platform-neutral local allowlist
contract. Its UUID, scope ID and canonical RFC1918 CIDR must be installed and
confirmed independently on the sensor. Each future concrete target is checked
against that grant. A job must never provide or replace its own trusted grant.
Thus a request for `8.8.8.8` cannot pass a grant for `192.168.1.0/24`, even when
sent by the core. The helper is tested, but no deployed sensor enforces it yet.
Provisioning, local confirmation, integrity-protected grant storage, expiry,
revocation delivery and fail-closed offline behavior are prerequisites for a
future executable sensor. A compromised core cannot be allowed to rewrite that
local allowlist through the job channel.

A future outbound sensor channel must authenticate the core (TLS certificate
verification), authenticate the machine separately, resist replay and bound
requests/results. Plaintext HTTP remote credentials are not an approved design.
No listener, polling loop or transport is implemented here.

## Capabilities and heartbeat

The fixed capability vocabulary is LOCAL_NETWORK_DISCOVERY, HOST_DISCOVERY,
SERVICE_DISCOVERY and LOG_COLLECTION. These are declared metadata only; there is
no executable capability. SHELL, EXEC, SCRIPT and ARBITRARY_NMAP are not accepted.
OS-specific Linux/Windows implementations belong behind future adapters.

`heartbeat` is a credential-authenticated domain method. It accepts bounded
platform/version and whitelisted capabilities; it accepts no client ONLINE state,
client last-seen timestamp, target or observations. The server stamps receipt time.
Status is derived at read time: DISABLED when site/sensor is disabled or revoked;
PENDING before the first authenticated heartbeat; ONLINE for elapsed time 0–300
seconds inclusive; OFFLINE otherwise (including future receipt times). No worker
or background polling is needed. ONLINE describes recent authenticated contact,
not evidence that a sensor is uncompromised or scans successfully.

## Future jobs and result ingestion (design only)

A future job needs a server UUID, sensor/site identity, persisted scope/assignment
and local-grant version, an exact authorized target set, fixed product job type,
expiry, timestamps and bounded result/error summaries. Proposed typed operations
are DISCOVER_NETWORK and DISCOVER_SERVICES; COLLECT_LOGS requires a separate
privacy/source contract. States may be PENDING, CLAIMED, RUNNING, COMPLETED,
FAILED or CANCELLED. No command string, executable path, script, arbitrary Nmap
arguments or raw user-provided target belongs in the wire contract. No job table
or execution service is added in 10A.

Core issuance and result admission must revalidate current scope and assignment
transactionally. Result ingestion must authenticate the machine, check job owner,
type, expiry/replay identity, exact expected targets and every observation's
membership, then derive device/site/scope identity server-side. It must reject
out-of-assignment evidence before existing inventory/risk/CVE/change pipelines.
Sensor reports are untrusted observations, not authority to create scopes,
choose device identity or assert vulnerabilities. The current target validator
is a necessary precondition, not a result-ingestion authorization API. No remote
result ingestion is exposed, so a sensor cannot submit inventory evidence in 10A.

## Migration and verification

Migration 30 only creates sites, remote_sensors, sensor_enrollment_tokens,
remote_scope_sites and sensor_scope_assignments plus an index. It leaves existing
09D tables, rows and stable keys intact; uses transactional initialization and
foreign keys; and creates no sites, sensors or authorization implicitly. No table
rebuild or foreign-key disabling is added. Existing operational database backup
advice still applies.

Tests use temporary databases and synthetic credentials. They exercise expiry,
one-time/concurrent consumption, revocation, safe reads, assignment revalidation,
local escape rejection, cross-site binding, loopback management restrictions,
29→30 preservation, rollback and repeated initialization. No scans or DNS are
needed. Run `.venv/bin/python -m pytest -q tests/test_remote_sensors.py
 tests/test_remote_sensor_api.py tests/test_remote_sensor_migration.py` (on one line).
In the managed environment, API tests need the verified non-sandboxed test runner
because sandbox asyncio cross-thread wakeups block TestClient.
