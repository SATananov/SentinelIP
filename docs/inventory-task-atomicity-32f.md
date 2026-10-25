# Phase 32F — Inventory Task Atomicity Close-Out

## Outcome

Phase 31 selected partial persistence during inventory scan result processing
as the strongest remaining production correctness risk. Phase 32 closes that
risk at the inventory service boundary and at remote task result completion.

For a validated remote inventory task result, the result digest, inventory
state, observations, change history, and task `COMPLETED` state participate in
one SQLite transaction. They commit together or roll back together. A result is
**transactionally applied once for a successfully committed task result, with
replay-safe duplicate acknowledgement**. This is not a distributed exactly-once
delivery guarantee.

Local device and service inventory processing also commits each result as one
service-owned transaction, or participates in an enclosing caller transaction.

## Phase 32 implementation

- **32A — Design:** Identified independent lower-level commits and the early
  remote task digest reservation as the partial-write window. Locked a shared
  SQLite transaction for remote task success; scanner execution, DNS, external
  exposure assessment, and risk/CVE work remain outside it.
- **32B — Persistence seams:** Inventory, service, observation, and change
  helpers accept an optional SQLite connection. With a supplied connection the
  helper uses it without initialization, opening, committing, rolling back, or
  closing it. Without one, existing standalone ownership remains.
- **32C — Device inventory:** `DeviceInventoryService.process_scan()` validates
  normalized input, then in standalone mode initializes the DB, opens one
  connection, starts `BEGIN IMMEDIATE`, performs authoritative reads and all
  device writes/reconciliation, and commits once. A caller-supplied connection
  remains caller-owned. Reconciliation reads only currently `ONLINE` devices
  for the network; omitted devices receive disappearance changes and become
  `OFFLINE` in the same transaction. An empty valid scan retains the prior
  behavior of taking all currently online devices offline.
- **32D — Service inventory:** `ServiceInventoryService.process_result()` uses
  the same owned-versus-caller-owned transaction contract for port/service
  state, observations, and changes. It does not reconcile absent ports/services.
  Scanner and DNS work, external exposure recording, and risk/CVE processing
  remain separate operations.
- **32E — Remote results:** The result coordinator starts `BEGIN IMMEDIATE`,
  reloads and revalidates task ownership, state, expiry, type, assignment,
  scope/target, and digest state, then reserves the digest, applies device or
  service inventory using the same connection, marks the task `COMPLETED`, and
  commits once.

Standalone transaction owners initialize schema before opening the processing
transaction. The shared-connection path does not initialize schema or alter
the caller's transaction or connection settings. SQLite foreign keys are
enabled by the production connection factory; transaction owners configure
`sqlite3.Row` where the processing code requires it.

## Remote task result semantics

The result digest is SHA-256 over the canonical serialized submitted result
body. It identifies application-level result content; it is separate from the
sensor transport nonce, which is fresh for each authenticated HTTP request.

- First valid result for a `RUNNING` task with no digest: digest, inventory, and
  `COMPLETED` state commit atomically.
- Completed task with the same digest and matching task type: return a duplicate
  success acknowledgement without invoking inventory processing again.
- Completed task with a different digest: reject with conflict; preserve the
  original result and task state.
- Legacy `RUNNING` with a digest, `FAILED` with a digest, or `COMPLETED` without
  an identifiable matching digest: reject conservatively. Do not infer result
  identity or reapply inventory.
- Permanent semantic rejection: roll back/no-op the success transaction and
  record task failure separately, without consuming a success digest or
  applying inventory. Failed tasks are not revived; an operator must issue a
  new task.
- Transient storage/processing failure: roll back the result transaction and
  return a retryable server error. No digest or inventory effect is intended to
  remain, and an otherwise eligible task remains retryable.
- If commit reports an error, the coordinator reads task state through a fresh
  connection. `COMPLETED` plus matching digest is acknowledged; `RUNNING` plus
  null digest is retryable; other or unreadable states fail safely as ambiguous.
  Rollback and connection cleanup errors are guarded so they do not mask the
  original failure or skip that reread.

`BEGIN IMMEDIATE` serializes competing result writers. Concurrent identical
submissions therefore apply once and the later writer acknowledges the
completed digest. Competing different results have one winner; the other
conflicts. A lock acquisition/timeout failure is retryable. SQLite writer
contention is still possible; this work does not claim lock-free operation or a
hard transaction-latency bound.

## Sensor delivery behavior

After execution, the sensor retains one logical result body in memory until Core
acknowledges it or permanently rejects it. Transient delivery failures (network
errors/timeouts and retryable HTTP responses such as 5xx and 429) retry that
same body with newly generated authentication headers, timestamp, and nonce on
each request.
Delivery failure does not report task execution failure or rerun the scanner.
Permanent rejection clears the pending result; actual local execution failure
continues to use the task-failure path.

Result delivery uses a capped backoff of **5, 10, 30, 60, 60… seconds**. Its
state is independent of heartbeat/polling backoff. Heartbeat success does not
reset it; heartbeat failure or exception does not prevent an already-due result
attempt. While a result is pending the runtime does not claim another task that
could overwrite it. Successful delivery or permanent rejection clears the
pending body and resets result backoff.

There is no durable sensor result spool. If the sensor process exits before
delivery succeeds, the in-memory result is lost; the task may expire and a new
task may be needed. This design does not provide restart-durable or distributed
exactly-once delivery.

## Boundaries and remaining risks

- The schema remains **46**. No migration, index, result-attempt table, or
  schema change was added.
- Existing task type validation, target/scope authorization, capability checks,
  nonce admission, and rate limits remain in force. The original 16 KiB sensor
  request limit was too small for all valid task results at the 254-observation
  and service cardinality bounds; Phase 32R reconciles the transport contract.
  See [Phase 32R-D](remote-task-result-envelope-32r-d.md) for exact request and
  response limits, measured payload sizes, and runtime failure classification.
- Local public discovery's host-discovery and service-discovery stages are not
  one cross-stage transaction. Each inventory result is atomic at its own
  service boundary.
- Scanner execution, DNS, external exposure recording, and risk/CVE work are
  intentionally separate domains. Their effects are not rolled back with the
  inventory transaction.
- SQLite writer contention may produce retryable failures. No hard latency or
  lock-free guarantee is made.
- The sensor result retry is memory-only; process restart may lose an
  undelivered completed result.
- No distributed exactly-once delivery guarantee exists. A committed result is
  applied transactionally once, and replay of its matching digest is a no-op.

## Verification evidence

The Phase 32 verification set covers transaction-aware helpers, device and
service atomicity, remote task coordinator success/replay/conflict, digest and
completion write failures, mid-inventory rollback and same-task retry, commit
ambiguity, rollback/close failure, legacy states, authorization rechecks,
concurrent identical/different submissions, sensor same-body retries, fresh
nonce generation, permanent rejection, execution-vs-delivery failure, capped
backoff, and heartbeat starvation/recovery. Migration tests verify schema 46.
Compile/import checks cover the changed transaction and runtime modules.

Direct coordinator, store, service, and sensor tests provide the Phase 32
transaction and retry evidence. The known TestClient/AnyIO issue can stall before
router entry, so end-to-end HTTP middleware/auth integration was not verified
through TestClient and is not reported as passing. `reportlab==5.0.1` is declared
in `requirements.txt`; it is absent from this environment and can block
unrelated `api.main`-dependent test collection. Direct Phase 32 tests avoid
that import path. These are environment verification limits, not claims of a
passing blocked suite.

## Phase 31 risk closure

Before Phase 32, lower-level writes could commit independently, while remote
task processing committed the result digest before inventory and task completion.
A later failure could leave mixed inventory state and make same-task resubmission
unavailable. After Phase 32, helper writes compose on one connection, device and
service results are atomic, and remote digest + inventory + completion share a
single transaction. Transient failure rolls back and leaves eligible work
retryable; a successful result replay is acknowledged without reapplication.

The closure is bounded to the persisted inventory/task transaction. It does not
add a durable result queue or claim distributed exactly-once delivery.
