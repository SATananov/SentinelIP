# Phase 32R-D — Remote Task Result Envelope Close-Out

## Outcome

Phase 37 found a transport-contract mismatch in the closed Phase 32 result path.
The model allowed up to 254 network observations, with bounded fields, while the
sensor request body limit was 16 KiB. A valid /24 result could therefore be
rejected by the sensor before Core received it. This did not invalidate Phase 32
digest, inventory, or task-completion atomicity; it prevented some valid results
from reaching that atomic path.

The old documentation combined the 254-observation and field limits with a
16 KiB task-result transport cap. Those bounds were individually finite but
internally incompatible.

## Transport contract

| Request/response | Maximum |
|---|---:|
| Default sensor request | 16,384 bytes |
| `POST /sensor/tasks/{task_id}/result` request | 1,310,720 bytes (1.25 MiB) |
| Task-result response | 16,384 bytes |
| Web telemetry request | 65,536 bytes |
| DNS telemetry request | 16,384 bytes |

Only the POST task-result route receives the larger request allowance. Other
sensor routes and enrollment retain 16 KiB. The server counts streamed body
bytes rather than relying on `Content-Length` alone; exactly-at-cap is accepted,
and cap+1 is rejected with 413. The route matcher follows the route structure
and does not impose UUID syntax because FastAPI declares `task_id` as `str`.
Non-HTTP ASGI scopes bypass HTTP body-limit processing.

The client retains a 16 KiB default request bound. `CoreClient.result()` alone
uses the 1,310,720-byte request bound; its response-read bound remains 16 KiB.
Bodies remain compact JSON serialized with the production serializer and are
bounded by UTF-8 byte count. There is no request compression or chunked logical
result protocol.

## Model sizes and headroom

Current result cardinalities are at most 254 network observations and at most
21 ports plus 21 services. Measurements use the current models and production
JSON serialization (`ensure_ascii=True`, compact separators):

| Valid result shape | Serialized bytes |
|---|---:|
| Minimal 254-host result with optional fields null | 20,769 |
| Maximum valid host result | 1,184,851 |
| Maximum valid service result | 130,826 |
| Selected task-result request cap | 1,310,720 |

The maximum host case includes the maximum accepted field lengths and astral
Unicode. Body limits are bytes, not character counts. Under the current
serializer, astral Unicode has the largest verified legal per-character JSON
expansion in the tested cases. The host maximum leaves 125,869 bytes of margin,
about 10.62% of the measured payload. Regression tests construct maximum valid
host and service results and assert their serialized sizes remain within the
cap; model or serializer changes must preserve that guard or reconcile the cap.

## Runtime failure and retry behavior

- `INVALID_RESULT`: malformed scanner output or a result that violates the
  declared structure, cardinality, field, or task-type contract.
- `RESULT_TOO_LARGE`: the locally serialized result exceeds the declared result
  transport limit, or the task-result endpoint responds with HTTP 413.
- Transient delivery: network errors, timeouts, HTTP 429, and 5xx responses
  retain the same logical result for retry.
- Other permanent 4xx responses remain permanent result rejections; they are
  not relabeled as size errors.

`RESULT_TOO_LARGE` uses the existing task-failure endpoint and existing task
failure fields. Core maps the code to fixed safe history text. Active task
failure behavior remains bounded by existing state checks: completed tasks
cannot be downgraded, expired tasks remain expired, and unknown tasks or tasks
owned by another sensor are rejected. Schema version remains **46**; no
migration was required.

Transient retries do not rerun the scanner or poll another task while a result
is pending. They preserve the logical body and generate fresh authentication
headers, timestamp, and nonce per request while retaining the existing 5, 10,
30, 60-second capped backoff. A successful acknowledgement clears pending
state. Core's result transaction is unchanged: digest reservation, inventory
persistence, and task `COMPLETED` commit atomically. A matching completed digest
is acknowledged as a duplicate without reapplying inventory.

## Compatibility and boundaries

Coordinated Core and sensor deployment is required. An old sensor may still
reject a valid result above 16 KiB locally. A new sensor talking to an old Core
may receive 413 for an otherwise valid result and classify it as
`RESULT_TOO_LARGE`; an older Core may not accept the new failure code. No
capability/version negotiation was added because releases are coordinated.

The body-limit middleware executes before route authentication. A matching
result-shaped in-flight request can therefore cause up to approximately
1.25 MiB of bounded body buffering, plus Python overhead, before authentication.
This allowance is limited to the result route shape. Authenticated per-sensor
rate limits do not protect that pre-auth body read.

## Verification and limitations

The focused suite covers production client serialization, client/server cap
equality, maximum model payload guards, exact cap and cap+1, streamed-body
limits, route matcher cases, root path and trailing slash behavior, non-HTTP
scope pass-through, runtime classifications, retry/backoff, task failure
persistence, transaction atomicity, and duplicate replay. Phase 24 telemetry
limits and Phase 36 database permissions were not changed.

Direct ASGI middleware, model, client, runtime, store, and transaction seams
were exercised. Full TestClient route-layer verification remains blocked by a
local TestClient/Starlette/AnyIO stall before router entry; it is not reported as
passing. The combined direct-seam, transaction, migration, telemetry, and
Phase 36 database-permission regression selection passed **225 tests**. This
includes the result-body/runtime, remote-result atomicity, transaction-aware
persistence, device/service atomicity, migration, telemetry, and database
permission suites. The TestClient-based remote-sensor task route suite stalled
and is not included in that total. Local reportlab absence was not relevant to
these focused suites.

## Phase and schema status

Phase 37 found this Phase 32 regression instead of selecting a new roadmap
risk. With the result-envelope mismatch reconciled, Phase 32 can return to
closed status. This close-out does not select Phase 38; a fresh roadmap audit
must select any later work.

Schema remains **46**. No migration was added.

Remaining separate roadmap risks include inventory observation/history
lifecycle, historical device-list scaling, Nmap post-capture output allocation,
`/events` exact-count and deep-offset scaling, memory-only pending results across
sensor restart, remote task/history retention, and broader HTTP/TestClient
verification confidence. They are not reopened or resolved by this close-out.
