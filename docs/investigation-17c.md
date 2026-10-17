# Phase 17C — Investigation Search Surface

## Purpose

The Investigation Search panel at the top of the main workspace provides an explicit, exact identifier lookup across the bounded 17B API. The operator chooses a query type first; the UI does not provide free-text or fuzzy search.

## Visible query types and validation

The panel exposes IP address, device ID, sensor ID, site ID, scope ID, Incident Review ID, Incident Review key, Sensor Task ID, and Evidence reference. It performs client-side validation for canonical IPv4, positive decimal IDs, `IR-` plus 32 lowercase hexadecimal characters, canonical lowercase UUIDs, and positive evidence IDs. The backend remains authoritative.

Evidence lookup uses a separate evidence type dropdown and positive ID input. Supported types are perimeter detection, perimeter policy correlation, perimeter host correlation, external exposure change, threat detection, and threat correlation. `WEB_DETECTION` is intentionally not offered.

## API and request handling

`investigationApi.js` sends only GET requests to `/investigation-lookup`, with `cache: no-store`, an optional AbortSignal, and explicit query parameters. Standard lookups send `query_type` and `value`; evidence lookups send `query_type`, `evidence_type`, and `evidence_id`.

Submitting aborts the previous request. Type or input changes invalidate the current generation and clear prior results. Stale successes and errors are ignored. No polling, query/result browser storage, or browser-history feature is added.

## Results

The compact result cards render only fixed 17B fields: typed entity label, backend label/context, explicit site/scope/device/sensor context, and a neutral timestamp. The UI does not render arbitrary response fields or raw domain payloads. Empty results say “No matching record found.” A truncated response displays that more records exist beyond the bounded set. API errors are reduced to concise status messages.

## Navigation

Open actions dispatch a typed result through App-level state with a monotonically increasing navigation nonce, so opening the same entity again is still a new request. No router or backend-provided URL is used. Existing Network Workspace, Remote Sensor Fleet, Incident Review, threat detail, perimeter detail, and exposure detail surfaces are reused through narrow selection hooks. Legacy events open the existing Events panel filtered by the exact IP lookup context; the exact event is highlighted if it is on the current page. If it is not, the panel explains that existing filters and pagination are needed to locate it.

Unsupported destination kinds have no Open action and display “Detail navigation unavailable.” Navigation failures remain in the relevant existing panel and do not trigger a fallback lookup against broad domain APIs.

## Boundaries

17C adds no mutations, arbitrary search, task actions, or direct-local bypass. The lookup depends on the direct-local 17B endpoint. `WEB_DETECTION` remains deferred. Backend contract and schema are unchanged; schema remains version 43.
