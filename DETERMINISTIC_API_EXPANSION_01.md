# DETERMINISTIC API EXPANSION 01

SentinelIP exposes the established security interpretation layers through a
bounded read-only API.

## Routes

Threats:
- `GET /threats`
- `GET /threats/{id}`

Correlations:
- `GET /correlations`
- `GET /correlations/{id}`

Incidents:
- `GET /incidents`
- `GET /incidents/{id}`

## Pagination

Collection routes use `limit` 1–100 (default 20) and `offset` >= 0.
Responses include total, count, limit, offset, selected filters, and records.

## Filters

Threats: type, state, severity, confidence, source IP, device ID, sensor ID.
Correlations: type, state, severity, confidence, source IP, device ID, sensor ID.
Incidents: type, status, priority.

Enum-like filters are constrained by FastAPI/Literal validation.

## Boundary

This API is a presentation/read layer. It does not run detection or correlation,
create incidents, mutate security interpretation records, confirm compromise,
confirm phishing, declare malware, perform remediation, call external
intelligence, or perform network activity.

Existing telemetry POST endpoints and authorized-network management endpoints
remain unchanged. The new threat/correlation/incident routes are GET only.
