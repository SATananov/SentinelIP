# INCREMENTAL DASHBOARD EXPANSION 01

SentinelIP now presents the persisted deterministic security pipeline in the
existing React dashboard.

The expansion is intentionally incremental. Existing event monitoring,
timeline analytics, filters, pagination, exports, and alert views remain in
place.

## Added read-only views

The dashboard displays:

- Threat count and recent persisted threat records
- Correlation count and recent persisted correlation records
- Incident Review count and recent persisted incident records
- Read-only detail inspection for each record

The UI uses only the existing GET routes:

- `GET /threats`
- `GET /threats/{id}`
- `GET /correlations`
- `GET /correlations/{id}`
- `GET /incidents`
- `GET /incidents/{id}`

## Interpretation boundary

The dashboard presents backend state. It does not create security meaning.

It does not run threat detection, run correlation, create incidents, mutate
security records, confirm compromise or phishing, declare malware, identify an
attacker, or perform remediation.

The existing API/backend remains authoritative.

## Refresh behavior

Security-layer collection data refreshes when the existing dashboard refresh
cycle completes. Detail records are loaded only when the user selects a
persisted record.

## Scope

This phase adds no backend migration, no backend behavior, no sensor behavior,
and no new external dependency.
