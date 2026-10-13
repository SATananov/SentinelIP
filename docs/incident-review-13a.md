# Incident Review 13A

SentinelIP incidents are analyst review containers. They group references to
existing observations, detections, correlations, and exposure changes for
investigation. The source evidence remains authoritative and is not copied into
or changed by a review. A review's state, priority, confidence, and disposition
describe analyst workflow and attention; they do not prove an attack,
compromise, intrusion, vulnerability, or exploitation.

13A creates review records only when an operator explicitly asks. It adds no
automatic incident generation and no exploitation capability.

## Review workflow

Use `POST /incident-reviews` with a bounded title and optional summary,
priority, confidence, and site/scope/device attribution. The API creates a
server-generated `incident_key`; callers cannot choose table names or source
model names. State is `OPEN`, `IN_REVIEW`, or `CLOSED`. Closing sets
`closed_at` from server time; reopening clears it. Disposition uses review
language such as `EXPECTED_ACTIVITY`, `NEEDS_MONITORING`, `ACTION_REQUIRED`,
`FALSE_POSITIVE`, or `INCONCLUSIVE`.

Attach existing evidence with `POST /incident-reviews/{id}/evidence`, supplying
one allowlisted evidence type and positive ID. Duplicate links are idempotent.
The API checks that the source exists and rejects inconsistent site, scope, or
device attribution. `first_evidence_at` and `last_evidence_at` are derived from
the linked source timestamps. Removing a link only detaches it from the review;
it never deletes the source object.

The supported types are `PERIMETER_DETECTION`,
`PERIMETER_POLICY_CORRELATION`, `PERIMETER_HOST_CORRELATION`,
`EXTERNAL_EXPOSURE_CHANGE`, `THREAT_DETECTION`, `THREAT_CORRELATION`, and
`WEB_DETECTION`. Links store type, ID, observed time, added time, and an
optional short relation reason. Full evidence payloads remain in their existing
tables and APIs.

## API

- `GET /incident-reviews` supports state, priority, site, scope, device,
  disposition, and bounded limit/offset filters.
- `GET /incident-reviews/{id}` reads review metadata.
- `POST /incident-reviews` creates an explicit review.
- `PATCH /incident-reviews/{id}` updates title, summary, state, priority,
  confidence, disposition, and analyst note.
- `GET /incident-reviews/{id}/evidence` lists typed links.
- `POST /incident-reviews/{id}/evidence` attaches a persisted source.
- `DELETE /incident-reviews/{id}/evidence/{type}/{evidence_id}` detaches a
  source link.

The existing `/incidents` API continues to serve the earlier deterministic
correlation review records. Manual grouping uses `/incident-reviews` so the
legacy record model and its consumers remain compatible.

The model does not infer that grouped evidence shares a cause or actor. Analysts
must inspect each source object and its provenance before drawing conclusions.
