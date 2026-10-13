# External Exposure 12B — Authorized Public Exposure Assessment

12B adds deterministic review classification on top of the factual exposure evidence introduced in 12A. It does not add a scanner, enlarge authorization, perform exploit checks, or infer vulnerability or compromise.

## Explicit expectation policy

A public scope may have one bounded `ALLOWLIST` policy containing up to 64 expected TCP ports. The policy is valid only for an enabled, explicitly authorized `PUBLIC_IPV4`, `PUBLIC_CIDR`, or `HOSTNAME` scope. It cannot contain a raw target, scanner flags, CVE claims, or executable input.

- No policy: exposure classification is `REVIEW`.
- Port present in the explicit expected-port list: `EXPECTED`.
- Port absent from an existing expected-port list: `UNEXPECTED`.

An empty explicit list is meaningful: the operator has declared that no externally exposed TCP ports are expected for that authorized scope, so any observed exposure is `UNEXPECTED`.

The words `EXPECTED` and `UNEXPECTED` describe operator-declared exposure intent only. They do **not** mean safe/unsafe, vulnerable/not vulnerable, exploitable, attacked, or compromised.

## Assessment lifecycle

Migration 38 backfills existing 12A exposures as `REVIEW` so pre-existing factual evidence is visible immediately. Every successful authorized public service observation is assessed after 12A persists the exposure. Creating or replacing a scope policy deterministically reassesses the scope's currently persisted exposures. Deleting the policy returns those exposures to `REVIEW`.

The current assessment stores the exposure identity, scope, optional policy reference, classification, deterministic rule ID/version, reason, and assessment timestamp. Exposure evidence remains the authoritative factual observation history.

## API

Policy configuration:

- `GET /scopes/{scope_id}/external-exposure-policy`
- `PUT /scopes/{scope_id}/external-exposure-policy`
- `DELETE /scopes/{scope_id}/external-exposure-policy`

Assessment review is read-only:

- `GET /external-exposure-assessments`
- `GET /external-exposure-assessments/{assessment_id}`

Assessment listing is bounded and can filter by scope, classification, public IPv4 and TCP port.

## Safety boundary

12B operates only on already persisted 12A evidence from explicitly authorized public scopes. It adds no target input to scanning, no Internet enumeration, no shell or arbitrary Nmap path, no exploit checks, no credential attempts and no CVE assertion. Service fingerprints are displayed as evidence but do not change expected/unexpected classification in 12B.
