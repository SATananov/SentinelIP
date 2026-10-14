# Incident Review 13B

13B adds a read-only related-evidence suggestion endpoint and an explicit
operator workflow for attaching or detaching evidence from 13A incident
reviews. Suggestions are review aids. They do not establish a causal
relationship, attack, compromise, intrusion, exploitation, or vulnerability.
Loading suggestions never attaches evidence, creates a review, changes a
disposition, or escalates a threat.

## Deterministic matching

The endpoint considers only the seven evidence types supported by 13A:
`PERIMETER_DETECTION`, `PERIMETER_POLICY_CORRELATION`,
`PERIMETER_HOST_CORRELATION`, `EXTERNAL_EXPOSURE_CHANGE`,
`THREAT_DETECTION`, `THREAT_CORRELATION`, and `WEB_DETECTION`.

A source must exist and have attribution that can be resolved using the same
existing site, authorized-scope, and device relationships used by 13A. Missing
attribution is never a wildcard. Candidate attribution must be compatible with
the review and all available linked evidence; conflicting or ambiguous
attribution is excluded. The strongest exact field on the review determines
the plain-language match reason, in this order: device, scope, then site.
Linked evidence further constrains compatibility and supplies an attribution
anchor when the review has no attribution of its own. No ownership or
cross-domain relationship is inferred.

Suggestions are limited to the inclusive interval from 30 minutes before
`first_evidence_at` through 30 minutes after `last_evidence_at`. Timestamps are
compared as instants; naive timestamps are treated as UTC, matching 13A. A
review without linked evidence timestamps returns no suggestions. `created_at`
is not used as a time anchor.

## API and workflow

`GET /incident-reviews/{incident_id}/related-evidence` accepts `limit` from 1
to 100 (default 100) and an optional `evidence_type` from the seven-value
allowlist. It returns only `evidence_type`, `evidence_id`, `observed_at`,
`source_status`, `already_linked`, and `match_reason`, with stable ordering by
`observed_at` descending, `evidence_type` ascending, then `evidence_id`
ascending. Up to 100 suggestions are returned. Database work scans at most
1,000 in-window records per selected evidence type.

Only available source rows are suggested. Existing stale links remain visible
in the 13A evidence list with `source_status: MISSING`; they are not returned as
new suggestions. An analyst must choose **Attach** for an available suggestion.
The UI calls the existing 13A attach endpoint, which remains responsible for
source existence, attribution validation, duplicate idempotency, and evidence
time recomputation. Detach uses the existing 13A endpoint and preserves the
source record.
