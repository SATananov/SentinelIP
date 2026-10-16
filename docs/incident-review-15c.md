# Incident Review 15C — Source-Surface Start Review

15C adds deliberate **Start Review** actions for the seven canonical 15B evidence types. Each action opens the existing `CreateIncidentReviewForm`; it does not create a review until the analyst submits.

## Source actions and identity

| Source surface | Canonical evidence type | Record ID used |
| --- | --- | --- |
| Threat detail in Security Review | `THREAT_DETECTION` | Threat detection `id` |
| Correlation detail in Security Review | `THREAT_CORRELATION` | Correlation `id` |
| External Activity, repeated detections | `PERIMETER_DETECTION` | Perimeter detection `id`, never the related event ID |
| External Activity, policy correlations | `PERIMETER_POLICY_CORRELATION` | Policy correlation `id` |
| External Activity, bounded host-correlation list | `PERIMETER_HOST_CORRELATION` | Host correlation `id`, never device/event ID |
| External Exposure, recent changes | `EXTERNAL_EXPOSURE_CHANGE` | Change record `id`; inventory rows have no action |
| Security Review, recent web detections | `WEB_DETECTION` | Web detection `id` |

The web-detection list uses `GET /web-detections` with limit/offset bounds. Its response is a compact projection of ID, detection type/state, device/hostname, and first/last timestamps. It omits structured evidence payloads. The host-correlation list is bounded to eight rows and uses the existing host-correlation API; it is independent of the dashboard refresh timer. The web list is fetched once per mount, not polled. Its current global newest-first query scans and uses a temporary sort; no index migration is introduced in this phase.

## Shared intake flow

`App.jsx` owns a tokenized intake request. The only identity passed to the form is the canonical `evidence_type` plus the positive source record `evidence_id`. A neutral display label and allowlisted read-only source-context fields are separate display data. Source records themselves are never forwarded or mutable.

Threats and correlations expose the action in their selected detail panel. Perimeter detections, perimeter policy correlations, host correlations, and exposure changes expose it on their compact source rows. Web detections expose it on their bounded rows. Legacy Security Incidents, perimeter event rows, and exposure inventory rows do not expose the action.

Manual Create Review remains independent and continues to call `POST /incident-reviews`. Promotion mode reuses the same form and submits exactly once to `POST /incident-reviews/from-evidence`. The response must echo the initiating type and ID before the existing create-success integration runs. No second attach request is made.

Review title and summary are entered by the analyst. Priority and review confidence remain analyst-controlled with the existing MEDIUM defaults. Source severity, confidence, category, and attribution are not copied into review fields. Available source context may be shown read-only; review attribution remains analyst-selected and server-validated.

## Cancel, replacement, and success

Cancel clears the tokenized intake request and unmounts the form, clearing its draft without making an API call or changing the selected review. A new token keys each promotion form instance, so a later source action starts with a clean draft and evidence reference. While a promotion is submitting, competing Start Review buttons are disabled and the shared intake callback rejects replacements.

After a matching successful response, the existing flow upserts the review, invalidates an older list request, selects through the existing review request guard, opens the existing Incident Review detail, and sends the targeted Analyst Operations refresh signal. Activity and Trends are not explicitly refreshed. On error, the source remains unchanged, form values and evidence context remain visible, and no fallback or attach call occurs.

## Read-only and schema boundary

Start Review does not acknowledge, handle, promote, or otherwise mutate source records. The only write is the 15B atomic review-plus-evidence operation after explicit form submission. No migration is added; schema remains version 43. The 15B transaction contract, manual 15A path, and existing legacy Security Incidents remain unchanged.

Phase 15 can close when manual creation still works, all seven record-specific actions reach this shared form with the correct stable ID, promotion remains atomic, cancel/error paths have no source side effects, and the existing guarded detail workflow opens the created review.
