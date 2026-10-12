# WEB DETECTION 01

Web Detection answers **what observed web behavior deserves review** using persisted
`web_observations` only. It does not establish phishing, malicious domains, malware,
compromise, or incidents. REVIEW is preferred over false certainty.

## Architecture

Persisted observation → immutable allowlisted `WebEvidence` → pure deterministic
rules → immutable `WebDetection` candidate → atomic durable `web_detections` review.
Observations remain facts; detections are interpretations with explicit rules;
stored reviews retain their explanations and provenance. No raw observation is
rewritten by evaluation.

Entry point (explicit local application call, no network):

```python
from services.web_detection_engine import WebDetectionEngine

reviews = WebDetectionEngine(db_path).evaluate_observation(observation_id)
```

The caller supplies the ID of an existing web observation. Unknown IDs fail clearly.
Evaluation is explicit: no background worker, ingestion hook, scheduled task or API
endpoint is added. Detection failure cannot affect telemetry ingestion. To evaluate
multiple observations, call the service explicitly for each selected ID. Within one
evaluation all candidate writes and observation links commit atomically.

`database.web_detections.get_web_detection` and `list_web_detections` provide local
read access. No frontend or active browsing functionality is involved.

## Rules, version 1

| Detection | Evidence | Severity | Confidence | State |
| --- | --- | --- | --- | --- |
| CROSS_DOMAIN_LOGIN_REDIRECT | Explicit different-hostname REDIRECT landing at the credential-form hostname; password or login signal, on that record or subsequently in matching context within 120 seconds | MEDIUM | MEDIUM | REVIEW |
| LOGIN_DOMAIN_REVIEW | Password-form signal without the stronger cross-domain rule for that observation | LOW | MEDIUM | REVIEW |
| REDIRECT_CHAIN_REVIEW | At least two linked REDIRECT records involving at least three distinct normalized hostnames in matching context within 120 seconds | LOW | MEDIUM | REVIEW |
| SUSPICIOUS_DOWNLOAD_FLOW | Explicit DOWNLOAD_SIGNAL with download flag following a password/login form or different-hostname REDIRECT in matching context within 300 seconds | MEDIUM | MEDIUM | REVIEW |

Different hostnames include subdomains: `example.test` and `login.example.test`
are different hostnames. This says nothing about ownership or registrable domains;
legitimate SSO and sign-in flows commonly cross hostnames. No homemade PSL logic is
used. Redirect evidence requires both endpoints and a landing hostname equal to the
reported destination. Referrer alone is not redirect evidence.

Cross-domain credential review selects the latest matching redirect and does not
jump across an observed navigation/redirect away from the landing hostname.
Redirect chains walk linked edges backward, stopping at an incompatible redirect
or navigation. A→B→A does not meet the three-hostname threshold. Non-redirect events
cannot manufacture edges.

Download flow review selects the latest eligible credential or redirect signal in
the five-minute context. This is temporal flow context, not proof of causation or
analysis of a file. A standalone download produces no detection. A navigation,
standalone redirect, IDN/punycode hostname or HTTPS/HTTP scheme alone produces no
threat verdict. LOGIN_DOMAIN_REVIEW can be noisy; it remains LOW and creates no
separate operational finding. Login-only signals do not trigger that inventory rule.

## Context, ordering and bounds

Multi-event rules match sensor ID, device binding (including null), browser session
ID, and tab ID. When tab IDs are absent on **both** records, matching uses the explicit
session instead. A missing tab never joins a known tab. A missing or blank session
disables multi-event rules, even if a tab or hostname matches. Context IDs are opaque;
no identity is guessed from time or hostname. Only browser evidence is accepted;
DNS observations are never queried.

Windows use `observed_at`, normalized to UTC, with inclusive upper bounds. Future
records are excluded. Equal timestamps use persisted observation ID as a deterministic
tie-breaker: this is storage order, not a claim of subsecond causality (existing web
persistence stores timestamps to seconds). The primary observation anchors each
window. Results are independent of input collection ordering.

The engine selects at most five minutes of explicit matching context, using an
expression index that handles timezone offsets. More than 1,000 context records
causes an explicit error with no detections written; evidence is not silently
truncated. Raw paths and arbitrary metadata are excluded even from database read
projections. There is no unbounded history or cross-source correlation.

## Persistence and the context contract fix

Migration 21 additively preserves `browser_session_id` and `tab_id` in
`web_observations`, plus a context/time index. The existing API/model/ingestion
already accepted those fields, but the database writer dropped them. The writer now
stores supplied values. This is a proven persistence gap, not a new sensor contract.
Old observations retain null context; no backfill or reconstruction is attempted.

Browser Sensor 01 currently supplies a browser session ID; its builders do not emit
`tab_id` despite receiving a `tabId` option. The browser extension is unchanged in
this phase. Consequently its observations may use the allowed **session-only**
fallback, which cannot distinguish tabs and is weaker evidence. Tab-specific
isolation applies only when a producer supplies persisted tab IDs. Tests exercise
both explicit-tab and session-only contexts. No claim of browser-wide tab isolation
is made for context the sensor never emitted.

Migration 22 adds `web_detections`, `web_detection_observations` and indexes. Existing
migration versions are untouched; upgrades are transactional and repeat-safe.
Foreign keys link sensor/device/observations. The relation table is used because
three rules genuinely use multiple observations.

Stable keys hash rule ID/version, sensor/device, primary observation ID, hostname,
and the sorted supporting observation IDs. Timestamps alone never identify a review.
Equivalent evaluations atomically upsert one record, retain first_seen/created_at
and original evidence, and monotonically advance last_seen/updated_at using evaluation
time. Evidence snapshots separately preserve observed/received timestamps. Repeated
source events with distinct persisted IDs remain distinct evidence. Rule version or
supporting observation-set changes can produce a new historical review; there is no
automatic resolution or deletion when later evidence changes or disappears.

The engine revalidates every evidence snapshot against persisted rows within the
write transaction. Missing or modified evidence aborts the entire batch. Concurrent
equivalent writes share one unique stable key.

Explicit later deletion of raw observations nulls their live foreign-key references;
minimal evidence snapshots retain original observation IDs and facts so review
history remains explainable. Detection adds no deletion/retention job. Review
snapshots can therefore outlive raw observations; their retention lifecycle requires
an explicit future policy. Existing manual finding states are unaffected because
this phase does not write `findings` at all.

## Privacy, limitations and deferred work

Snapshots contain only observation ID, sensor/device identity, normalized hostname,
event type, observed/received times, explicit session/tab IDs, redirect endpoints,
structural boolean signals and browser source. Each review also stores rule identity,
version, reason, severity and confidence. These are sensitive browsing-related facts;
access should remain local and controlled.

No page content, titles, HTML, credentials, form values, cookies, URLs, paths, query
strings, browser history, screenshots or raw metadata are required or copied.
DOMAIN_ONLY observations work. No website fetch, form submission, browser automation,
DNS lookup, packet capture, interception, proxying, file download or execution occurs.
No external reputation, intelligence, domain-age or brand data is consulted. HTTPS
is not treated as proof of trust, HTTP as proof of malice, password forms as phishing,
or download signals as malware.

Deferred: lookalike/confusable/brand rules (punycode alone is not a threat signal),
domain registration age, TLS certificate assessment, cross-source correlation,
operational finding integration, manual detection lifecycle, read API/frontend,
automatic evaluation and review-retention policy. No browser blocking is implemented.

## Verification

With existing repository dependencies in `.venv`, from the repository root:

```sh
.venv/bin/python -m pytest -q tests/test_web_detection_models.py tests/test_web_detection_rules.py tests/test_database_web_detections.py tests/test_web_detection_engine.py tests/test_web_detection_integration.py
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q dns-sensor/tests
```

Browser regression: run `npm test` from `browser-extension/`. On Node versions
reporting test files rather than individual cases, `node --test --test-isolation=none`
shows all 11 cases. Tests use synthetic persisted evidence and temporary SQLite
files; integration guards forbid external connections, lookups and DNS evidence access.
