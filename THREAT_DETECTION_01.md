# THREAT DETECTION 01

Threat Detection asks **what observed pattern may represent a security threat**.
It uses persisted local SentinelIP evidence, deterministic rules, and auditable threat
records. It does not create incidents or claim confirmed phishing, malware,
exploitation, successful intrusion, or device compromise.

## Evidence hierarchy and scope

Raw observations → local detection/assessment → threat interpretation → future
correlation → future incident. These layers remain separate.

The implemented rules consume only `events` (SSH) and `web_detections` with their
existing observation snapshots/links. Service exposure findings, CVE reviews,
possible matches and inventory changes remain assessments; they are not evidence of
active exploitation or hostile reconnaissance. SentinelIP inventory scans never
become recon threats through this layer. DNS observations are not queried.

`services/threat_models.py` defines immutable typed SSH and web evidence and
`ThreatDetection`. It reuses existing finding severity/confidence enums. Only
ANOMALOUS and SUSPECTED states exist in the model and database constraint. CONFIRMED
and DETECTED are intentionally unavailable here. Confidence describes confidence in
the observed pattern, not confidence in consequences or intent.

## Rules, version 1

| Threat | Trigger | State | Severity | Confidence |
| --- | --- | --- | --- | --- |
| SSH_BRUTE_FORCE_THREAT | Existing SSHDetector returns ALERT for a failed-login row after replay of same-source failed-login rows in its window | SUSPECTED | MEDIUM | HIGH |
| SUSPICIOUS_AUTH_ACTIVITY | Existing SSHDetector returns WARNING for failed authentication, or WARNING/ALERT for preauth activity | ANOMALOUS | LOW for isolated username review; MEDIUM for repeated activity | MEDIUM |
| WEB_CREDENTIAL_FLOW_THREAT | Persisted CROSS_DOMAIN_LOGIN_REDIRECT review | SUSPECTED | MEDIUM | MEDIUM |

### SSH semantics

The adapter constructs a fresh existing `SSHDetector` and replays each eligible
persisted row once, ordered by timestamp then event ID. Defaults remain five events
within 60 seconds, inclusive, with the existing three-event warning and existing
case-insensitive username policy. No second username list or threshold system is
introduced; `services/detector.py` is unchanged. Usernames are taken from persisted
fields when supplied, even if an older collector did not pass them to its live
in-memory detector. Persisted severity/message text is not trusted as the trigger.

`event_count` is the collector's running count, **not a multiplicity**. It is retained
for audit but never summed or used to simulate additional attempts. One row with
count 999 cannot manufacture a brute-force threat. LOGIN_SUCCESS and
CONNECTION_CLOSED create no threat and erase no history. Preauth activity never
becomes brute force or recon automatically.

Source IP is observed network-source evidence, not a permanent attacker identity.
There is no reputation/geolocation lookup. The legacy events table lacks monitored
host/device/sensor identity; SSH threats leave device and sensor null rather than
infer them from the source address. Multi-collector attribution is future work.
The source query matches the persisted IP representation; outputs are validated
and canonicalized as literal IP addresses without resolution.

Legacy SSH timestamps are naive local wall-clock values. The adapter preserves
that clock basis without silently labeling it UTC. Aware timestamps normalize to
UTC; naive and aware histories never mix. No local timezone/DST reconstruction is
attempted. Equal timestamp order uses persisted ID, matching storage order rather
than asserting subsecond causal order.

### Web flow and strengthening

A cross-domain credential review anchors a threat by its **primary observation ID**,
sensor/device binding and threat rule version. LOGIN_DOMAIN_REVIEW and redirect-chain
review alone create no threat. SUSPICIOUS_DOWNLOAD_FLOW alone also creates no threat.

A download review may add evidence to the anchored threat only when:

- Its snapshot explicitly includes the credential review's primary observation ID.
- Sensor, device binding, explicit session and tab context match exactly.
- The download follows the anchor in observation order and is at most 300 seconds later.

Both missing tab IDs permit the existing session-only fallback; missing session
IDs prevent strengthening. A missing tab never joins a known tab. No matching solely
by domain/time is allowed. The existing Browser Sensor's absent tab IDs remain a
known weaker-context limitation; no browser code changes were made.

Strengthening appends the linked web detection and observation snapshots and updates
last_seen; it does **not** increase severity/confidence or change SUSPECTED. It never
means malware. Web reasons and recommendations ask reviewers to verify whether
credential entry and the destination were expected; legitimate sign-in flows can
produce these patterns.

Evaluating either the cross-domain review or its linked download finds the same
anchor and known supporting downloads. If the cross-domain review has not yet been
persisted, evaluating the download returns no threat; explicitly re-evaluating after
it exists can create the anchored threat. Nothing automatically runs web detection.

## Explicit service API and bounds

```python
from services.threat_engine import ThreatEngine

engine = ThreatEngine(db_path)
ssh_threats = engine.evaluate_ssh_event(event_id)
web_threats = engine.evaluate_web_detection(web_detection_id)
# Equivalent typed entry point:
results = engine.evaluate_evidence("SSH_EVENT", event_id)
```

Methods return a list containing zero or one durable threat record. Missing source
IDs and malformed evidence fail clearly. FINDING, CVE_MATCH and CHANGE are explicit
deferred categories returning no candidates without loading or interpreting them.
Unknown categories are rejected.

SSH loads only the primary source/type's 60-second window. Web loads only detection
records directly linked to the bounded observation set or credential anchor, then
checks the five-minute observation-time window. Every related-record query is capped
at 1,000 rows; overflow fails explicitly rather than silently truncating evidence.
Web snapshots are bounded to 1,000 observations and two million characters. Raw
web observations, unbounded source history, DNS records and external data are not
loaded. Existing indexed observation links and new indexes support these reads.

No background worker, ingestion hook, scheduler, HTTP endpoint or frontend is added.
Local read helpers are `database.threats.get_threat` and `list_threats`. Collection,
telemetry ingestion, existing detectors and assessment behavior remain unchanged.

## Persistence, identity and history

Additive migration **23** creates `threat_detections`, `threat_evidence` and indexes.
Existing tables/data remain intact. Migration assertions are extended; the existing
migration rollback test moves its synthetic next migration to version 24.

Threat evidence uses explicit SSH_EVENT/WEB_DETECTION types, original evidence IDs,
source-specific foreign-key columns and immutable structured snapshots. Primary
evidence type/ID identify the corresponding audit link. Foreign keys set live links
to null on a later explicit source deletion; original IDs/snapshots remain for audit.
There is no destructive cleanup or automatic resolution. Audit snapshots may outlive
source retention; a threat-retention policy is deferred.

Stable keys include threat type, rule/version, relevant source or sensor/device
identity, and an evidence anchor. SSH anchors are persisted primary event IDs, so
re-evaluating the same event is idempotent; different qualifying events remain
separate historical evaluations rather than one permanent IP identity. Web anchors
are credential primary observation IDs, so supporting downloads share the same threat.
No timestamps alone identify a threat.

The engine holds one SQLite write transaction across source reads, evaluation and
persistence. Writes validate typed snapshots against source evidence, atomically
upsert a unique stable key and append unique evidence links. Concurrent equivalent
writes cannot duplicate a threat. Existing snapshots cannot be overwritten: a source
mutation that conflicts with an audit snapshot rolls back the entire evaluation.
First_seen/created_at remain stable, last_seen/updated_at advance monotonically using
UTC evaluation time. Source timestamps remain in snapshots. Mutable web last_seen
bookkeeping is deliberately excluded from immutable evidence identity.

Manual lifecycle is deferred. No threat is resolved from absence, a successful login,
a missing observation, or a future assessment result. Evidence strengthening never
rewrites historical threat conclusions.

## Privacy and recommendations

SSH snapshots contain only ID, source IP, username if available, event type, stored
running count and timestamp. Raw log messages/lines are excluded from reads. Web
snapshots contain review identity/type/state/severity/confidence, sensor/device,
hostname, reason, rule/version, creation evaluation time and allowlisted immutable
observation snapshots (including their observed/received times and context).
No paths, query strings, page content, arbitrary metadata, form values, cookies or
credentials are required or copied.

Recommendations are non-destructive text: review the source/destination activity,
verify expected authentication or credential entry, and manually assess controls.
No remediation is performed.

## Deferred capabilities and prohibitions

Deferred: service-exposure threat mapping, CVE-to-threat mapping, recon, malware
execution, C2, lateral movement, ransomware, exfiltration, DoS/DDoS, cross-service
credential stuffing, zero-day exploitation, endpoint compromise, confirmed phishing
or malware, incident models, manual lifecycle, API/frontend, automatic evaluation,
threat-retention policy and cross-source correlation.

No exploitation, credential attack, network scan, website fetch, browser automation,
DNS enrichment, packet capture, TLS/DoH interception, external intelligence,
IP/domain reputation, geolocation, browser blocking, firewall/network configuration,
automated remediation or runtime AI is added or invoked. All interpretation is local,
deterministic and evidence-based.

## Tests

From the repository root using existing `.venv` dependencies:

```sh
.venv/bin/python -m pytest -q tests/test_threat_models.py tests/test_threat_rules.py tests/test_database_threats.py tests/test_threat_engine.py tests/test_threat_integration.py
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q dns-sensor/tests
```

From `browser-extension/`: `npm test`; `node --test --test-isolation=none` exposes all
11 individual cases on Node versions whose default reporter summarizes test files.
Threat tests use deterministic synthetic evidence and temporary databases. The
combined SSH/web integration explicitly blocks connections and hostname resolution.
