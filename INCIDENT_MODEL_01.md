# INCIDENT MODEL 01

SentinelIP Incident Model 01 introduces an explicit investigation object above the deterministic correlation layer.

Hierarchy:

Raw Observation → Detection → Threat → Correlation → Incident Review

An Incident in this version is an explicitly opened investigation record. It is not proof of compromise, phishing, malware, successful intrusion, attacker identity, or exploitation.

Creation is explicit with `IncidentEngine(db_path).open_review([correlation_id])`. There is no background worker or automatic ingestion hook.

Version 01 supports status `OPEN`, priority `MEDIUM`, and types `AUTHENTICATION_REVIEW`, `WEB_ACTIVITY_REVIEW`, and `MULTI_SIGNAL_REVIEW`.

Each incident stores an immutable safe snapshot of selected correlations. If a source correlation is later removed, its live foreign key may become NULL while the original identity and snapshot remain for audit.

No exploitation, credential attack, network scan, packet capture, external intelligence, reputation lookup, remediation, firewall change, browser/DNS modification, or AI inference is performed. Grouping correlations does not establish causality or a common actor.

Acknowledgement, assignment, notes, closure/reopening, automatic incident creation, API, and frontend are deferred.
