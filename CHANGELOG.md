# Changelog

All notable SentinelIP release baselines are documented here.

SentinelIP remains under active development. Release notes describe verified
project state at the tagged commit; they do not imply proof of compromise,
malware, phishing, exploitation, or attacker identity.

## [v0.1.0] — 2026-10-12

First verified defensive security platform baseline.

### Added

- Authorized private-network foundation and target-policy boundaries.
- Host discovery, persistent device inventory, and conservative Nmap-based
  port/service discovery.
- Deterministic change detection and risk-assessment findings.
- Conservative CVE correlation over persisted service evidence.
- SSH security monitoring with repeated-authentication and suspicious-username
  review signals.
- Authenticated browser and DNS telemetry foundations with privacy-focused
  normalization and retention controls.
- Deterministic web detections, threat detections, correlation records, and
  explicit incident-review records.
- Read-only security API endpoints for threats, correlations, and incident
  reviews.
- React security dashboard with overview analytics, filtering, exports, and
  read-only security-review panels.
- Filtered CSV, JSON, and PDF reporting.
- Typed, allow-listed read-only tool layer.
- Bounded runtime specialists and deterministic SentinelIP orchestrator.
- Reproducible Python dependency manifests and Quick Start documentation.
- Security reporting policy and project-documentation navigation.
- Real SentinelIP dashboard preview in the root README.

### Verified baseline

At the `v0.1.0` tag:

- 607 backend tests passed.
- 102 DNS sensor tests passed.
- 11 browser-extension tests passed.
- Frontend lint passed.
- Frontend production build passed.

### Known watchpoints

- The frontend production build reports a single JavaScript bundle above
  Vite's 500 KiB warning threshold. This is an optimization watchpoint, not a
  release failure.
- SentinelIP is still under active development.
- Threat, correlation, and incident-review records remain review artifacts and
  do not independently establish compromise or causality.

### Defensive boundary

This release does not provide exploitation, credential attacks, arbitrary
Internet-wide scanning, autonomous remediation, browser blocking, HTTPS MITM,
external reputation lookups, autonomous agent loops, or model-generated
security actions.
