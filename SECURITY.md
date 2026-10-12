# Security Policy

SentinelIP is a defensive cybersecurity project intended for authorized,
private-network monitoring, assessment, telemetry review, and security analysis.

## Reporting a vulnerability

Please avoid publishing working exploit details, credentials, sensor tokens,
private telemetry, or other sensitive evidence in a public issue.

If GitHub private vulnerability reporting is enabled for this repository, use
that channel for security-sensitive reports. Otherwise, open a minimal public
issue asking for a private contact channel and do not include exploit details
or secrets in the issue body.

A useful report should include:

- the affected SentinelIP component
- the observed behavior and expected behavior
- the security impact
- safe reproduction steps
- relevant version or commit information
- whether credentials, tokens, or private telemetry may have been exposed

## Scope

Security reports are especially relevant for:

- telemetry authentication and sensor-token handling
- authorization boundaries for network discovery and inventory
- API input validation and data exposure
- privacy handling in browser and DNS telemetry
- report/export data handling
- read-only tool, specialist, and orchestrator boundaries

## Defensive boundary

SentinelIP does not provide offensive exploitation, credential attacks,
arbitrary Internet-wide scanning, autonomous remediation, or model-generated
security actions.

Please keep vulnerability reproduction limited to systems and networks you are
authorized to test.

## Sensitive data

Do not include real passwords, API keys, sensor tokens, cookies, personal data,
or private network evidence in public reports. Redact or replace sensitive
values with synthetic examples whenever possible.
