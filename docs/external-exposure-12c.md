# External Exposure 12C — Service Exposure Classification

12C adds deterministic operational classification to the factual external exposure model.
It does not perform new scans and does not create vulnerability, exploitability, attack, or compromise claims.

Each persisted authorized public TCP exposure is classified into a service role:
`REMOTE_ADMIN`, `WEB`, `FILE_SHARING`, `DATABASE`, `MAIL`, `DNS`, `VPN`, `OTHER`, or `UNKNOWN`.

A separate exposure profile groups the role as `COMMON_PUBLIC_SERVICE`, `SENSITIVE_ADMIN_SERVICE`,
`INTERNAL_STYLE_SERVICE`, or `UNKNOWN_SERVICE`. These labels describe operational exposure only.
They are not severity ratings and do not override the explicit EXPECTED/UNEXPECTED/REVIEW policy assessment from 12B.

Rules use only normalized observed TCP port and service identity. Port mappings take precedence over service-name fallback,
and no banner text is interpreted as proof of a vulnerability.

Read-only API:

- `GET /external-exposure-classifications`
- `GET /external-exposure-classifications/{id}`

Supported filters include scope, service role, exposure profile, public IPv4 address, and TCP port.
