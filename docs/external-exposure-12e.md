# 12E — External Exposure Dashboard

12E adds a read-only dashboard that combines the factual external-exposure layers introduced in 12A–12D.

## Endpoint

`GET /external-exposure-dashboard`

Optional filters:

- `scope_id`: one authorized public scope (`PUBLIC_IPV4`, `PUBLIC_CIDR`, or `HOSTNAME`)
- `time_range`: `24h`, `72h`, `7d`, `30d`, or `all` for the change-history window
- `recent_limit`: 1–50 rows for recent exposure/change tables

## Evidence shown

The dashboard aggregates:

- current external exposure inventory and presence state
- expected / unexpected / review configuration assessment
- deterministic service role and exposure profile
- deterministic observed change counts and recent changes
- top exposed TCP ports and public target addresses

The dashboard is an evidence and review surface. `UNEXPECTED`, `SENSITIVE_ADMIN_SERVICE`, `INTERNAL_STYLE_SERVICE`, and change labels are not vulnerability, exploitation, intrusion, or compromise claims.

12E introduces no scanner, probe, mutation endpoint, new target type, or broader authorization boundary. It reads only previously recorded authorized public exposure evidence.
