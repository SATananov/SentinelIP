# External Exposure 12A — Normalized Exposure Model

12A adds a factual, read-only model for services observed from SentinelIP's existing explicitly authorized public-target scan paths. It does not add a new scanner, expand target authorization, or perform Internet-wide enumeration.

## Supported scope sources

Exposure evidence can be created only from successful service scans for persisted, enabled and explicitly authorized `PUBLIC_IPV4`, `PUBLIC_CIDR`, or current `HOSTNAME` scopes. The observed IPv4 address must remain a member of that exact scope. Private-network inventory never becomes external-exposure evidence.

## Model

`external_exposures` provides stable identity for an observed open TCP endpoint using the scope, public IPv4 address and port. It retains first/last-seen timestamps and the latest bounded service fingerprint when one exists.

`external_exposure_observations` is immutable evidence history. Exact replays are idempotent through an observation digest. A port can exist as exposure evidence without a service fingerprint; in that case the service fields and service confidence remain null rather than being invented.

12A deliberately does **not** classify an exposure as vulnerable, exploitable, compromised, new, unchanged, removed, intended, or unintended. Those judgments belong to later assessment/change phases.

## Read API

- `GET /external-exposures`
- `GET /external-exposures/{exposure_id}`
- `GET /external-exposures/{exposure_id}/observations`

The list endpoint supports bounded filtering by scope, device, public target IPv4 and destination port.

## Safety boundary

12A reuses only the existing authorized public scan flow and fixed conservative scanner profiles. It adds no raw target parameter, no arbitrary Nmap flags, no shell/command execution and no unrestricted Internet scan capability.
