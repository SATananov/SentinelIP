# Perimeter Monitoring 11D — Allowed vs Blocked Correlation

11D correlates persisted inbound perimeter policy evidence when the same flow identity changes between an allowed outcome and a blocked/rejected outcome. It remains a deterministic **review signal**: it does not claim attack, intrusion, successful access, or compromise.

## Correlation identity

Only persisted `INBOUND` `CONNECTION_ATTEMPT` or `POLICY_DECISION` events are eligible. The action must be `ALLOW`, `BLOCK`, or `REJECT`.

Events are compared only when all of these fields match:

- Site;
- perimeter `source_type` and `source_key`;
- source IP;
- destination IP;
- destination port;
- protocol.

The source port is intentionally not part of the identity because it is commonly ephemeral. `UNKNOWN` actions are not correlated. Different Sites, perimeter sources, source IPs, destinations, ports, protocols, or directions do not mix.

## Five-minute transition window

The correlation window is inclusive and bounded to five minutes.

- a current `ALLOW` event with prior matching `BLOCK`/`REJECT` evidence becomes `BLOCK_THEN_ALLOW`;
- a current `BLOCK`/`REJECT` event with prior matching `ALLOW` evidence becomes `ALLOW_THEN_BLOCK`.

A same-policy sequence by itself does not create a policy correlation. The correlation stores the immutable event IDs and separate allowed/blocked evidence sets, plus counts and the primary policy action.

## Persistence and replay

Migration 35 adds `perimeter_policy_correlations`. Each correlation has a deterministic stable key anchored to its primary event, evidence IDs, rule ID, and rule version. Exact re-evaluation is idempotent; conflicting evidence cannot overwrite an existing correlation.

The stored state is `REVIEW` and confidence is `HIGH` because the rule is deterministic over normalized evidence. Those labels describe rule certainty, not malicious intent.

## Ingestion integration

Authenticated `POST /sensor/perimeter-events` continues to persist normalized perimeter evidence and run the 11C inbound-attempt detector. 11D additionally evaluates each accepted event for an allowed-vs-blocked transition and returns any resulting IDs in `policy_correlation_ids`.

No new sensor authority is introduced. The existing `LOG_COLLECTION` capability and 11B transport/authentication boundary remain unchanged.

## Read API

Review is read-only:

- `GET /perimeter-policy-correlations`
- `GET /perimeter-policy-correlations/{id}`

List filters include Site, correlation type, protocol, perimeter source type/key, source IP, destination IP/port, and primary action.

## Boundaries

11D does not perform packet capture, active scanning, firewall modification, blocking, reputation lookup, geolocation, exploit validation, host authentication correlation, or incident generation. A policy transition can reflect a rule change, NAT/firewall behavior, administrator action, or other benign causes. Host-level correlation belongs to 11E.

11E adds a separate site-scoped host correlation layer that can associate a perimeter destination with one uniquely matching device in authorized private-network inventory. Policy correlations remain unchanged and do not themselves imply host acceptance.
