# Perimeter Monitoring 11E — Host Correlation

11E associates inbound perimeter evidence with a concrete device already known to the Site's authorized private-network inventory. It is a factual inventory correlation for review, not proof that a connection succeeded or that a host was compromised.

## Site-scoped matching

An event is eligible when it is `INBOUND` and its type is `CONNECTION_ATTEMPT`, `POLICY_DECISION`, or `FLOW`. SentinelIP resolves the event's destination IP only against devices reachable through this chain:

`Site → bound PRIVATE_NETWORK scope → linked enabled/authorized network → inventory device`

The scope and network must both remain authorized and enabled. The device's current `last_ip_address` must exactly equal the perimeter destination IP. Public scopes are never considered.

A correlation is created only when exactly one eligible device matches. Zero matches or ambiguous matches fail closed and produce no host correlation.

## Stored correlation

Migration 36 adds `perimeter_host_correlations`. A correlation snapshots:

- Site and optional sensor identity;
- perimeter event ID;
- private scope ID and network ID;
- matched device ID;
- destination IP and port;
- protocol and firewall action;
- perimeter observation time;
- device `last_seen`, status, and identity confidence at evaluation time;
- deterministic rule identity and review reason.

The state is `REVIEW` and rule confidence is `HIGH` because the association is an exact, unique site-scoped inventory match. This confidence does **not** mean the perimeter traffic succeeded or was malicious.

## Ingestion integration

Authenticated `POST /sensor/perimeter-events` continues to run the 11C attempt detector and 11D policy-transition correlation. 11E also evaluates each accepted event and returns resulting IDs in `host_correlation_ids`.

No additional sensor capability or authority is introduced. The existing `LOG_COLLECTION` authentication and transport boundary remains unchanged.

## Read API

Host correlations are read-only:

- `GET /perimeter-host-correlations`
- `GET /perimeter-host-correlations/{id}`

List filters include Site, device, network, scope, protocol, policy action, destination IP, and destination port.

## Boundaries

11E does not inspect host authentication logs, infer application acceptance, claim compromise, create incidents, scan hosts, alter firewall policy, or perform remediation. It currently correlates against the inventory device's current `last_ip_address`; historical address-at-event-time reconstruction is intentionally deferred rather than inferred.
