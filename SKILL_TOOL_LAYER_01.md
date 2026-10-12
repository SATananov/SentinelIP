# SKILL / TOOL LAYER 01

SentinelIP now has a narrow typed tool boundary intended for future optional
runtime specialists and orchestration.

This phase does not add an agent, an LLM runtime, autonomous loops, API routes,
network activity, or new security interpretation.

## Architecture

Future callers use this boundary:

`caller -> ToolCall -> ToolRegistry -> ToolPolicy -> explicit handler -> deterministic database read`

The registry does not expose arbitrary Python callables, dynamic imports, shell
commands, direct SQL, scanner adapters, or operating-system access.

## Initial catalog

The first catalog is deliberately read-only:

- `list_threats`
- `get_threat`
- `list_correlations`
- `get_correlation`
- `list_incidents`
- `get_incident`

Collection tools accept only bounded `limit` and `offset` arguments. Detail
tools accept one positive persisted record ID.

## Policy boundary

`ToolPolicy` uses an explicit allow-list. Every tool in this phase has
`READ` access and the `SECURITY_STATE` capability.

The tool layer cannot:

- execute shell commands
- invoke Nmap or any scanner
- access arbitrary network targets
- run threat evaluation
- run correlation
- create incident reviews
- mutate persisted security interpretation
- perform remediation
- make external intelligence requests
- dynamically import a requested implementation

## Deterministic authority

The tool layer is an adapter over persisted deterministic state. Existing
SentinelIP services and database semantics remain authoritative.

Threat, correlation, and incident meaning is not recreated in the tool layer.
No AI inference is introduced.

## Deferred

Later phases may add additional explicitly authorized tools for visibility,
monitoring, assessment, threat review, and orchestration. Active tools must
preserve target authorization and service policy boundaries; they are not part
of this phase.
