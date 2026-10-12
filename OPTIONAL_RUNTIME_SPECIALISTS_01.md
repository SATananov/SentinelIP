# OPTIONAL RUNTIME SPECIALISTS 01

SentinelIP now has a small optional runtime-specialist layer above the explicit
tool registry.

This is not an LLM integration and not an autonomous agent system.

## Runtime boundary

The implemented path is:

`caller -> SpecialistRequest -> SpecialistRegistry -> ReadOnlySpecialist -> ToolCall -> ToolRegistry -> ToolPolicy -> read-only handler`

A specialist cannot call SentinelIP database modules, services, scanners,
shell commands, or operating-system primitives directly. Its only execution
boundary is the existing `ToolRegistry`.

## Specialist catalog

Version 01 exposes three deliberately narrow review specialists:

- `threat_review`
- `correlation_review`
- `incident_review`

Each supports only:

- `LIST`
- `DETAIL`

The specialist maps those intents to one of the six existing read-only tools.
It does not invent a new security interpretation and does not select arbitrary
tool names.

## No AI inference

There is no model provider, prompt, natural-language planner, autonomous loop,
background worker, or model-generated action.

The runtime layer performs deterministic routing only.

Persisted SentinelIP state remains authoritative.

## Safety boundary

Runtime specialists cannot:

- execute shell commands
- invoke Nmap or a scanner
- perform network activity
- query external intelligence
- call threat or correlation engines
- create incident reviews
- mutate persisted security interpretation
- perform remediation
- dynamically import requested code
- bypass `ToolPolicy`
- bypass `ToolRegistry`

## Future extension

A later runtime may use model-assisted reasoning, but any such component must
remain optional and must consume narrow typed specialist/tool interfaces.

The future SentinelIP orchestrator is not implemented in this phase.
