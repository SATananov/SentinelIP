# OPTIONAL SENTINELIP ORCHESTRATOR 01

SentinelIP now has an optional deterministic coordinator above the bounded
runtime-specialist layer.

This phase completes the initial runtime architecture without adding an LLM,
autonomous agent loop, background worker, model provider, network action, or
security-state mutation.

## Architecture

The only supported path is:

`caller -> OrchestratorRequest -> SentinelIPOrchestrator -> SpecialistRegistry -> ReadOnlySpecialist -> ToolRegistry -> ToolPolicy -> deterministic persisted state`

The orchestrator does not import or invoke the tool layer directly.

It cannot select arbitrary specialists or arbitrary tool names.

## Explicit operations

Version 01 supports a fixed enum of operations:

- `SECURITY_OVERVIEW`
- `THREAT_LIST`
- `THREAT_DETAIL`
- `CORRELATION_LIST`
- `CORRELATION_DETAIL`
- `INCIDENT_LIST`
- `INCIDENT_DETAIL`

List operations accept only bounded `limit` and `offset` arguments through the
existing specialist/tool contracts.

Detail operations require exactly one persisted record ID.

## Security overview

`SECURITY_OVERVIEW` is the only multi-specialist coordination operation.

It deterministically requests LIST results from:

1. `threat_review`
2. `correlation_review`
3. `incident_review`

No inference is performed between those results. They remain separate security
layers.

## No autonomous reasoning

There is no prompt, natural-language planner, model choice, retry loop,
self-reflection loop, task queue, background scheduler, memory system, or
model-generated action.

The orchestrator performs only static typed routing.

## Safety boundary

The orchestrator cannot:

- access the database directly
- access the tool registry directly
- invoke scanners
- perform network activity
- invoke threat or correlation engines
- create incident reviews
- mutate security interpretation
- execute shell commands
- perform remediation
- query external intelligence
- dynamically import requested code
- infer compromise, phishing, malware, exploitation, or attacker identity

Existing deterministic SentinelIP layers remain authoritative.

## Future model assistance

A future optional model-facing adapter may produce an `OrchestratorRequest`,
but that adapter must remain outside the deterministic orchestrator and must
not gain more authority than these explicit typed operations.

No such model-facing adapter is implemented here.
