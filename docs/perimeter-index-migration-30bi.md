# Phase 30B-I: Perimeter relationship indexes

Schema migration 46 adds two non-unique indexes, based on Phase 30B-M synthetic
measurements showing repeated full-table scans during perimeter event foreign
key checks and component deletion:

- `idx_perimeter_detections_primary_event` on
  `perimeter_detections(primary_event_id)`
- `idx_perimeter_policy_correlations_primary_event` on
  `perimeter_policy_correlations(primary_event_id)`

The indexes improve child-row lookup and foreign-key dependency checks. They
consume persistent database space and add maintenance work to inserts and
updates; they do not change foreign-key actions, uniqueness, ingestion, or
evidence semantics. The migration adds no tables, columns, or constraints.

This migration does not implement perimeter retention. Perimeter lifecycle
classes remain `POLICY_UNDEFINED` until the separately authorized retention
implementation is complete. The 180-day received-time/component policy remains
the approved design, and future cleanup should use connection-local TEMP graph
staging rather than materializing the full graph as Python objects.

No `received_at` index is added: Phase 30B-M did not establish that it is
required. Candidate selection should be measured during cleanup implementation
and verification. No other permanent index is approved by this phase.

There is no hard component-size rejection. Future preview must expose eligible
and protected component sizes; apply remains manual, requires explicit
destructive confirmation, and must keep each component atomic. Large components
may require substantial transaction time and writer-lock duration. No hard
cleanup-latency or component-row bound is claimed.
