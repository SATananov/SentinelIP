# Perimeter Monitoring 11F — External Activity Dashboard

11F adds a read-only operational view over the perimeter evidence introduced in 11A–11E. It does not create new detections, correlations, incidents, or claims about compromise.

## API

`GET /perimeter-dashboard` accepts optional `site_id`, `source_type`, and a bounded `time_range` (`1h`, `6h`, `24h`, `72h`, `7d`, `all`).

The response contains factual aggregates for inbound evidence:

- inbound total and ALLOW/BLOCK/REJECT/UNKNOWN counts;
- unique external source IPs;
- host-linked event count;
- repeated inbound review-signal count;
- policy-correlation count;
- top external sources and destination ports;
- a bounded hourly timeline;
- recent inbound evidence with optional inventory-device association;
- recent repeated-attempt review signals;
- recent BLOCK_THEN_ALLOW / ALLOW_THEN_BLOCK correlations;
- filter options for sites and observed perimeter source types.

## UI

The React dashboard adds an **External Activity** panel with site, source-type, and time-window filters. The panel intentionally uses review-oriented wording. It does not label inbound traffic as an attack or claim that a destination host accepted traffic merely because perimeter evidence targeted its address.

## Boundary

11F remains read-only. Existing 11A–11E evidence and deterministic review objects remain authoritative. No active response, blocking, scanning, or incident creation is introduced here.
