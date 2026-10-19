# Incident Review Reporting 20B: Printable HTML

`GET /incident-reviews/{review_id}/report.html` renders a printable, standalone HTML view of the bounded report produced by the 20A assembler. It uses the same Incident Review read-access boundary and report snapshot. The renderer receives the completed fixed projection and performs no database access or additional source lookups.

The page contains a fixed report header, current-state notice, review summary, evidence, notes, and timeline. It displays only fields already present in the 20A projection; it introduces no report data contract, source mapping, or collection caps of its own. All seven existing evidence types have readable labels. Missing source rows remain visible with neutral `Missing` status. Collection truncation reports the returned, total, and omitted counts. Chronological item order from 20A is preserved.

Dynamic values are treated as plain text and escaped with Python's standard quote-aware HTML escaping. Analyst text is not interpreted as Markdown or HTML; summary, final summary, note text, and timeline summary preserve newlines through static `white-space: pre-wrap` styling. Evidence rendering uses a fixed allowlist of 20A context fields. No raw dictionary dump or source payload is rendered.

The response is UTF-8 HTML with `Cache-Control: no-store`, inline `Content-Disposition`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. The filename contains only the numeric review ID and UTC generation timestamp. A restrictive CSP blocks scripts, images, fonts, objects, forms, frames, and external resources; the document uses embedded static CSS only. It includes screen and print styles and no interactive controls.

Rendered UTF-8 output is limited to 6 MiB. Oversize output returns a safe 413 without partial HTML. The 20A JSON ceiling and caps remain unchanged: 4 MiB JSON, 200 evidence links, 50 notes, and 50 timeline events. Reports are generated on demand from current state and are not persisted or represented as immutable evidence artifacts.

No PDF, CSV, frontend action, migration, or schema change is included. Schema remains version 44. 20C may add the compact review-detail actions for JSON download and printable report.
