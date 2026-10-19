# Incident Review Reporting 20C: Detail Handoff Actions

The selected Incident Review detail header contains two compact, read-only actions: **Download JSON** and **Printable Report**. They use only the established 20A JSON and 20B HTML report endpoints; the frontend does not reconstruct report data or add a report page, dashboard, or router.

Download JSON sends a `GET` with `cache: no-store` and an `AbortSignal`, then downloads the server response as a Blob. It accepts only the server's fixed ASCII `Content-Disposition` filename pattern for the selected numeric review ID. Any absent or unsafe filename falls back to `sentinelip-incident-review-{id}.json`. The temporary anchor is removed and its object URL is revoked immediately after triggering the download; the report body is not retained in application state or browser storage.

Printable Report opens a blank tab, clears its `opener`, applies a `no-referrer` policy, and then navigates it to the fixed HTML endpoint. This lets the UI detect a blocked popup while preventing the new report tab from controlling the application. A blocked popup produces concise feedback. The frontend does not fetch or inject the HTML, and it does not call print automatically.

The JSON action shows a compact pending state. Starting another request aborts the earlier request; changing or unmounting the selected detail aborts and invalidates it. A generation and selected-ID check prevents stale responses from triggering a download. Errors show safe messages for unavailable reports, oversized reports, and general request failures; aborts do not show an error.

Neither action calls review, timeline, or evidence mutation APIs. Reports are not cached or persisted by the frontend. This is a frontend-only change: no backend projection, schema, or migration changes are made. Phase 20 is ready to close once these actions and the existing bounded JSON/printable HTML endpoints meet the combined verification checkpoint.
