import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const app = readFileSync(new URL('../src/App.jsx', import.meta.url), 'utf8')
const css = readFileSync(new URL('../src/App.css', import.meta.url), 'utf8')
const overview = app.slice(app.indexOf('id="module-overview"'), app.indexOf('id="module-scope-discovery"'))

test('Overview uses four original API-owned KPI values without synthetic calculations', () => {
  for (const value of ['overview.total_events', 'overview.severity.INFO', 'overview.severity.WARNING', 'overview.severity.ALERT']) {
    assert.ok(overview.includes(`{${value}}`))
  }
  assert.equal((overview.match(/className="card /g) ?? []).length, 4)
})

test('Overview timeline renders the last twelve existing intervals with accessible matching values', () => {
  assert.match(overview, /timeline\.slice\(-12\)/)
  assert.match(overview, /activity-spark" aria-hidden="true"/)
  assert.match(overview, /className="activity-accessible-values" aria-label="Displayed activity interval counts"/)
  assert.match(overview, /\{item\.minute\}: \{item\.total\} events/)
  assert.match(overview, /No timeline data\./)
})

test('Alert preview is bounded to three real alerts and shows existing metadata without misleading total', () => {
  assert.match(overview, /alerts\.slice\(0, 3\)/)
  for (const value of ['alert.severity', 'alert.timestamp', 'alert.message', 'alert.source_ip', 'alert.event_type', 'alert.event_count']) {
    assert.ok(overview.includes(value), `Missing ${value}`)
  }
  assert.doesNotMatch(overview, /panel-count|alerts\.length\}<\/span>/)
  assert.match(overview, /No alerts recorded\./)
})

test('Overview keeps both Events and Analytics links using existing module routing', () => {
  assert.equal((overview.match(/handleModuleLink\(event, 'events-analytics'\)/g) ?? []).length, 2)
  assert.equal((overview.match(/workspaceHash\('events-analytics'\)/g) ?? []).length, 2)
})

test('Overview adds no data ownership, fetch, or polling and keeps the original API refresh topology', () => {
  assert.doesNotMatch(overview, /fetch\(|setInterval\(|useEffect\(/)
  assert.equal((app.match(/setInterval\(/g) ?? []).length, 1)
  assert.match(app, /setInterval\(\(\) => \{\s*loadData\(\)\s*\},\s*5000\)/)
})

test('Overview-only responsive grid and narrow content wrapping are scoped', () => {
  assert.match(css, /\.overview-content-grid \{ display: grid; grid-template-columns:/)
  assert.match(css, /@media \(max-width: 1120px\)/)
  assert.match(css, /@media \(max-width: 620px\) \{ \.cards\.overview-kpis/)
  assert.match(css, /@media \(max-width: 360px\)/)
  assert.match(css, /\.overview-alert-meta span \{ min-width: 0; overflow-wrap: anywhere; \}/)
  assert.match(css, /\.activity-accessible-values \{ position: absolute;/)
  assert.match(css, /gap: 16px; margin-bottom: var\(--content-gap\); align-items: start;/)
  assert.match(css, /height: clamp\(90px, 10vw, 126px\); min-height: 90px;/)
})
