import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const app = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8')
const css = await readFile(new URL('../src/App.css', import.meta.url), 'utf8')
const globalCss = await readFile(new URL('../src/index.css', import.meta.url), 'utf8')
const hook = await readFile(new URL('../src/hooks/useWorkspaceNavigation.js', import.meta.url), 'utf8')
const security = await readFile(new URL('../src/components/SecurityReviewPanel.jsx', import.meta.url), 'utf8')
const operations = await readFile(new URL('../src/components/IncidentReviewOperations.jsx', import.meta.url), 'utf8')
const navigation = await readFile(new URL('../src/services/workspaceNavigation.js', import.meta.url), 'utf8')

const moduleIds = [
  'overview', 'scope-discovery', 'remote-sensors', 'operations',
  'detections', 'perimeter', 'events-analytics',
]

test('seven workspace modules and separate Local Operator destination are exposed', () => {
  for (const id of moduleIds) assert.ok(navigation.includes(`id: '${id}'`), `missing module ${id}`)
  assert.match(app, /WORKSPACE_MODULES\.filter\(\(\{ id \}\) => id !== 'data-lifecycle'\)/)
  assert.match(app, /workspaceHash\('data-lifecycle'\)/)
  assert.match(app, /id="module-data-lifecycle"/)
  assert.match(app, /aria-label="Main navigation"/)
  assert.match(app, /aria-current=\{activeModule === id \? 'page' : undefined\}/)
})

test('all modules stay mounted and inactive module regions are hidden and inert', () => {
  for (const component of [
    'InvestigationLookup', 'NetworkWorkspace', 'RemoteSensorFleet', 'SecurityReviewPanel',
    'ExternalActivityDashboard', 'ExternalExposureDashboard', 'DataLifecycle',
  ]) {
    const count = app.match(new RegExp(`<${component}(?:\\s|>)`, 'g'))?.length ?? 0
    assert.equal(count, 1, `${component} should have exactly one mounted instance`)
  }
  for (const id of moduleIds.filter((value) => !['operations', 'detections'].includes(value))) {
    assert.match(app, new RegExp(`id="module-${id}"[\\s\\S]{0,180}hidden=\\{activeModule !== '${id}'\\} inert=\\{activeModule !== '${id}'\\}`))
  }
  assert.match(security, /id="module-operations"[\s\S]*?hidden=\{activeModule !== 'operations'\} inert=\{activeModule !== 'operations'\}/)
  assert.match(security, /id="module-detections"[\s\S]*?hidden=\{activeModule !== 'detections'\} inert=\{activeModule !== 'detections'\}/)
  assert.match(css, /\.workspace-module\[hidden\], \.security-workspace-part\[hidden\] \{ display: none !important; \}/)
})

test('navigation owns hash state, history events, focus, and reduced-motion behavior', () => {
  assert.match(hook, /moduleFromHash\(window\.location\.hash\)/)
  assert.match(hook, /window\.addEventListener\('hashchange'/)
  assert.match(hook, /window\.location\.hash = nextHash/)
  assert.match(hook, /workspace-heading-\$\{activeModule\}/)
  assert.match(hook, /scrollToVisibleTarget\(heading, \{ focus: !keepInitialTabOrder \}\)/)
  assert.match(hook, /prefers-reduced-motion: reduce/)
})

test('investigation pivots activate the destination module before target scrolling', () => {
  assert.match(app, /navigateToModule\(moduleForInvestigationKind\(request\.kind\)\)/)
  assert.match(app, /\}, \[activeModule, investigationNavigation\]\)/)
  assert.match(app, /window\.requestAnimationFrame\(\(\) => \{\s*document\.getElementById\(destinationPanelId\)/)
})

test('combined Operations and Detections share one mounted owner and one request lifecycle', () => {
  assert.equal((app.match(/<SecurityReviewPanel\b/g) ?? []).length, 1)
  assert.equal((security.match(/<IncidentReviewOperations\b/g) ?? []).length, 1)
  assert.match(security, /\}, \[refreshSignal\]\)/)
  assert.match(security, /\}, \[\]\)/)
  assert.match(security, /<IncidentReviewOperations[\s\S]*?<section className="security-workspace-part" id="module-detections"/)
  assert.match(operations, /workspace-heading-operations/)
  assert.match(security, /workspace-heading-detections/)
})

test('workspace navigation adds no fetch or polling timer and preserves API status/header', () => {
  assert.equal((app.match(/setInterval\(/g) ?? []).length, 1)
  assert.match(app, /setInterval\(\(\) => \{\s*loadData\(\)\s*\},\s*5000\)/)
  assert.equal((app.match(/fetch\(`\$\{API_BASE\}\/health`\)/g) ?? []).length, 1)
  assert.match(app, /API Online/)
  assert.match(app, /API Offline/)
  assert.match(app, /Last updated:/)
})

test('keyboard focus and narrow-screen styles remain present without app-level nested scrolling', () => {
  assert.match(globalCss, /:focus-visible/)
  assert.match(globalCss, /prefers-reduced-motion/)
  assert.match(css, /@media \(max-width: 760px\)/)
  assert.match(css, /overflow-x: auto/)
  assert.doesNotMatch(css, /\.app-shell\s*\{[^}]*overflow-y:\s*auto/s)
  assert.doesNotMatch(css, /\.workspace-column\s*\{[^}]*height:\s*100vh/s)
  assert.match(app, /Tanashi Studio™/)
  assert.match(app, /© 2026 Tanashi Studio\. All rights reserved\./)
})
