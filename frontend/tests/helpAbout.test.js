import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { helpTopicFromHash, moduleFromHash, workspaceHash } from '../src/services/workspaceNavigation.js'

const app = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8')
const help = await readFile(new URL('../src/components/HelpGuide.jsx', import.meta.url), 'utf8')
const about = await readFile(new URL('../src/components/AboutSentinelIP.jsx', import.meta.url), 'utf8')
const css = await readFile(new URL('../src/App.css', import.meta.url), 'utf8')
const navigation = await readFile(new URL('../src/services/workspaceNavigation.js', import.meta.url), 'utf8')
const hook = await readFile(new URL('../src/hooks/useWorkspaceNavigation.js', import.meta.url), 'utf8')

test('help and about are direct hash destinations with contextual topic links', () => {
  assert.equal(moduleFromHash('#workspace/help?topic=scope'), 'help')
  assert.equal(moduleFromHash('#workspace/about'), 'about')
  assert.equal(helpTopicFromHash('#workspace/help?topic=scope'), 'scope')
  assert.equal(workspaceHash('help', 'sensors'), '#workspace/help?topic=sensors')
  assert.equal(workspaceHash('about'), '#workspace/about')
  assert.throws(() => workspaceHash('unsupported'), TypeError)
})

test('guide covers the required verified topics, search and no-results feedback', () => {
  for (const id of ['getting-started', 'overview', 'scope', 'sensors', 'operations', 'detections', 'perimeter', 'events', 'lifecycle', 'troubleshooting']) assert.ok(help.includes(`id: '${id}'`), `missing help topic ${id}`)
  assert.match(help, /type="search"/)
  assert.match(help, /results.length === 0/)
  assert.match(help, /No help topics match/)
  assert.match(help, /aria-label="Help topics"/)
  assert.match(help, /aria-pressed=/)
  assert.match(help, /Help is bundled in the frontend/)
})

test('context help maps operational destinations to relevant topics and supports Escape return', () => {
  for (const topic of ["overview: 'overview'", "'scope-discovery': 'scope'", "'remote-sensors': 'sensors'", "operations: 'operations'", "detections: 'detections'", "perimeter: 'perimeter'", "'events-analytics': 'events'", "'data-lifecycle': 'lifecycle'"]) assert.ok(app.includes(topic))
  assert.match(app, /event\.key === 'Escape'/)
  assert.match(app, /target instanceof HTMLInputElement/)
  assert.match(app, /target instanceof HTMLTextAreaElement/)
  assert.match(app, /navigateToModule\('help', moduleHelpTopic\)/)
  assert.match(app, /Return to workspace/)
})

test('sidebar labels have decorative SVG icons and both support destinations are represented', () => {
  for (const id of ['overview', 'scope-discovery', 'remote-sensors', 'operations', 'detections', 'perimeter', 'events-analytics', 'data-lifecycle', 'help', 'about']) assert.ok(app.includes(`${id}: <>`) || app.includes(`'${id}': <>`), `missing icon for ${id}`)
  for (const label of ['Overview', 'Scope & Discovery', 'Remote Sensors', 'Operations', 'Detections', 'Perimeter', 'Events & Analytics', 'Data Lifecycle']) assert.ok(navigation.includes(`label: '${label}'`), `missing label ${label}`)
  for (const label of ['Help &amp; User Guide', 'About SentinelIP']) assert.ok(app.includes(label), `missing label ${label}`)
  assert.match(app, /'aria-hidden': true/)
  assert.match(app, /aria-label="Support and information"/)
  assert.match(css, /\.module-nav a\[aria-current="page"\]/)
})

test('help and about are mounted once, use hidden inert panels, and add no API requests or polling', () => {
  assert.equal((app.match(/<HelpGuide\b/g) ?? []).length, 1)
  assert.equal((app.match(/<AboutSentinelIP\b/g) ?? []).length, 1)
  assert.match(app, /id="module-help"[\s\S]{0,150}hidden=\{activeModule !== 'help'\} inert=\{activeModule !== 'help'\}/)
  assert.match(app, /id="module-about"[\s\S]{0,150}hidden=\{activeModule !== 'about'\} inert=\{activeModule !== 'about'\}/)
  assert.equal((app.match(/setInterval\(/g) ?? []).length, 1)
  assert.equal((app.match(/fetch\(/g) ?? []).length, 6)
  assert.doesNotMatch(help, /fetch\(|setInterval\(|API_BASE/)
})

test('hash changes drive direct links, refresh and browser Back/Forward without resetting module state', () => {
  assert.match(hook, /window\.addEventListener\('hashchange', syncFromLocation\)/)
  assert.match(hook, /setActiveModule\(moduleFromHash\(window\.location\.hash\)\)/)
  assert.match(hook, /window\.location\.hash = nextHash/)
  for (const state of ['severityFilter', 'ipDraft', 'ipFilter', 'timeRange', 'exportRangeMode', 'exportFromLocal', 'exportUntilLocal', 'pageSize']) assert.ok(app.includes(`const [${state},`), `${state} remains owned by the app`)
  assert.match(app, /const \[severityFilter, setSeverityFilter\] = useState/)
  assert.equal((app.match(/<NetworkWorkspace\b/g) ?? []).length, 1)
  assert.equal((app.match(/<RemoteSensorFleet\b/g) ?? []).length, 1)
  assert.equal((app.match(/<SecurityReviewPanel\b/g) ?? []).length, 1)
})

test('about copy stays within verified capabilities and carries required attribution', async () => {
  const source = await readFile(new URL('../src/components/AboutSentinelIP.jsx', import.meta.url), 'utf8')
  assert.match(source, /SentinelIP/)
  assert.match(source, /local-first operating model/)
  assert.match(source, /Tanashi Studio™/)
  assert.match(source, /© 2026 Tanashi Studio\. All rights reserved\./)
  assert.match(source, /operator remains responsible for authorized use/)
  assert.doesNotMatch(source, /certified|guarantee|version \d|registered trademark|endorsed by/i)
  assert.ok(about.includes('CSV, JSON, and PDF'))
})

test('help and about layouts adapt to narrow screens with visible keyboard focus', async () => {
  assert.match(css, /\.help-layout, \.about-grid \{ grid-template-columns: 1fr; \}/)
  assert.match(css, /\.mobile-workspace-menu \{[^}]*overflow-y: auto/s)
  assert.match(await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8'), /mobile-workspace-menu[\s\S]*?Support &amp; Information[\s\S]*?About SentinelIP/)
  const globalCss = await readFile(new URL('../src/index.css', import.meta.url), 'utf8')
  assert.match(globalCss, /:focus-visible/)
})
