import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { moduleFromHash } from '../src/services/workspaceNavigation.js'
import { skipToWorkspaceMain } from '../src/hooks/useWorkspaceNavigation.js'

const root = new URL('../', import.meta.url)
const app = await readFile(new URL('src/App.jsx', root), 'utf8')
const hook = await readFile(new URL('src/hooks/useWorkspaceNavigation.js', root), 'utf8')
const operationsPanel = await readFile(new URL('src/components/SecurityReviewPanel.jsx', root), 'utf8')
const operationsHeading = await readFile(new URL('src/components/IncidentReviewOperations.jsx', root), 'utf8')

const moduleHeadings = [
  ['overview', 'workspace-heading-overview'],
  ['scope-discovery', 'workspace-heading-scope-discovery'],
  ['remote-sensors', 'workspace-heading-remote-sensors'],
  ['operations', 'workspace-heading-operations'],
  ['detections', 'workspace-heading-detections'],
  ['perimeter', 'workspace-heading-perimeter'],
  ['events-analytics', 'workspace-heading-events-analytics'],
  ['data-lifecycle', 'workspace-heading-data-lifecycle'],
  ['help', 'workspace-heading-help'],
  ['about', 'workspace-heading-about'],
]

function withDocument(moduleId, { headingTop = -180, hidden = false } = {}, run) {
  const oldWindow = globalThis.window
  const oldDocument = globalThis.document
  const calls = { prevented: 0, focused: [], scrolls: [], history: 0, fetches: 0, timers: 0 }
  const target = {
    isConnected: true,
    getBoundingClientRect: () => ({ top: headingTop, bottom: headingTop + 24, left: 260, right: 500 }),
    closest: () => hidden ? { hidden: true } : null,
    focus: (options) => calls.focused.push(options),
  }
  const main = { ...target, getBoundingClientRect: () => ({ top: headingTop, bottom: 500, left: 260, right: 800 }) }
  const documentElement = { style: { setProperty: () => {} } }
  globalThis.document = {
    documentElement,
    getElementById: (id) => id === `workspace-heading-${moduleId}` ? target : id === 'main-content' ? main : null,
    querySelector: (selector) => selector === '.dashboard-header' ? header : sidebar,
  }
  const header = { getBoundingClientRect: () => ({ top: 0, bottom: 104, left: 250, right: 1000 }) }
  const sidebar = { getBoundingClientRect: () => ({ top: 0, bottom: 0, left: 0, right: 240 }) }
  globalThis.window = {
    scrollY: 600,
    innerHeight: 800,
    location: { hash: '#workspace/' + moduleId },
    history: { length: 4, state: null, pushState: () => calls.history++, replaceState: () => calls.history++ },
    fetch: () => calls.fetches++, setInterval: () => calls.timers++,
    matchMedia: () => ({ matches: true }),
    getComputedStyle: (element) => element === documentElement
      ? { getPropertyValue: () => '28px' }
      : { position: element === header ? 'sticky' : 'sticky' },
    scrollTo: (...args) => calls.scrolls.push(args),
  }
  try {
    run(calls)
  } finally {
    if (oldWindow === undefined) delete globalThis.window
    else globalThis.window = oldWindow
    if (oldDocument === undefined) delete globalThis.document
    else globalThis.document = oldDocument
  }
}

test('skip link focuses each active module heading without changing URL or invoking operations', async (t) => {
  for (const [moduleId, headingId] of moduleHeadings) {
    await t.test(moduleId, () => withDocument(moduleId, {}, (calls) => {
      const event = { preventDefault: () => calls.prevented++ }
      assert.equal(skipToWorkspaceMain(event, moduleId), true)
      assert.equal(calls.prevented, 1)
      assert.deepEqual(calls.focused, [{ preventScroll: true }])
      assert.equal(calls.scrolls.length, 1)
      assert.deepEqual(calls.scrolls[0], [0, 288])
      assert.equal(globalThis.window.location.hash, `#workspace/${moduleId}`)
      assert.equal(calls.history, 0)
      assert.equal(calls.fetches, 0)
      assert.equal(calls.timers, 0)
      assert.ok(app.includes(`id="${headingId}"`) || operationsPanel.includes(`id="${headingId}"`) || operationsHeading.includes(`id="${headingId}"`))
    }))
  }
})

test('skip link does not focus a hidden or inert heading', () => {
  withDocument('help', { hidden: true }, (calls) => {
    const event = { preventDefault: () => calls.prevented++ }
    assert.equal(skipToWorkspaceMain(event, 'help'), false)
    assert.equal(calls.prevented, 1)
    assert.deepEqual(calls.focused, [])
    assert.deepEqual(calls.scrolls, [])
    assert.equal(globalThis.window.location.hash, '#workspace/help')
  })
})

test('skip link markup retains a semantic main target and handler prevents hash routing', () => {
  assert.match(app, /<a className="skip-link" href="#main-content" onClick=\{\(event\) => skipToWorkspaceMain\(event, activeModule\)\}>/)
  assert.match(app, /<main id="main-content" className="dashboard" tabIndex="-1">/)
  assert.match(hook, /event\.preventDefault\(\)/)
  assert.match(hook, /const initialModulePosition = useRef\(true\)/)
  assert.match(hook, /if \(keepInitialTabOrder\) initialModulePosition\.current = false/)
  assert.match(hook, /scrollToVisibleTarget\(target, \{ focus: true, preserveVisible: true \}\)/)
  assert.match(hook, /target\.closest\?\.\('\[hidden\], \[inert\]'\)/)
})

test('skip activation preserves direct hash and Back/Forward module routing', () => {
  for (const [moduleId] of moduleHeadings) {
    const hash = `#workspace/${moduleId}`
    assert.equal(moduleFromHash(hash), moduleId)
  }
  assert.match(hook, /window\.addEventListener\('hashchange', syncFromLocation\)/)
  assert.match(hook, /window\.history\.scrollRestoration = 'manual'/)
  assert.match(hook, /window\.location\.hash = nextHash/)
})

test('skip behavior adds no timer or fetch and hidden module regions remain inert', () => {
  assert.equal((app.match(/setInterval\(/g) ?? []).length, 1)
  assert.match(app, /setInterval\(\(\) => \{\s*loadData\(\)\s*\},\s*5000\)/)
  for (const id of ['overview', 'scope-discovery', 'remote-sensors', 'perimeter', 'events-analytics', 'data-lifecycle', 'help', 'about']) {
    assert.match(app, new RegExp(`hidden=\\{activeModule !== '${id}'\\} inert=\\{activeModule !== '${id}'\\}`))
  }
  assert.match(operationsPanel, /hidden=\{activeModule !== 'operations'\} inert=\{activeModule !== 'operations'\}/)
  assert.match(operationsPanel, /hidden=\{activeModule !== 'detections'\} inert=\{activeModule !== 'detections'\}/)
})
