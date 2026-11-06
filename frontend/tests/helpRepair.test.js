import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { scrollToVisibleTarget } from '../src/hooks/useWorkspaceNavigation.js'

const base = new URL('../', import.meta.url)
const read = (path) => readFile(new URL(path, base), 'utf8')
const app = await read('src/App.jsx')
const review = await read('src/components/SecurityReviewPanel.jsx')
const css = await read('src/App.css')
const globalCss = await read('src/index.css')
const hook = await read('src/hooks/useWorkspaceNavigation.js')
const help = await read('src/components/HelpGuide.jsx')
const about = await read('src/components/AboutSentinelIP.jsx')
const favicon = await read('public/favicon.svg')
const favicon48 = await readFile(new URL('public/favicon-48.png', base))
const html = await read('index.html')

test('sidebar uses the exact browser-linked 48px favicon PNG without distortion', () => {
  assert.match(html, /rel="icon" type="image\/png" sizes="48x48" href="\/favicon-48\.png"/)
  assert.match(app, /<img className="brand-mark" src="\/favicon-48\.png" alt="" width="38" height="38"/)
  assert.equal(favicon48.readUInt32BE(16), 48)
  assert.equal(favicon48.readUInt32BE(20), 48)
  assert.match(favicon, /<svg/)
  assert.doesNotMatch(html, /href="\/favicon\.svg"/)
  assert.doesNotMatch(app, /className="brand-mark"[^>]*>S</)
  assert.match(css, /\.brand-mark\s*\{[^}]*object-fit:\s*contain/s)
  assert.match(css, /\.brand-mark\s*\{[^}]*height:\s*auto/s)
})

test('entry positioning uses actual sticky element geometry for Help and About', () => {
  assert.match(hook, /workspace-heading-\$\{activeModule\}/)
  assert.match(hook, /scrollToVisibleTarget\(heading, \{ focus: !keepInitialTabOrder \}\)/)
  assert.match(hook, /getBoundingClientRect\(\)/)
  assert.match(hook, /getComputedStyle\(element\)/)
  assert.match(hook, /new window\.ResizeObserver\(updateScrollInset\)/)
  assert.match(hook, /updateWorkspaceScrollPadding\(heading\)/)
  assert.match(globalCss, /--workspace-clearance: 28px/)
  assert.match(app, /id="workspace-heading-help"/)
  assert.match(app, /id="workspace-heading-about"/)
})

test('safe positioning adapts to measured desktop header and mobile sticky sidebar', () => {
  const oldWindow = globalThis.window
  const oldDocument = globalThis.document
  const calls = []
  const target = {
    isConnected: true,
    getBoundingClientRect: () => ({ top: 400, right: 400, left: 260 }),
    focus: ({ preventScroll }) => calls.push(['focus', preventScroll]),
  }
  const header = { getBoundingClientRect: () => ({ top: 0, bottom: 118, left: 250, right: 900 }) }
  let sidebarRect = { top: 0, bottom: 0, left: 0, right: 240 }
  const sidebar = { getBoundingClientRect: () => sidebarRect }
  const cssProps = new Map()
  const documentElement = { style: { setProperty: (name, value) => cssProps.set(name, value) } }
  globalThis.document = { documentElement, querySelector: (selector) => selector === '.dashboard-header' ? header : sidebar }
  globalThis.window = {
    scrollY: 600, innerHeight: 900, matchMedia: () => ({ matches: false }),
    getComputedStyle: (element) => element === documentElement
      ? { getPropertyValue: () => '28px' }
      : { position: 'sticky' },
    scrollTo: (position) => calls.push(['scroll', position]),
  }
  try {
    assert.equal(scrollToVisibleTarget(target, { focus: true }), true)
    assert.deepEqual(calls[0], ['focus', true])
    assert.equal(calls[1][1].top, 854)
    assert.equal(cssProps.get('--workspace-scroll-inset'), '146px')
    sidebarRect = { top: 0, bottom: 146, left: 0, right: 500 }
    target.getBoundingClientRect = () => ({ top: 400, right: 400, left: 20 })
    calls.length = 0
    scrollToVisibleTarget(target)
    assert.equal(calls[0][1].top, 826)
    assert.equal(cssProps.get('--workspace-scroll-inset'), '174px')
  } finally {
    if (oldWindow === undefined) delete globalThis.window
    else globalThis.window = oldWindow
    if (oldDocument === undefined) delete globalThis.document
    else globalThis.document = oldDocument
  }
})

test('visible desktop article selection does not move the page; offscreen selection reveals it', () => {
  const oldWindow = globalThis.window
  const oldDocument = globalThis.document
  const calls = []
  let rect = { top: 220, bottom: 290, left: 260, right: 800 }
  const target = { isConnected: true, getBoundingClientRect: () => rect, focus: () => calls.push('focus') }
  const docEl = { style: { setProperty: (...args) => calls.push(args) } }
  globalThis.document = {
    documentElement: docEl,
    querySelector: () => null,
  }
  globalThis.window = {
    scrollY: 900, innerHeight: 800, matchMedia: () => ({ matches: false }),
    getComputedStyle: () => ({ getPropertyValue: () => '28px' }),
    scrollTo: (position) => calls.push(position),
  }
  try {
    assert.equal(scrollToVisibleTarget(target, { focus: true, preserveVisible: true }), true)
    assert.equal(calls.some((value) => value && typeof value === 'object' && 'top' in value), false)
    rect = { top: 850, bottom: 920, left: 260, right: 800 }
    scrollToVisibleTarget(target, { preserveVisible: true })
    assert.deepEqual(calls.at(-1), { top: 1722, behavior: 'smooth' })
  } finally {
    if (oldWindow === undefined) delete globalThis.window
    else globalThis.window = oldWindow
    if (oldDocument === undefined) delete globalThis.document
    else globalThis.document = oldDocument
  }
})

test('topic selection focuses the new article and replaces rather than pushes history', () => {
  assert.match(help, /shouldMoveToArticle\.current = true/)
  assert.match(help, /scrollToVisibleTarget\(articleHeading\.current, \{ focus: true, preserveVisible: true \}\)/)
  assert.match(help, /aria-live="polite"/)
  assert.match(help, /aria-pressed=\{selected\.id === topic\.id\}/)
  assert.match(hook, /window\.history\.replaceState\(window\.history\.state, '', nextHash\)/)
  assert.doesNotMatch(hook, /selectHelpTopic[\s\S]*?window\.location\.hash\s*=/)
})

test('Help query and selection state survive module changes because Help is single and keep-mounted', () => {
  assert.match(help, /const \[query, setQuery\] = useState\(''\)/)
  assert.equal((app.match(/<HelpGuide\b/g) ?? []).length, 1)
  assert.match(app, /<HelpGuide topicId=\{helpTopic\} onTopicChange=\{selectHelpTopic\}/)
  assert.match(app, /hidden=\{activeModule !== 'help'\} inert=\{activeModule !== 'help'\}/)
})

test('direct links and Back/Forward resync module and selected Help topic', () => {
  assert.match(hook, /const initialModulePosition = useRef\(true\)/)
  assert.match(hook, /window\.history\.scrollRestoration = 'manual'/)
  assert.match(hook, /window\.addEventListener\('hashchange', syncFromLocation\)/)
  assert.match(hook, /setActiveModule\(moduleFromHash\(window\.location\.hash\)\)/)
  assert.match(hook, /setHelpTopic\(helpTopicFromHash\(window\.location\.hash\)\)/)
  assert.match(hook, /window\.requestAnimationFrame\(/)
})

test('keyboard focus targets visible content and hidden destinations are inert', () => {
  assert.match(help, /tabIndex="-1"/)
  assert.match(help, /onClick=\{\(\) => chooseTopic\(topic\)\}/)
  assert.match(css, /\.help-article h3:focus-visible/)
  assert.match(app, /hidden=\{activeModule !== 'help'\} inert=\{activeModule !== 'help'\}/)
  assert.match(app, /hidden=\{activeModule !== 'about'\} inert=\{activeModule !== 'about'\}/)
})

test('responsive Help stacks by 480px and scroll code has no fixed header offset', () => {
  assert.match(css, /\.help-layout\s*\{[^}]*grid-template-columns:\s*minmax\(220px, 290px\) minmax\(0, 1fr\)/s)
  assert.match(css, /@media \(max-width: 480px\)\s*\{[\s\S]*?\.help-layout, \.about-grid \{ grid-template-columns: 1fr; \}/)
  assert.match(css, /\.module-section[^{}]*\{[^}]*scroll-margin-block-start: var\(--workspace-clearance\)/)
  assert.match(globalCss, /scroll-padding-block-start: var\(--workspace-scroll-inset, var\(--workspace-clearance\)\)/)
  assert.match(globalCss, /--workspace-clearance: 28px/)
  assert.doesNotMatch(hook, /scrollIntoView/)
  assert.doesNotMatch(globalCss, /scroll-behavior:\s*smooth/)
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.dashboard-header \{ position: relative/)
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.dashboard-header \.header-actions \{\s*width: 100%/)
  assert.match(css, /@media \(max-width: 480px\)[\s\S]*?\.help-layout, \.about-grid \{ grid-template-columns: 1fr; \}/)
})

test('desktop actions are compact and wrap accessibly at responsive widths', () => {
  assert.match(css, /\.header-actions \{[^}]*flex-flow: row wrap; gap: 8px;/)
  assert.match(css, /\.header-actions \.last-updated \{[^}]*white-space: nowrap/)
  assert.match(css, /@media \(max-width: 980px\)[\s\S]*?\.header-actions \{ flex-wrap: wrap/)
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.header-actions \{ width: 100%; justify-content: flex-start/)
  assert.match(css, /@media \(max-width: 480px\)[\s\S]*?\.header-actions \.last-updated \{ flex-basis: 100%;/)
})

test('About attribution is distinct and global footer retains exact wording', () => {
  assert.match(about, /className="about-attribution" aria-label="Product attribution"/)
  assert.match(about, /Tanashi Studio™/)
  assert.match(about, /© 2026 Tanashi Studio\. All rights reserved\./)
  assert.match(app, /<footer className="dashboard-footer">[\s\S]*?Tanashi Studio™[\s\S]*?© 2026 Tanashi Studio\. All rights reserved\./)
  assert.doesNotMatch(about, /<footer className="about-brand"/)
  assert.doesNotMatch(about, /<h3>SentinelIP<\/h3>/)
})

test('seven modules, operator destination, existing polling, and app state remain in place', () => {
  for (const id of ['overview', 'scope-discovery', 'remote-sensors', 'perimeter', 'events-analytics', 'data-lifecycle']) assert.ok(app.includes(`id="module-${id}"`))
  for (const id of ['operations', 'detections']) assert.ok(review.includes(`id="module-${id}"`))
  for (const state of ['severityFilter', 'ipDraft', 'ipFilter', 'timeRange', 'exportRangeMode', 'exportFromLocal', 'exportUntilLocal', 'pageSize']) assert.ok(app.includes(`const [${state},`))
  assert.match(app, /setInterval\(\(\) => \{\s*loadData\(\)\s*\},\s*5000\)/)
  assert.equal((app.match(/fetch\(/g) ?? []).length, 6)
})
