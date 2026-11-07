import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const app = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8')
const css = await readFile(new URL('../src/App.css', import.meta.url), 'utf8')
const hook = await readFile(new URL('../src/hooks/useWorkspaceNavigation.js', import.meta.url), 'utf8')
const nav = await readFile(new URL('../src/services/workspaceNavigation.js', import.meta.url), 'utf8')

test('mobile Workspace control exposes the current destination and controlled menu accessibly', () => {
  assert.match(app, /id="mobile-workspace-button"/)
  assert.match(app, /aria-label=\{`Workspace: \$\{WORKSPACE_MODULES\.find/)
  assert.match(app, /aria-expanded=\{mobileMenuOpen\}/)
  assert.match(app, /aria-controls="mobile-workspace-menu"/)
  assert.match(app, /id="mobile-workspace-menu" className="mobile-workspace-menu" aria-label="Workspace destinations"[\s\S]*?hidden=\{!mobileMenuOpen\} inert=\{!mobileMenuOpen\}/)
  assert.match(css, /\.mobile-workspace-menu\[hidden\] \{ display: none; \}/)
  assert.match(css, /\.mobile-workspace-button[^{]*\{[^}]*min-height: 54px/s)
  assert.match(css, /\.mobile-workspace-menu a[^{]*\{[^}]*min-height: 46px/s)
  assert.match(css, /\.mobile-workspace-menu \{[^}]*max-height:[^}]*overflow-y: auto/s)
})

test('mobile menu includes each operational destination and distinct local and support groups', () => {
  assert.match(app, /modules\.map\(\(\{ id, label \}\) => <a key=\{id\} href=\{workspaceHash\(id\)\} aria-current=\{activeModule === id \? 'page' : undefined\}/)
  assert.match(app, /<p className="mobile-menu-group-label">Local operator<\/p>[\s\S]*?workspaceHash\('data-lifecycle'\)/)
  assert.match(app, /<p className="mobile-menu-group-label">Support &amp; Information<\/p>[\s\S]*?\['help', 'about'\]/)
  assert.match(app, /'events-analytics'/)
  assert.match(nav, /id: 'data-lifecycle', label: 'Data Lifecycle'/)
})

test('menu selection closes and keeps the shared module navigation and history behavior', () => {
  assert.match(app, /selectMobileDestination\(event, id\)/)
  assert.match(app, /setMobileMenuOpen\(false\)/)
  assert.match(app, /navigateToModule\(moduleId\)/)
  assert.match(hook, /window\.location\.hash = nextHash/)
  assert.match(hook, /window\.addEventListener\('hashchange', syncFromLocation\)/)
  assert.match(hook, /moduleFromHash\(window\.location\.hash\)/)
  assert.match(app, /aria-current=\{activeModule === id \? 'page' : undefined\}/)
})

test('Escape closes an open menu and restores focus to the Workspace control', () => {
  assert.match(app, /if \(event\.key !== 'Escape'\) return[\s\S]*?event\.stopPropagation\(\)[\s\S]*?setMobileMenuOpen\(false\)[\s\S]*?mobileMenuButtonRef\.current\?\.focus\(\)/)
  assert.match(app, /onKeyDown=\{handleMobileMenuKeyDown\}/)
})

test('responsive navigation preserves desktop sidebar and introduces no fetch or polling', () => {
  assert.match(css, /@media \(min-width: 761px\) \{\s*\.mobile-workspace \{ display: none; \}/)
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.module-nav, \.support-nav \{ display: none; \}/)
  assert.equal((app.match(/setInterval\(/g) ?? []).length, 1)
  assert.equal((app.match(/fetch\(`\$\{API_BASE\}\/health`\)/g) ?? []).length, 1)
  assert.equal((app.match(/<NetworkWorkspace\b/g) ?? []).length, 1)
  assert.equal((app.match(/<SecurityReviewPanel\b/g) ?? []).length, 1)
})

test('external hash navigation closes an open mobile menu and reduced motion disables its transition', () => {
  assert.match(app, /const closeMobileMenu = \(\) => setMobileMenuOpen\(false\)[\s\S]*?window\.addEventListener\('hashchange', closeMobileMenu\)/)
  assert.match(hook, /window\.addEventListener\('hashchange', syncFromLocation\)/)
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)[^{]*\{\s*\.mobile-menu-indicator \{ transition: none; \}/)
})
