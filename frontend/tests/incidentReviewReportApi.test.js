import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  buildIncidentReviewHtmlReportUrl,
  buildIncidentReviewJsonReportUrl,
  downloadIncidentReviewJson,
  incidentReviewJsonFilename,
  IncidentReviewReportError,
  openIncidentReviewHtmlReport,
  triggerIncidentReviewJsonDownload,
} from '../src/services/incidentReviewReportApi.js'

test('report URLs use the existing API base and fixed endpoints with validated IDs', () => {
  assert.equal(buildIncidentReviewJsonReportUrl(41), 'http://127.0.0.1:8000/incident-reviews/41/report.json')
  assert.equal(buildIncidentReviewHtmlReportUrl(41), 'http://127.0.0.1:8000/incident-reviews/41/report.html')
  for (const invalid of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '41', '41/report.json']) {
    assert.throws(() => buildIncidentReviewJsonReportUrl(invalid), TypeError)
    assert.throws(() => buildIncidentReviewHtmlReportUrl(invalid), TypeError)
  }
  assert.equal(buildIncidentReviewJsonReportUrl(2, '../report.html'),
    'http://127.0.0.1:8000/incident-reviews/2/report.json')
})

test('JSON download uses GET, no-store, forwards AbortSignal, returns the response Blob and safe server filename', async () => {
  const originalFetch = globalThis.fetch
  const controller = new AbortController()
  const blob = new Blob(['report'])
  let request
  globalThis.fetch = async (url, options) => {
    request = { url, options }
    return { ok: true, blob: async () => blob,
      headers: { get: (name) => name === 'content-disposition'
        ? 'attachment; filename="sentinelip-incident-review-41-20261019T051500Z.json"' : null } }
  }
  try {
    const result = await downloadIncidentReviewJson(41, controller.signal)
    assert.equal(request.url, buildIncidentReviewJsonReportUrl(41))
    assert.equal(request.options.method, 'GET')
    assert.equal(request.options.cache, 'no-store')
    assert.equal(request.options.signal, controller.signal)
    assert.equal(result.blob, blob)
    assert.equal(result.filename, 'sentinelip-incident-review-41-20261019T051500Z.json')
  } finally { globalThis.fetch = originalFetch }
})

test('malicious, mismatched, or nonconforming Content-Disposition falls back to numeric review ID', () => {
  const fallback = 'sentinelip-incident-review-41.json'
  for (const header of [
    'attachment; filename="../../evil.json"',
    'attachment; filename="sentinelip-incident-review-42-20261019T051500Z.json"',
    'attachment; filename="sentinelip-incident-review-41-20261019T051500Z.json\\nX-Evil: yes"',
    'attachment; filename="sentinelip-incident-review-41-20261019T051500Z.json"; filename*=utf-8',
    'attachment; filename="evil\\".json"',
  ]) assert.equal(incidentReviewJsonFilename(41, header), fallback)
  assert.equal(incidentReviewJsonFilename(41, ''), fallback)
})

test('safe status errors do not read or expose arbitrary response bodies; abort is forwarded', async () => {
  const originalFetch = globalThis.fetch
  for (const [status, message] of [[404, 'Incident Review report is no longer available.'],
    [413, 'Incident Review report exceeds the allowed export size.'],
    [500, 'Incident Review report request failed.']]) {
    globalThis.fetch = async () => ({ ok: false, status, text: async () => { throw new Error('must not read') } })
    await assert.rejects(downloadIncidentReviewJson(8), (error) => {
      assert.ok(error instanceof IncidentReviewReportError)
      assert.equal(error.message, message)
      assert.equal(error.message.includes('must not read'), false)
      return true
    })
  }
  let receivedSignal
  const controller = new AbortController()
  globalThis.fetch = async (_url, options) => {
    receivedSignal = options.signal
    return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => {
      const error = new Error('aborted')
      error.name = 'AbortError'
      reject(error)
    }, { once: true }))
  }
  try {
    const pending = downloadIncidentReviewJson(8, controller.signal)
    controller.abort()
    await assert.rejects(pending, { name: 'AbortError' })
    assert.equal(receivedSignal, controller.signal)
  } finally { globalThis.fetch = originalFetch }
})

test('download creates a temporary anchor and always removes it and revokes the object URL', () => {
  const events = []
  const anchor = { click: () => events.push('click'), remove: () => events.push('remove') }
  const browser = {
    URL: { createObjectURL: (blob) => { assert.equal(blob, 'blob'); events.push('create'); return 'blob:report' },
      revokeObjectURL: (url) => { assert.equal(url, 'blob:report'); events.push('revoke') } },
    document: { createElement: (tag) => { assert.equal(tag, 'a'); return anchor },
      body: { appendChild: (node) => { assert.equal(node, anchor); events.push('append') } } },
  }
  triggerIncidentReviewJsonDownload('blob', 'safe.json', browser)
  assert.equal(anchor.href, 'blob:report')
  assert.equal(anchor.download, 'safe.json')
  assert.deepEqual(events, ['create', 'append', 'click', 'remove', 'revoke'])
})

test('printable report opens only the fixed URL in a new tab with opener protections', () => {
  const events = []
  const popup = {
    document: { createElement: (tag) => { assert.equal(tag, 'meta'); return {} },
      head: { appendChild: (meta) => { events.push(['referrer', meta.name, meta.content]) } } },
    location: { replace: (url) => events.push(['navigate', url]) },
  }
  const browser = { window: { open: (...args) => { events.push(['open', ...args]); return popup } } }
  assert.equal(openIncidentReviewHtmlReport(13, browser), popup)
  assert.equal(popup.opener, null)
  assert.deepEqual(events, [
    ['open', 'about:blank', '_blank'],
    ['referrer', 'referrer', 'no-referrer'],
    ['navigate', buildIncidentReviewHtmlReportUrl(13)],
  ])
  const blocked = { window: { open: () => null } }
  assert.equal(openIncidentReviewHtmlReport(13, blocked), null)
  assert.throws(() => openIncidentReviewHtmlReport('../evil', browser), TypeError)
})

test('handoff component protects selection races, aborts replacements, and has no mutation or storage behavior', async () => {
  const source = await readFile(new URL('../src/components/IncidentReviewHandoffActions.jsx', import.meta.url), 'utf8')
  assert.match(source, /requestRef\.current\?\.abort\(\)/)
  assert.match(source, /selectedIdRef\.current !== requestedId/)
  assert.match(source, /generation !== generationRef\.current/)
  assert.match(source, /return \(\) => \{[\s\S]*requestRef\.current\?\.abort\(\)/)
  assert.match(source, /Preparing JSON…/)
  assert.match(source, /disabled=\{!validReviewId \|\| pending\}/)
  assert.match(source, /Allow pop-ups to open the printable report\./)
  assert.doesNotMatch(source, /updateIncidentReview|addIncidentReviewNote|attachIncidentEvidence|detachIncidentEvidence|window\.print|localStorage|sessionStorage|indexedDB|dangerouslySetInnerHTML/)
  assert.match(source, /Download JSON/)
  assert.match(source, /Printable Report/)
})
