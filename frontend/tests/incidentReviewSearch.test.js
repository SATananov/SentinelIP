import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  buildIncidentReviewSearchQuery,
  createIncidentReviewSearchRequestController,
  dateInputToSearchTimestamp,
  loadIncidentReviewSearch,
  nextIncidentReviewSearchOffset,
  previousIncidentReviewSearchOffset,
  selectIncidentReviewSearchResult,
} from '../src/services/incidentReviewSearchApi.js'

test('search query uses only the fixed endpoint parameters and defaults to a bounded first page', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options })
    return { ok: true, json: async () => ({ items: [], limit: 20, offset: 0, has_more: false }) }
  }
  try {
    const controller = new AbortController()
    const result = await loadIncidentReviewSearch({
      title: '  firewall auth* OR (vpn)  ', state: 'CLOSED', priority: 'HIGH',
      disposition: 'BENIGN', site_id: '3', scope_id: 4, device_id: '5',
      created_from: '2026-09-01T00:00:00.000Z', created_until: '2026-09-02T00:00:00.000Z',
      closed_from: '', confidence: 'HIGH', arbitrary: 'ignored',
    }, controller.signal)
    assert.equal(result.limit, 20)
    const request = calls[0]
    const url = new URL(request.url)
    assert.equal(url.pathname, '/incident-reviews/search')
    assert.equal(url.searchParams.get('title'), 'firewall auth* OR (vpn)')
    assert.equal(url.searchParams.get('state'), 'CLOSED')
    assert.equal(url.searchParams.get('priority'), 'HIGH')
    assert.equal(url.searchParams.get('disposition'), 'BENIGN')
    assert.equal(url.searchParams.get('site_id'), '3')
    assert.equal(url.searchParams.get('scope_id'), '4')
    assert.equal(url.searchParams.get('device_id'), '5')
    assert.equal(url.searchParams.get('created_from'), '2026-09-01T00:00:00.000Z')
    assert.equal(url.searchParams.get('created_until'), '2026-09-02T00:00:00.000Z')
    assert.equal(url.searchParams.has('closed_from'), false)
    assert.equal(url.searchParams.has('confidence'), false)
    assert.equal(url.searchParams.has('arbitrary'), false)
    assert.equal(url.searchParams.get('limit'), '20')
    assert.equal(url.searchParams.get('offset'), '0')
    assert.equal(request.options.method, 'GET')
    assert.equal(request.options.cache, 'no-store')
    assert.equal(request.options.signal, controller.signal)
  } finally { globalThis.fetch = originalFetch }
})

test('search query rejects missing or too-short title, invalid IDs, enums, dates, and bounds before fetch', () => {
  for (const title of ['', '  ', 'ab', '!!?']) {
    assert.throws(() => buildIncidentReviewSearchQuery({ title }), /three searchable title characters/)
  }
  assert.throws(() => buildIncidentReviewSearchQuery({ title: 'review', site_id: '0' }), /positive integer/)
  assert.throws(() => buildIncidentReviewSearchQuery({ title: 'review', state: 'UNKNOWN' }), /unsupported/)
  assert.throws(() => buildIncidentReviewSearchQuery({ title: 'review', created_from: '2026-01-01T00:00:00' }), /explicit timezone/)
  assert.throws(() => buildIncidentReviewSearchQuery({ title: 'review', limit: 101 }), /limit is out of range/)
  assert.throws(() => buildIncidentReviewSearchQuery({ title: 'review', offset: 100001 }), /offset is out of range/)
  assert.doesNotThrow(() => buildIncidentReviewSearchQuery({ title: 'VPN:!! auth' }))
})

test('date controls convert local calendar starts and inclusive end days to explicit UTC timestamps', () => {
  const from = dateInputToSearchTimestamp('2026-10-01')
  const through = dateInputToSearchTimestamp('2026-10-01', { exclusiveEnd: true })
  assert.match(from, /Z$/)
  assert.match(through, /Z$/)
  assert.ok(Date.parse(through) > Date.parse(from))
  assert.equal(dateInputToSearchTimestamp(''), '')
  assert.throws(() => dateInputToSearchTimestamp('2026-02-30'), /valid calendar date/)
})

test('search API hides response bodies and network exception details while preserving status and aborts', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => ({ ok: false, status: 422, json: async () => ({ detail: 'private SQL text' }) })
    await assert.rejects(loadIncidentReviewSearch({ title: 'review' }), (error) => {
      assert.equal(error.status, 422)
      assert.equal(error.message, 'Check the review title and filters, then try again.')
      return true
    })
    globalThis.fetch = async () => { throw new TypeError('internal host detail') }
    await assert.rejects(loadIncidentReviewSearch({ title: 'review' }), /Incident Review search is unavailable\./)
    globalThis.fetch = async () => { const error = new Error('aborted'); error.name = 'AbortError'; throw error }
    await assert.rejects(loadIncidentReviewSearch({ title: 'review' }), { name: 'AbortError' })
  } finally { globalThis.fetch = originalFetch }
})

test('new searches abort previous requests and stale success or error generations are ignored', () => {
  const requests = createIncidentReviewSearchRequestController()
  const first = requests.start()
  const second = requests.start()
  assert.equal(first.signal.aborted, true)
  assert.equal(first.isCurrent(), false)
  assert.equal(second.signal.aborted, false)
  assert.equal(second.isCurrent(), true)
  requests.abort()
  assert.equal(second.signal.aborted, true)
  assert.equal(second.isCurrent(), false)
})

test('search pagination uses a fixed page size, respects has_more, and stays within offset bounds', () => {
  assert.equal(nextIncidentReviewSearchOffset(0, true), 20)
  assert.equal(nextIncidentReviewSearchOffset(20, true), 40)
  assert.equal(nextIncidentReviewSearchOffset(20, false), 20)
  assert.equal(nextIncidentReviewSearchOffset(100000, true), 100000)
  assert.equal(previousIncidentReviewSearchOffset(40), 20)
  assert.equal(previousIncidentReviewSearchOffset(0), 0)
})

test('search result selection delegates only the review ID through the existing callback', () => {
  const selected = []
  assert.equal(selectIncidentReviewSearchResult(42, (id) => selected.push(id)), true)
  assert.deepEqual(selected, [42])
  assert.equal(selectIncidentReviewSearchResult(0, (id) => selected.push(id)), false)
})

test('discovery component stays bounded to the search projection and keeps queue/detail behavior separate', async () => {
  const source = await readFile(new URL('../src/components/IncidentReviewSearch.jsx', import.meta.url), 'utf8')
  assert.match(source, /Search review titles by word or word beginning/)
  assert.match(source, /selectIncidentReviewSearchResult\(item\.id, onSelectReview\)/)
  assert.match(source, /results\.has_more/)
  assert.match(source, /setResults\(null\)/)
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|confidence|summary|evidence|timeline/)
  assert.match(source, /created_from/)
  assert.match(source, /created_until/)
  assert.match(source, /setOffset\(0\)/)
})
