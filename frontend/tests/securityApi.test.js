import assert from 'node:assert/strict'
import test from 'node:test'

import {
  attachIncidentEvidence,
  addIncidentReviewNote,
  detachIncidentEvidence,
  loadIncidentReviewOperations,
  loadIncidentReviewActivity,
  buildIncidentReviewActivityQuery,
  buildIncidentReviewTrendsQuery,
  loadIncidentReviewTrends,
  loadIncidentReviewSites,
  buildIncidentReviewSitesQuery,
  buildIncidentReviewScopesQuery,
  buildIncidentReviewDevicesQuery,
  loadIncidentReviewScopes,
  loadIncidentReviewDevices,
  buildIncidentReviewOperationsQuery,
  loadIncidentReviewEvidence,
  loadIncidentReviewNotes,
  loadIncidentReviews,
  loadIncidentReviewTimeline,
  loadRelatedIncidentEvidence,
  updateIncidentReview,
} from '../src/services/securityApi.js'
import { formatReviewAge, formatSiteWorkloadAge } from '../src/services/incidentReviewFormat.js'
import {
  applyDeviceDrilldown,
  applyScopeDrilldown,
  applySiteContextToQueue,
  isCurrentReviewQueueResult,
  requestIncidentReviewSelection,
  siteContextFromWorkloadRow,
} from '../src/services/incidentReviewOperationsState.js'

test('operations request uses explicit bounded filters, sort, and pagination', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(url)
    return { ok: true, json: async () => ({ summary: {}, queue: [], pagination: {} }) }
  }
  try {
    const query = buildIncidentReviewOperationsQuery({ state: 'OPEN', site_id: 3,
      has_evidence: false, has_attention: true, attention_signal: 'AGING_REVIEW',
      unresolved_only: true, sort: 'oldest_open', limit: 50, offset: 100 })
    assert.match(query, /state=OPEN/)
    assert.match(query, /has_evidence=false/)
    assert.match(query, /unresolved_only=true/)
    assert.match(query, /has_attention=true/)
    assert.match(query, /attention_signal=AGING_REVIEW/)
    assert.match(buildIncidentReviewOperationsQuery({ has_attention: false }), /has_attention=false/)
    await loadIncidentReviewOperations({ state: 'OPEN', sort: 'priority', limit: 10, offset: 20 })
    assert.match(calls[0], /\/incident-review-operations\?/)
    assert.match(calls[0], /sort=priority/)
    assert.match(calls[0], /limit=10/)
  } finally { globalThis.fetch = originalFetch }
})

test('operations request propagates API errors', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => ({ ok: false, status: 422 })
  try { await assert.rejects(loadIncidentReviewOperations(), /Security API request failed \(422\)/) }
  finally { globalThis.fetch = originalFetch }
})

test('activity feed request exposes only the explicit filters and bounded pagination', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(url)
    return { ok: true, json: async () => ({ activity: [], pagination: { limit: 10, offset: 20, total: 0 } }) }
  }
  try {
    const query = buildIncidentReviewActivityQuery({ event_type: 'STATE_CHANGED', incident_review_id: 5,
      site_id: 3, scope_id: 7, device_id: 8, since: '2026-10-01T00:00:00Z',
      until: '2026-10-02T00:00:00Z', limit: 10, offset: 20 })
    for (const expected of ['event_type=STATE_CHANGED', 'incident_review_id=5', 'site_id=3',
      'scope_id=7', 'device_id=8', 'since=', 'until=', 'limit=10', 'offset=20']) {
      assert.ok(query.includes(expected), expected)
    }
    await loadIncidentReviewActivity({ event_type: 'REVIEW_CLOSED', site_id: 3, limit: 10, offset: 20 })
    assert.match(calls[0], /\/incident-review-operations\/activity\?/)
    assert.match(calls[0], /event_type=REVIEW_CLOSED/)
    assert.match(calls[0], /site_id=3/)
    assert.match(calls[0], /offset=20/)
    globalThis.fetch = async () => ({ ok: false, status: 422 })
    await assert.rejects(loadIncidentReviewActivity(), /Security API request failed \(422\)/)
  } finally { globalThis.fetch = originalFetch }
})

test('workload trends request supports the four fixed windows and propagates errors', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(url)
    return { ok: true, json: async () => ({ window: '30d', series: [], current_snapshot: {} }) }
  }
  try {
    assert.equal(buildIncidentReviewTrendsQuery(), 'window=30d')
    for (const window of ['24h', '7d', '30d', '90d']) {
      assert.equal(buildIncidentReviewTrendsQuery(window), `window=${window}`)
    }
    assert.throws(() => buildIncidentReviewTrendsQuery('all'), /Unsupported incident review trends window/)
    await loadIncidentReviewTrends('24h')
    assert.match(calls[0], /\/incident-review-operations\/trends\?window=24h/)
    globalThis.fetch = async () => ({ ok: false, status: 422 })
    await assert.rejects(loadIncidentReviewTrends('7d'), /Security API request failed \(422\)/)
  } finally { globalThis.fetch = originalFetch }
})

test('site workload request carries independent sort and pagination and propagates errors', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(url)
    return { ok: true, json: async () => ({ sites: [], pagination: { limit: 10, offset: 20, total: 0 } }) }
  }
  try {
    assert.match(buildIncidentReviewSitesQuery({ sort: 'attention_desc', limit: 10, offset: 20 }), /sort=attention_desc/)
    await loadIncidentReviewSites({ sort: 'site_name', limit: 10, offset: 20 })
    assert.match(calls[0], /\/incident-review-operations\/sites\?/)
    assert.match(calls[0], /sort=site_name/)
    assert.match(calls[0], /offset=20/)
    globalThis.fetch = async () => ({ ok: false, status: 422 })
    await assert.rejects(loadIncidentReviewSites(), /Security API request failed \(422\)/)
  } finally { globalThis.fetch = originalFetch }
})

test('queue request can filter explicitly to unattributed reviews', () => {
  assert.match(buildIncidentReviewOperationsQuery({ unattributed_only: true }), /unattributed_only=true/)
  assert.match(buildIncidentReviewOperationsQuery({ unattributed_scope_only: true }), /unattributed_scope_only=true/)
  assert.match(buildIncidentReviewOperationsQuery({ unattributed_device_only: true }), /unattributed_device_only=true/)
})

test('scope and device workload requests require site context and encode pagination and sorting', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(url)
    return { ok: true, json: async () => ({ scopes: [], devices: [], pagination: { total: 0 } }) }
  }
  try {
    assert.throws(() => buildIncidentReviewScopesQuery(), /exactly one selected site/)
    assert.throws(() => buildIncidentReviewDevicesQuery({ site_id: 4, unattributed_only: true }), /exactly one selected site/)
    assert.match(buildIncidentReviewScopesQuery({ site_id: 4 }, { sort: 'name', limit: 10, offset: 20 }), /site_id=4/)
    assert.match(buildIncidentReviewDevicesQuery({ unattributed_only: true }, { sort: 'label', limit: 5, offset: 15 }), /unattributed_only=true/)
    await loadIncidentReviewScopes({ site_id: 4 }, { sort: 'attention_desc', limit: 10, offset: 20 })
    await loadIncidentReviewDevices({ unattributed_only: true }, { sort: 'label', limit: 5, offset: 15 })
    assert.match(calls[0], /\/incident-review-operations\/scopes\?/)
    assert.match(calls[0], /site_id=4/)
    assert.match(calls[0], /sort=attention_desc/)
    assert.match(calls[0], /offset=20/)
    assert.match(calls[1], /\/incident-review-operations\/devices\?/)
    assert.match(calls[1], /unattributed_only=true/)
    assert.match(calls[1], /sort=label/)
    globalThis.fetch = async () => ({ ok: false, status: 503 })
    await assert.rejects(loadIncidentReviewScopes({ site_id: 4 }), /Security API request failed \(503\)/)
    await assert.rejects(loadIncidentReviewDevices({ site_id: 4 }), /Security API request failed \(503\)/)
  } finally { globalThis.fetch = originalFetch }
})

test('site, scope, and device drill-down transitions preserve context and reset queue paging', () => {
  const initial = { site_id: 2, scope_id: 3, device_id: 4, has_attention: true, offset: 60 }
  const site = siteContextFromWorkloadRow({ site_id: null })
  assert.deepEqual(site, { site_id: null, unattributed_only: true })
  assert.deepEqual(applySiteContextToQueue(initial, { site_id: 9, unattributed_only: false }), {
    has_attention: true, site_id: 9, offset: 0,
  })
  assert.deepEqual(applySiteContextToQueue(initial, site), {
    has_attention: true, unattributed_only: true, offset: 0,
  })
  assert.deepEqual(applyScopeDrilldown({ site_id: 2, device_id: 4, offset: 40 }, null), {
    site_id: 2, device_id: 4, unattributed_scope_only: true, offset: 0,
  })
  assert.deepEqual(applyScopeDrilldown({ unattributed_only: true, offset: 5 }, 7), {
    unattributed_only: true, scope_id: 7, offset: 0,
  })
  assert.deepEqual(applyDeviceDrilldown({ unattributed_only: true, scope_id: 3, offset: 20 }, 8), {
    unattributed_only: true, scope_id: 3, device_id: 8, offset: 0,
  })
})

test('a queue result is visible only for the filter and page query that requested it', () => {
  const response = { queryKey: '{"site_id":2,"offset":0}', result: { queue: [{ id: 3 }] } }
  assert.deepEqual(isCurrentReviewQueueResult(response, '{"site_id":2,"offset":0}'), { queue: [{ id: 3 }] })
  assert.equal(isCurrentReviewQueueResult(response, '{"site_id":9,"offset":0}'), null)
  assert.equal(isCurrentReviewQueueResult(response, '{"site_id":2,"offset":20}'), null)
})

test('queue and activity selection use the same controlled review navigation callback', () => {
  for (const source of ['queue', 'activity']) {
    let selectedReviewId = null
    requestIncidentReviewSelection(41, (reviewId) => { selectedReviewId = reviewId })
    assert.equal(selectedReviewId, 41, `${source} selection reaches the controlled detail selection`)
  }
})

test('review age labels are workload buckets and closed age is blank', () => {
  assert.equal(formatReviewAge(20, 'LT_1H'), '< 1h')
  assert.equal(formatReviewAge(3600, 'H1_24'), '1h–24h')
  assert.equal(formatReviewAge(null, null), '—')
  assert.equal(formatSiteWorkloadAge(90000), '1d')
  assert.equal(formatSiteWorkloadAge(null), '—')
})

test('incident review API reads suggestions and mutates links only on explicit calls', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, options })
    return { ok: true, json: async () => ({ items: [] }) }
  }

  try {
    await loadIncidentReviews()
    await loadIncidentReviewEvidence(7)
    await loadRelatedIncidentEvidence(7)
    assert.equal(calls.length, 3)
    assert.match(calls[0].url, /\/incident-reviews\?limit=20&offset=0$/)
    assert.match(calls[1].url, /\/incident-reviews\/7\/evidence\?limit=100&offset=0$/)
    assert.match(calls[2].url, /\/incident-reviews\/7\/related-evidence\?limit=100$/)

    await attachIncidentEvidence(7, { evidence_type: 'THREAT_DETECTION', evidence_id: 12 })
    await detachIncidentEvidence(7, { evidence_type: 'THREAT_DETECTION', evidence_id: 12 })
    assert.equal(calls[3].options.method, 'POST')
    assert.deepEqual(JSON.parse(calls[3].options.body), {
      evidence_type: 'THREAT_DETECTION', evidence_id: 12,
    })
    assert.equal(calls[4].options.method, 'DELETE')
    assert.match(calls[4].url, /\/incident-reviews\/7\/evidence\/THREAT_DETECTION\/12$/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('incident review history reads and note creation use explicit bounded API calls', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, options })
    return { ok: true, json: async () => ({ items: [] }) }
  }
  try {
    await loadIncidentReviewTimeline(9)
    await loadIncidentReviewNotes(9)
    await addIncidentReviewNote(9, 'Analyst observation')
    await updateIncidentReview(9, { state: 'IN_REVIEW' })
    assert.match(calls[0].url, /\/incident-reviews\/9\/timeline\?limit=100&offset=0$/)
    assert.match(calls[1].url, /\/incident-reviews\/9\/notes\?limit=100&offset=0$/)
    assert.equal(calls[2].options.method, 'POST')
    assert.deepEqual(JSON.parse(calls[2].options.body), { note_text: 'Analyst observation' })
    assert.match(calls[3].url, /\/incident-reviews\/9$/)
    assert.equal(calls[3].options.method, 'PATCH')
    assert.deepEqual(JSON.parse(calls[3].options.body), { state: 'IN_REVIEW' })
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('review draft, close, and reopen use explicit PATCH mutations and surface server errors', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, options })
    if (calls.length === 4) {
      return { ok: false, status: 422, json: async () => ({ detail: 'A final analyst summary is required.' }) }
    }
    return { ok: true, json: async () => ({ id: 14, state: 'OPEN' }) }
  }
  try {
    await updateIncidentReview(14, { disposition: 'BENIGN', final_summary: 'Reviewed.' })
    await updateIncidentReview(14, { disposition: 'BENIGN', final_summary: 'Reviewed.', state: 'CLOSED' })
    await updateIncidentReview(14, { state: 'OPEN' })
    await assert.rejects(
      updateIncidentReview(14, { state: 'CLOSED' }),
      /Security API request failed \(422\): A final analyst summary is required\./,
    )
    assert.deepEqual(calls.map(({ options }) => JSON.parse(options.body)), [
      { disposition: 'BENIGN', final_summary: 'Reviewed.' },
      { disposition: 'BENIGN', final_summary: 'Reviewed.', state: 'CLOSED' },
      { state: 'OPEN' },
      { state: 'CLOSED' },
    ])
    assert.ok(calls.every(({ url, options }) => url.endsWith('/incident-reviews/14') && options.method === 'PATCH'))
  } finally {
    globalThis.fetch = originalFetch
  }
})
