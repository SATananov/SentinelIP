import assert from 'node:assert/strict'
import test from 'node:test'

import {
  attachIncidentEvidence,
  addIncidentReviewNote,
  detachIncidentEvidence,
  loadIncidentReviewEvidence,
  loadIncidentReviewNotes,
  loadIncidentReviews,
  loadIncidentReviewTimeline,
  loadRelatedIncidentEvidence,
  updateIncidentReview,
} from '../src/services/securityApi.js'

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
