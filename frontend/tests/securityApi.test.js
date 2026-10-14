import assert from 'node:assert/strict'
import test from 'node:test'

import {
  attachIncidentEvidence,
  detachIncidentEvidence,
  loadIncidentReviewEvidence,
  loadIncidentReviews,
  loadRelatedIncidentEvidence,
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
