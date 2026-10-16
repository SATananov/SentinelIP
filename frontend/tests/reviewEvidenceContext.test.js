import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildReviewEvidenceContext,
  clearReviewIntakeRequest,
  createReviewIntakeRequest,
  isValidReviewEvidenceContext,
  isValidPromotedReviewResponse,
  matchesReviewEvidenceResponse,
} from '../src/services/reviewEvidenceContext.js'

const cases = [
  ['THREAT_DETECTION', 'Threat detection'],
  ['THREAT_CORRELATION', 'Threat correlation'],
  ['PERIMETER_DETECTION', 'Perimeter detection'],
  ['PERIMETER_POLICY_CORRELATION', 'Perimeter policy correlation'],
  ['PERIMETER_HOST_CORRELATION', 'Perimeter host correlation'],
  ['EXTERNAL_EXPOSURE_CHANGE', 'Exposure change'],
  ['WEB_DETECTION', 'Web detection'],
]

test('source records map to exact canonical evidence identities and neutral display labels', () => {
  for (const [type, label] of cases) {
    const context = buildReviewEvidenceContext(type, { id: 23, severity: 'HIGH', confidence: 'HIGH', device_id: 8 })
    assert.equal(context.evidence_type, type)
    assert.equal(context.evidence_id, 23)
    assert.equal(context.label, `${label} #23`)
    assert.equal(isValidReviewEvidenceContext(context), true)
    assert.equal('priority' in context, false)
    assert.equal('confidence' in context, false)
    assert.equal('site_id' in context, false)
    assert.equal('scope_id' in context, false)
  }
})

test('perimeter and host contexts use their source record ID, never related event or device IDs', () => {
  const detection = buildReviewEvidenceContext('PERIMETER_DETECTION', { id: 31, primary_event_id: 401, site_id: 7 })
  const host = buildReviewEvidenceContext('PERIMETER_HOST_CORRELATION', { id: 32, event_id: 402, device_id: 9, site_id: 7 })
  assert.equal(detection.evidence_id, 31)
  assert.equal(host.evidence_id, 32)
  assert.equal(detection.sourceContext.site_id, 7)
  assert.equal(host.sourceContext.device_id, 9)
})

test('unsupported types and missing, non-positive, or unsafe record IDs have no context', () => {
  for (const [type, record] of [
    ['LEGACY_INCIDENT', { id: 1 }],
    ['THREAT_DETECTION', {}],
    ['THREAT_DETECTION', { id: 0 }],
    ['THREAT_DETECTION', { id: -1 }],
    ['THREAT_DETECTION', { id: '2' }],
    ['THREAT_DETECTION', { id: Number.MAX_SAFE_INTEGER + 1 }],
  ]) assert.equal(buildReviewEvidenceContext(type, record), null)
  assert.equal(isValidReviewEvidenceContext({ evidence_type: 'THREAT_DETECTION', evidence_id: 0 }), false)
})

test('promotion response must echo the exact immutable evidence reference', () => {
  const context = buildReviewEvidenceContext('WEB_DETECTION', { id: 45 })
  const good = { review: { id: 9, state: 'OPEN', disposition: 'UNREVIEWED' },
    evidence: { evidence_type: 'WEB_DETECTION', evidence_id: 45 } }
  assert.equal(matchesReviewEvidenceResponse(good, context), true)
  assert.equal(isValidPromotedReviewResponse(good, context), true)
  assert.equal(matchesReviewEvidenceResponse({ evidence: { evidence_type: 'THREAT_DETECTION', evidence_id: 45 } }, context), false)
  assert.equal(matchesReviewEvidenceResponse({ evidence: { evidence_type: 'WEB_DETECTION', evidence_id: 46 } }, context), false)
  assert.equal(isValidPromotedReviewResponse({ ...good, review: { ...good.review, state: 'CLOSED' } }, context), false)
})

test('intake cancellation is token-scoped and a new source starts with a clean request', () => {
  const first = createReviewIntakeRequest(1, buildReviewEvidenceContext('THREAT_DETECTION', { id: 12 }))
  assert.ok(Object.isFrozen(first))
  assert.ok(Object.isFrozen(first.evidence))
  assert.equal(clearReviewIntakeRequest(first, 1), null)

  const second = createReviewIntakeRequest(2, buildReviewEvidenceContext('WEB_DETECTION', { id: 19 }))
  assert.equal(clearReviewIntakeRequest(second, 1), second)
  assert.equal(second.evidence.evidence_type, 'WEB_DETECTION')
  assert.equal(second.evidence.evidence_id, 19)
})
