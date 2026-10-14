import assert from 'node:assert/strict'
import test from 'node:test'

import { createIncidentReviewRequestGuard } from '../src/services/incidentReviewRequestGuard.js'

test('selecting another review invalidates all earlier detail and mutation requests', () => {
  const guard = createIncidentReviewRequestGuard()
  guard.select(11)
  const detailRequest = guard.begin(11)
  const mutationRequest = guard.begin(11)
  assert.equal(guard.isCurrent(detailRequest), false)
  assert.equal(guard.isCurrent(mutationRequest), true)

  guard.select(12)
  assert.equal(guard.isCurrent(mutationRequest), false)
  const reviewBRequest = guard.begin(12)
  assert.equal(guard.isCurrent(reviewBRequest), true)
})

test('closing the detail invalidates pending requests for the selected review', () => {
  const guard = createIncidentReviewRequestGuard()
  guard.select(7)
  const request = guard.begin(7)
  guard.invalidate()
  assert.equal(guard.isCurrent(request), false)
})
