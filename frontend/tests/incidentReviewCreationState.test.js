import assert from 'node:assert/strict'
import test from 'node:test'

import {
  completeCreatedIncidentReview,
  createIncidentReviewAttemptGuard,
  createIncidentReviewListGuard,
  upsertCreatedIncidentReview,
} from '../src/services/incidentReviewCreationState.js'
import { createIncidentReviewRequestGuard } from '../src/services/incidentReviewRequestGuard.js'

test('only one create attempt can be active and invalidated attempts cannot update UI', () => {
  const guard = createIncidentReviewAttemptGuard()
  const first = guard.begin(0)
  assert.ok(first)
  assert.equal(guard.begin(0), null)
  assert.equal(guard.isCurrent(first), true)
  guard.invalidate()
  assert.equal(guard.isCurrent(first), false)
  assert.equal(guard.maySelectCreatedReview(first, 0), false)
})

test('a current creation selects through the existing review request guard and notifies operations', () => {
  const attemptGuard = createIncidentReviewAttemptGuard()
  const attempt = attemptGuard.begin(3)
  const detailGuard = createIncidentReviewRequestGuard()
  const selected = []
  let localSelection = null
  let operationsRefreshes = 0
  const review = { id: 31, title: 'Created review', state: 'OPEN', priority: 'MEDIUM',
    confidence: 'MEDIUM', disposition: 'UNREVIEWED' }

  const didSelect = completeCreatedIncidentReview({
    review,
    attempt,
    currentSelectionVersion: 3,
    requestGuard: detailGuard,
    onSelectReview: (id) => selected.push(id),
    setSelectedReview: (item) => { localSelection = item },
    refreshOperations: () => { operationsRefreshes += 1 },
  })

  assert.equal(didSelect, true)
  assert.deepEqual(selected, [31])
  assert.equal(localSelection, review)
  assert.equal(operationsRefreshes, 1)
  const detailRequest = detailGuard.begin(31)
  assert.equal(detailGuard.isCurrent(detailRequest), true)
})

test('a create response does not override a deliberate later review selection', () => {
  const attemptGuard = createIncidentReviewAttemptGuard()
  const attempt = attemptGuard.begin(4)
  const detailGuard = createIncidentReviewRequestGuard()
  const selected = []
  let operationsRefreshes = 0
  const didSelect = completeCreatedIncidentReview({
    review: { id: 32 }, attempt, currentSelectionVersion: 5,
    requestGuard: detailGuard,
    onSelectReview: (id) => selected.push(id),
    setSelectedReview: () => assert.fail('stale create must not select'),
    refreshOperations: () => { operationsRefreshes += 1 },
  })
  assert.equal(didSelect, false)
  assert.deepEqual(selected, [])
  assert.equal(operationsRefreshes, 1)
})

test('created review upsert preserves it against a stale list and a fresh list can reconcile it', () => {
  const listGuard = createIncidentReviewListGuard()
  const staleListRequest = listGuard.begin()
  const review = { id: 51, title: 'New' }
  listGuard.invalidate()
  let reviews = upsertCreatedIncidentReview([{ id: 2 }, { id: 1 }], review)
  assert.equal(listGuard.isCurrent(staleListRequest), false)
  assert.deepEqual(reviews.map((item) => item.id), [51, 2, 1])

  const freshListRequest = listGuard.begin()
  const freshServerList = [{ id: 51, title: 'New' }, { id: 2 }]
  if (listGuard.isCurrent(freshListRequest)) reviews = freshServerList
  assert.deepEqual(reviews, freshServerList)
})
