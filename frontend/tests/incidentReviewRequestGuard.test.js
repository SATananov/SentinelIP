import assert from 'node:assert/strict'
import test from 'node:test'

import {
  createIncidentReviewRequestGuard,
  createOperationsRequestGuard,
} from '../src/services/incidentReviewRequestGuard.js'

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

function deferred() {
  let resolve
  let reject
  const promise = new Promise((accept, fail) => { resolve = accept; reject = fail })
  return { promise, resolve, reject }
}

test('controlled selection null to A loads A and selection A to B rejects late A results and errors', async () => {
  const guard = createIncidentReviewRequestGuard()
  const requestA = deferred()
  const requestB = deferred()
  const rendered = []
  const aToken = guard.selectAndBegin(11)
  const bTokenPromise = requestA.promise.then((value) => {
    if (guard.isCurrent(aToken)) rendered.push(value)
  }, (error) => {
    if (guard.isCurrent(aToken)) rendered.push(error.message)
  })
  const bToken = guard.selectAndBegin(12)
  requestA.resolve('review A')
  requestB.resolve('review B')
  if (guard.isCurrent(bToken)) rendered.push(await requestB.promise)
  await bTokenPromise
  assert.deepEqual(rendered, ['review B'])
  assert.equal(guard.isCurrent(aToken), false)
  assert.equal(guard.isCurrent(bToken), true)
})

test('a non-abort error from review A is ignored after controlled selection moves to B', async () => {
  const guard = createIncidentReviewRequestGuard()
  const requestA = deferred()
  let detailError = null
  const aToken = guard.selectAndBegin(31)
  const aCompletion = requestA.promise.catch((error) => {
    if (guard.isCurrent(aToken)) detailError = error.message
  })
  const bToken = guard.selectAndBegin(32)
  requestA.reject(new Error('late A failure'))
  await aCompletion
  assert.equal(detailError, null)
  assert.equal(guard.isCurrent(bToken), true)
})

test('controlled B errors are current, closing invalidates B, and stale mutation A is ignored', async () => {
  const guard = createIncidentReviewRequestGuard()
  const requestA = guard.selectAndBegin(21)
  const mutationA = guard.begin(21)
  const requestB = guard.selectAndBegin(22)
  assert.equal(guard.isCurrent(requestA), false)
  assert.equal(guard.isCurrent(mutationA), false)
  assert.equal(guard.isCurrent(requestB), true)

  let acceptedError = null
  if (guard.isCurrent(requestB)) acceptedError = 'B failed'
  assert.equal(acceptedError, 'B failed')
  guard.invalidate()
  assert.equal(guard.isCurrent(requestB), false)
})

test('operations resource generations accept only the active queue, site, activity, or trend request', () => {
  const guard = createOperationsRequestGuard()
  for (const resource of ['queue', 'sites', 'activity', 'trends']) {
    const oldRequest = guard.begin(resource)
    const currentRequest = guard.begin(resource)
    assert.equal(guard.isCurrent(resource, oldRequest), false)
    assert.equal(guard.isCurrent(resource, currentRequest), true)
    guard.invalidate(resource)
    assert.equal(guard.isCurrent(resource, currentRequest), false)
  }
})

test('superseded non-abort operation errors and completions cannot alter resource state', async () => {
  const guard = createOperationsRequestGuard()
  for (const resource of ['queue', 'sites', 'scopes', 'devices', 'activity', 'trends']) {
    let state = { data: null, error: null, loading: false }
    const older = guard.begin(resource)
    state.loading = true
    const current = guard.begin(resource)
    state.loading = true
    if (guard.isCurrent(resource, older)) state = { data: 'stale', error: null, loading: false }
    if (guard.isCurrent(resource, older)) state = { data: null, error: 'late network error', loading: false }
    assert.deepEqual(state, { data: null, error: null, loading: true })
    if (guard.isCurrent(resource, current)) state = { data: 'current', error: null, loading: false }
    assert.deepEqual(state, { data: 'current', error: null, loading: false })
  }
})
