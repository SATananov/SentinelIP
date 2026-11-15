import assert from 'node:assert/strict'
import test from 'node:test'

import {
  HttpEndpointApiError,
  httpHistoryUrl,
  httpInspectionUrl,
  inspectHttpEndpoint,
  loadHttpEndpointHistory,
} from '../src/services/httpEndpointApi.js'

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body }
}

const endpoint = { scopeId: 11, deviceId: 22, portId: 33 }

test('inspection and history URLs use the configured API base and selected inventory IDs', () => {
  assert.equal(httpInspectionUrl(11, 22, 33), 'http://127.0.0.1:8000/scopes/11/devices/22/ports/33/fingerprint-http')
  assert.equal(httpHistoryUrl(11, 22, 33), 'http://127.0.0.1:8000/scopes/11/devices/22/ports/33/http-observations')
  assert.equal(httpHistoryUrl(11, 22, 33, { cursor: 'abc+/=' }),
    'http://127.0.0.1:8000/scopes/11/devices/22/ports/33/http-observations?cursor=abc%2B%2F%3D')
  for (const id of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '11']) {
    assert.throws(() => httpInspectionUrl(id, 22, 33), TypeError)
    assert.throws(() => httpHistoryUrl(11, 22, id), TypeError)
  }
  assert.throws(() => httpHistoryUrl(11, 22, 33, { limit: 101 }), TypeError)
  assert.throws(() => httpHistoryUrl(11, 22, 33, { cursor: 'x'.repeat(513) }), TypeError)
})

test('inspection is an explicit POST with the selected HTTP or HTTPS scheme', async () => {
  const originalFetch = globalThis.fetch
  const requests = []
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options })
    return response(200, { outcome: 'RESPONSE_RECEIVED', scheme: JSON.parse(options.body).scheme,
      persistence: { status: 'PERSISTED', observation_id: 7 } })
  }
  try {
    assert.equal(requests.length, 0)
    const controller = new AbortController()
    const http = await inspectHttpEndpoint({ ...endpoint, scheme: 'http', signal: controller.signal })
    const https = await inspectHttpEndpoint({ ...endpoint, scheme: 'https' })
    assert.equal(requests.length, 2)
    assert.deepEqual(requests.map(({ options }) => [options.method, JSON.parse(options.body).scheme]), [
      ['POST', 'http'], ['POST', 'https'],
    ])
    assert.equal(requests[0].options.signal, controller.signal)
    assert.equal(requests[0].options.cache, 'no-store')
    assert.equal(http.scheme, 'http')
    assert.equal(https.scheme, 'https')
    await assert.rejects(inspectHttpEndpoint({ ...endpoint, scheme: 'ftp' }), TypeError)
  } finally { globalThis.fetch = originalFetch }
})

test('history uses GET, no-store, cancellation and the server cursor without fetching other pages', async () => {
  const originalFetch = globalThis.fetch
  let request
  const history = { items: [], limit: 20, returned: 0, next_cursor: 'next-page' }
  globalThis.fetch = async (url, options) => {
    request = { url, options }
    return response(200, history)
  }
  try {
    const controller = new AbortController()
    assert.deepEqual(await loadHttpEndpointHistory({ ...endpoint, signal: controller.signal }), history)
    assert.equal(request.url, httpHistoryUrl(11, 22, 33))
    assert.equal(request.options.method, 'GET')
    assert.equal(request.options.cache, 'no-store')
    assert.equal(request.options.signal, controller.signal)
    assert.equal(request.url.includes('cursor='), false)
    await loadHttpEndpointHistory({ ...endpoint, cursor: 'next-page' })
    assert.equal(request.url, httpHistoryUrl(11, 22, 33, { cursor: 'next-page' }))
  } finally { globalThis.fetch = originalFetch }
})

test('capacity rejection is returned as an inspection outcome and is not treated as a request error', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => response(200, {
    outcome: 'CAPACITY_REJECTED', persistence: { status: 'NOT_ATTEMPTED', reason: 'capacity_rejected' },
  })
  try {
    const result = await inspectHttpEndpoint({ ...endpoint, scheme: 'http' })
    assert.equal(result.outcome, 'CAPACITY_REJECTED')
    assert.equal(result.persistence.status, 'NOT_ATTEMPTED')
  } finally { globalThis.fetch = originalFetch }
})

test('authorization, target, persistence and network failures map to bounded client errors', async () => {
  const originalFetch = globalThis.fetch
  try {
    const cases = [
      [403, { detail: 'raw scope data' }, 'authorization'],
      [404, { detail: 'raw database path' }, 'missing_resource'],
      [409, { detail: 'DNS changed' }, 'scope_changed'],
      [422, { detail: 'traceback' }, 'request_rejected'],
      [503, { detail: { code: 'observation_persistence_failed', inspection_outcome: 'TIMEOUT' } }, 'persistence_failure'],
    ]
    for (const [status, body, kind] of cases) {
      globalThis.fetch = async () => response(status, body)
      await assert.rejects(inspectHttpEndpoint({ ...endpoint, scheme: 'http' }), (error) => {
        assert.ok(error instanceof HttpEndpointApiError)
        assert.equal(error.kind, kind)
        assert.equal(error.message.includes('raw'), false)
        assert.equal(error.message.includes('traceback'), false)
        if (kind === 'persistence_failure') assert.equal(error.inspectionOutcome, 'TIMEOUT')
        return true
      })
    }
    globalThis.fetch = async () => { throw new TypeError('network detail') }
    await assert.rejects(loadHttpEndpointHistory(endpoint), (error) => error.kind === 'network_error')
  } finally { globalThis.fetch = originalFetch }
})

test('invalid inspection and history response shapes are rejected', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => response(200, { outcome: 'RESPONSE_RECEIVED' })
    await assert.rejects(inspectHttpEndpoint({ ...endpoint, scheme: 'http' }), /invalid inspection result/)
    globalThis.fetch = async () => response(200, { items: 'not a list' })
    await assert.rejects(loadHttpEndpointHistory(endpoint), /invalid observation history/)
  } finally { globalThis.fetch = originalFetch }
})
