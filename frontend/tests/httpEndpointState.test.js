import assert from 'node:assert/strict'
import test from 'node:test'

import {
  appendUniqueObservations,
  httpEndpointIdentity,
  inspectionPresentation,
  isCurrentHttpEndpointRequest,
  safeResponseHeaders,
  selectableTcpPorts,
  endHttpEndpointRequest,
  tryBeginHttpEndpointRequest,
  verifiedTlsFacts,
} from '../src/services/httpEndpointState.js'

test('only existing open TCP port records are selectable and ordering is stable', () => {
  const ports = [
    { id: 5, port_number: 443, transport: 'TCP', state: 'open' },
    { id: 4, port_number: 80, transport: 'tcp', state: 'closed' },
    { id: 3, port_number: 80, transport: 'tcp', state: 'open' },
    { id: 2, port_number: 53, transport: 'udp', state: 'open' },
    { id: 0, port_number: 22, transport: 'tcp', state: 'open' },
  ]
  assert.deepEqual(selectableTcpPorts(ports).map((port) => port.id), [3, 5])
  assert.deepEqual(selectableTcpPorts(null), [])
})

test('cursor page merging preserves server order, removes duplicates and caps local history', () => {
  const page1 = [{ id: 8, observed_at: 'same' }, { id: 7, observed_at: 'same' }]
  const page2 = [{ id: 7, observed_at: 'same' }, { id: 6, observed_at: 'same' }]
  assert.deepEqual(appendUniqueObservations(page1, page2), [page1[0], page1[1], page2[1]])
  assert.deepEqual(appendUniqueObservations([], Array.from({ length: 5 }, (_, index) => ({ id: index + 1 })), 3), [
    { id: 1 }, { id: 2 }, { id: 3 },
  ])
})

test('endpoint request identity and generation suppress results from a previous selection', () => {
  const selected = httpEndpointIdentity(1, 2, 80)
  const changedPort = httpEndpointIdentity(1, 2, 443)
  assert.equal(isCurrentHttpEndpointRequest(selected, selected, 4, 4), true)
  assert.equal(isCurrentHttpEndpointRequest(selected, changedPort, 4, 4), false)
  assert.equal(isCurrentHttpEndpointRequest(selected, selected, 4, 5), false)
  const aborted = new AbortController()
  aborted.abort()
  assert.equal(isCurrentHttpEndpointRequest(selected, selected, 4, 4, aborted.signal), false)
})

test('inspection request lock blocks duplicate submissions until the first settles', () => {
  const pending = { current: false }
  assert.equal(tryBeginHttpEndpointRequest(pending), true)
  assert.equal(tryBeginHttpEndpointRequest(pending), false)
  endHttpEndpointRequest(pending)
  assert.equal(tryBeginHttpEndpointRequest(pending), true)
  endHttpEndpointRequest(pending)
})

test('inspection presentation distinguishes response, TLS failure, network failure, capacity and persistence', () => {
  assert.equal(inspectionPresentation({ scheme: 'http', outcome: 'RESPONSE_RECEIVED', persistence: { status: 'PERSISTED' } }).tone, 'good')
  const tlsFailure = inspectionPresentation({ scheme: 'https', outcome: 'TLS_VERIFICATION_FAILED', persistence: { status: 'PERSISTED' } })
  assert.equal(tlsFailure.tone, 'warning')
  assert.match(tlsFailure.title, /TLS certificate verification failed/)
  assert.match(tlsFailure.message, /failed inspection result was stored/)
  assert.equal(inspectionPresentation({ scheme: 'http', outcome: 'TIMEOUT', persistence: { status: 'PERSISTED' } }).tone, 'warning')
  assert.equal(inspectionPresentation({ scheme: 'http', outcome: 'CONNECTION_FAILED', persistence: { status: 'PERSISTED' } }).tone, 'warning')
  assert.equal(inspectionPresentation({ outcome: 'CAPACITY_REJECTED', persistence: { status: 'NOT_ATTEMPTED' } }).tone, 'warning')
  assert.equal(inspectionPresentation(null, { kind: 'persistence_failure', inspectionOutcome: 'TIMEOUT' }).tone, 'warning')
  assert.equal(inspectionPresentation(null, { kind: 'authorization', message: 'Rejected' }).tone, 'error')
  assert.equal('vulnerability' in tlsFailure, false)
})

test('only verified certificate metadata is eligible for display', () => {
  const verified = { verification_status: 'VERIFIED', sha256_fingerprint: 'a'.repeat(64) }
  const failed = { verification_status: 'FAILED', sha256_fingerprint: 'a'.repeat(64) }
  assert.equal(verifiedTlsFacts(verified), verified)
  assert.equal(verifiedTlsFacts(failed), null)
  assert.equal(verifiedTlsFacts(null), null)
})

test('response header projection excludes server secrets and arbitrary fields', () => {
  assert.deepEqual(safeResponseHeaders({
    date: 'today', 'content-security-policy': 'default-src none',
    server: 'weak-banner', 'set-cookie': 'secret=value', authorization: 'token',
  }), [['date', 'today'], ['content-security-policy', 'default-src none']])
  assert.deepEqual(safeResponseHeaders(['not', 'headers']), [])
})
