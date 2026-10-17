import assert from 'node:assert/strict'
import test from 'node:test'

import * as api from '../src/services/remoteSensorApi.js'
import { canReenableSensor, canRevokeEnrollment, createManagementRequestGuard, enrollmentLifecycle } from '../src/services/remoteSensorManagementState.js'

function mockFetch(t, responder = () => ({ ok: true, status: 200, json: async () => ({}) })) {
  const original = globalThis.fetch
  const calls = []
  globalThis.fetch = async (...args) => { calls.push(args); return responder(...args) }
  t.after(() => { globalThis.fetch = original })
  return calls
}

test('site and enrollment API helpers use bounded fixed routes and explicit payloads', async (t) => {
  const calls = mockFetch(t)
  await api.listRemoteSensorSites({ limit: 50, offset: 100 })
  await api.createRemoteSensorSite({ name: ' North ', description: 'Lab', enabled: true, ignored: 'discarded' })
  await api.setRemoteSensorSiteEnabled(3, false)
  await api.listRemoteSensorEnrollments(3, { limit: 25, offset: 0 })
  await api.issueRemoteSensorEnrollment(3, 900)
  await api.revokeRemoteSensorEnrollment(9)
  assert.match(calls[0][0], /\/sites\?limit=50&offset=100$/)
  assert.deepEqual(JSON.parse(calls[1][1].body), { name: 'North', description: 'Lab', enabled: true })
  assert.deepEqual(JSON.parse(calls[2][1].body), { enabled: false })
  assert.match(calls[3][0], /\/sites\/3\/sensor-enrollments\?limit=25&offset=0$/)
  assert.deepEqual(JSON.parse(calls[4][1].body), { ttl_seconds: 900 })
  assert.equal(calls[5][1].method, 'DELETE')
  assert.throws(() => api.listRemoteSensorSites({ limit: 101 }))
  assert.throws(() => api.issueRemoteSensorEnrollment(3, 59))
})

test('sensor and assignment helpers use explicit bodies and fixed routes', async (t) => {
  const calls = mockFetch(t)
  await api.setRemoteSensorEnabled(4, false)
  await api.revokeRemoteSensorCredential(4)
  await api.listRemoteSensorAssignments(4, { limit: 100, offset: 0 })
  await api.listEligibleSensorScopes(2, 4, { limit: 25, offset: 25 })
  await api.addRemoteSensorAssignment(4, 17)
  await api.removeRemoteSensorAssignment(4, 17)
  assert.deepEqual(JSON.parse(calls[0][1].body), { enabled: false })
  assert.equal(calls[1][0], 'http://127.0.0.1:8000/sensors/4/credential')
  assert.match(calls[2][0], /\/sensors\/4\/scope-assignments\?limit=100&offset=0$/)
  assert.match(calls[3][0], /\/sites\/2\/eligible-sensor-scopes\?limit=25&offset=25&sensor_id=4$/)
  assert.deepEqual(JSON.parse(calls[4][1].body), { scope_id: 17 })
  assert.equal(calls[5][1].method, 'DELETE')
  assert.throws(() => api.addRemoteSensorAssignment(4, '17 OR 1=1'))
})

test('enrollment token response is available only from issuance and no storage helper is used', async (t) => {
  const calls = mockFetch(t, () => ({ ok: true, status: 201, json: async () => ({ id: 5, token: 'one-time-secret' }) }))
  const result = await api.issueRemoteSensorEnrollment(2, 300)
  assert.equal(result.token, 'one-time-secret')
  assert.equal(calls.length, 1)
  const source = await import('node:fs/promises').then((fs) => fs.readFile(new URL('../src/components/RemoteSensorFleetManagement.jsx', import.meta.url), 'utf8'))
  assert.doesNotMatch(source, /localStorage|sessionStorage|history\.pushState|console\.(log|debug)/)
  assert.match(source, /This token is shown only once\. Copy it now; it cannot be retrieved later\./)
})

test('enrollment lifecycle distinguishes pending, consumed, revoked, and expired states', () => {
  const now = Date.parse('2026-10-17T00:00:00Z')
  assert.equal(enrollmentLifecycle({ expires_at: '2026-10-17T00:01:00Z' }, now), 'Pending')
  assert.equal(enrollmentLifecycle({ consumed_at: 'x', expires_at: '2026-10-17T00:01:00Z' }, now), 'Consumed')
  assert.equal(enrollmentLifecycle({ revoked_at: 'x', consumed_at: 'x' }, now), 'Revoked')
  assert.equal(enrollmentLifecycle({ expires_at: '2026-10-16T23:59:00Z' }, now), 'Expired')
  assert.equal(canRevokeEnrollment({ expires_at: '2026-10-17T00:01:00Z' }, now), true)
  assert.equal(canRevokeEnrollment({ consumed_at: 'x', expires_at: '2026-10-17T00:01:00Z' }, now), false)
  assert.equal(canReenableSensor({ status: 'ONLINE' }), true)
  assert.equal(canReenableSensor({ status: 'REVOKED' }), false)
})

test('management request generations ignore stale success and error across entity changes', () => {
  const guard = createManagementRequestGuard()
  const old = guard.begin('site:1:sensor:4')
  const current = guard.begin('site:2:sensor:7')
  assert.equal(guard.isCurrent(old), false)
  assert.equal(guard.isCurrent(current), true)
  guard.invalidate('site:2:sensor:8')
  assert.equal(guard.isCurrent(current), false)
})

test('no task mutation, command, or unsupported delete helper is exported', () => {
  const exported = Object.keys(api)
  assert.equal(exported.some((name) => /^delete(RemoteSensor|RemoteSite)|^rename|^move|^updateSensorCapabilities|^(create|retry|cancel|mutate).*task|command/i.test(name)), false)
  assert.equal(typeof api.loadRemoteSensorTaskHistory, 'function')
})
