import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'

import * as api from '../src/services/remoteSensorApi.js'
import {
  availableRemoteTaskTypes,
  createTaskOperationRequestGuard,
  taskCreationConfirmation,
  taskCreationResultMessage,
} from '../src/services/remoteSensorTaskOperationsState.js'

function mockFetch(t, responder = () => ({ ok: true, status: 201, json: async () => ({ id: 'task-1', status: 'PENDING' }) })) {
  const original = globalThis.fetch
  const calls = []
  globalThis.fetch = async (...args) => { calls.push(args); return responder(...args) }
  t.after(() => { globalThis.fetch = original })
  return calls
}

test('eligible task selector helpers use bounded fixed routes and omit arbitrary options', async (t) => {
  const calls = mockFetch(t, () => ({ ok: true, status: 200, json: async () => ({ items: [] }) }))
  await api.listEligibleRemoteSensorTaskScopes(4, { limit: 50, offset: 100, ignored: 'secret' })
  await api.listEligibleRemoteSensorTaskDevices(4, 7, { limit: 25, offset: 25, ignored: 'secret' })
  assert.match(calls[0][0], /\/sensors\/4\/eligible-task-scopes\?limit=50&offset=100$/)
  assert.match(calls[1][0], /\/sensors\/4\/eligible-task-devices\?limit=25&offset=25&scope_id=7$/)
  assert.equal(calls[0][1].cache, 'no-store')
  assert.throws(() => api.listEligibleRemoteSensorTaskScopes(4, { limit: 101 }))
  assert.throws(() => api.listEligibleRemoteSensorTaskDevices(4, 7, { offset: 100001 }))
})

test('task creation helpers send only fixed typed bodies', async (t) => {
  const calls = mockFetch(t)
  await api.createRemoteSensorNetworkTask(4, 7)
  await api.createRemoteSensorServiceTask(4, 7, 9)
  assert.equal(calls[0][0], 'http://127.0.0.1:8000/sensors/4/tasks/discover-network')
  assert.equal(calls[0][1].method, 'POST')
  assert.deepEqual(JSON.parse(calls[0][1].body), { scope_id: 7 })
  assert.equal(calls[1][0], 'http://127.0.0.1:8000/sensors/4/tasks/discover-services')
  assert.deepEqual(JSON.parse(calls[1][1].body), { scope_id: 7, device_id: 9 })
  assert.throws(() => api.createRemoteSensorNetworkTask(4, '7 OR 1=1'))
  assert.throws(() => api.createRemoteSensorServiceTask(4, 7, 0))
})

test('task operation availability respects capability and administrative state only', () => {
  const base = { id: 4, enabled: true, site_enabled: true, capabilities: ['HOST_DISCOVERY', 'SERVICE_DISCOVERY'] }
  assert.deepEqual(availableRemoteTaskTypes(base), ['DISCOVER_NETWORK', 'DISCOVER_SERVICES'])
  for (const status of ['OFFLINE', 'PENDING', 'ONLINE', 'UNKNOWN']) {
    assert.deepEqual(availableRemoteTaskTypes({ ...base, status }), ['DISCOVER_NETWORK', 'DISCOVER_SERVICES'])
  }
  assert.deepEqual(availableRemoteTaskTypes({ ...base, status: 'DISABLED' }), [])
  assert.deepEqual(availableRemoteTaskTypes({ ...base, status: 'REVOKED' }), [])
  assert.deepEqual(availableRemoteTaskTypes({ ...base, site_enabled: false }), [])
  assert.deepEqual(availableRemoteTaskTypes({ ...base, capabilities: ['LOG_COLLECTION'] }), [])
  assert.deepEqual(availableRemoteTaskTypes(null), [])
})

test('task operation confirmation is explicit and success wording remains pending', () => {
  assert.equal(taskCreationConfirmation('DISCOVER_NETWORK', { scope_name: 'Office LAN' }, null, { name: 'Sensor A' }),
    'Create a network discovery task for Office LAN on Sensor A? It will run only if the sensor claims it before the 15-minute expiry.')
  assert.equal(taskCreationConfirmation('DISCOVER_SERVICES', null, { ip_address: '192.168.1.20' }, { name: 'Sensor A' }),
    'Create a service discovery task for 192.168.1.20 on Sensor A? It will run only if the sensor claims it before the 15-minute expiry.')
  assert.match(taskCreationResultMessage({ id: 'task-1', status: 'PENDING' }), /Task queued.*Pending/)
  assert.doesNotMatch(taskCreationResultMessage({ id: 'task-1', status: 'PENDING' }), /complete|executed|results ready/i)
  assert.match(taskCreationResultMessage({ id: 'task-1', status: 'COMPLETED' }), /not confirmed/i)
})

test('request generations reject stale task operation results', () => {
  const guard = createTaskOperationRequestGuard()
  const old = guard.begin()
  const current = guard.begin()
  assert.equal(guard.isCurrent(old), false)
  assert.equal(guard.isCurrent(current), true)
  guard.invalidate()
  assert.equal(guard.isCurrent(current), false)
})

test('task operations UI is bounded, confirmed, race-safe, and has no task mutation extras', async () => {
  const component = await readFile(new URL('../src/components/RemoteSensorTaskOperations.jsx', import.meta.url), 'utf8')
  const fleet = await readFile(new URL('../src/components/RemoteSensorFleet.jsx', import.meta.url), 'utf8')
  const apiNames = Object.keys(api)
  assert.match(component, /window\.confirm\(confirmation\)/)
  assert.match(component, /submitLock\.current/)
  assert.match(component, /contextRef\.current === context/)
  assert.match(component, /onTaskCreated\?\./)
  assert.match(component, /Eligible assigned scope/)
  assert.match(component, /Eligible device and IP/)
  assert.doesNotMatch(component, /<input|setInterval|setTimeout|nmap|command|ports|payload|retryRemote|cancelRemote/)
  assert.match(fleet, /RemoteSensorTaskOperations/)
  assert.match(fleet, /historyRefreshGeneration/)
  assert.equal(apiNames.some((name) => /^(retry|cancel|delete).*task/i.test(name)), false)
  assert.equal(apiNames.some((name) => /^create.*Task$/i.test(name) && !['createRemoteSensorNetworkTask', 'createRemoteSensorServiceTask'].includes(name)), false)
})

test('queue capacity backend errors remain visible as neutral API errors', async (t) => {
  mockFetch(t, () => ({ ok: false, status: 409, json: async () => ({ detail: { code: 'TASK_QUEUE_FULL', detail: 'Sensor task queue is at capacity.' } }) }))
  await assert.rejects(api.createRemoteSensorNetworkTask(4, 7), /Sensor task queue is at capacity/)
})
