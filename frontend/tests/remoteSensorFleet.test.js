import assert from 'node:assert/strict'
import test from 'node:test'

import * as remoteSensorApi from '../src/services/remoteSensorApi.js'
import { buildRemoteSensorFleetQuery, loadRemoteSensorFleet } from '../src/services/remoteSensorApi.js'
import {
  createFleetRequestGuard,
  fleetCapabilitiesLabel,
  fleetResultViewState,
  fleetSiteState,
  fleetStatusLabel,
  PLATFORM_METADATA_LABEL,
  projectFleetDetail,
  formatFleetHeartbeatAge,
  formatFleetTimestamp,
  toggleFleetSelection,
  updateFleetFilter,
  updateFleetLimit,
  updateFleetPage,
} from '../src/services/remoteSensorFleetState.js'

test('fleet API query explicitly serializes supported bounded fields only', () => {
  const query = buildRemoteSensorFleetQuery({ limit: 20, offset: 40, site_id: 3,
    status: 'ONLINE', platform: 'linux', enabled: false, ignored: 'secret' })
  assert.equal(query, 'limit=20&offset=40&site_id=3&status=ONLINE&platform=linux&enabled=false')
  assert.equal(buildRemoteSensorFleetQuery(), 'limit=100&offset=0')
})

test('invalid fleet query values are rejected before request and are not forwarded', async () => {
  for (const filters of [{ limit: 101 }, { offset: 100001 }, { site_id: '2 OR 1=1' },
    { status: 'HEALTHY' }, { enabled: 'false' }]) {
    assert.throws(() => buildRemoteSensorFleetQuery(filters))
  }
  assert.equal(buildRemoteSensorFleetQuery({ arbitrary: 'x' }), 'limit=100&offset=0')
  const originalFetch = globalThis.fetch
  let called = false
  globalThis.fetch = async () => { called = true; throw new Error('must not be called') }
  try { await assert.rejects(loadRemoteSensorFleet({ status: 'HEALTHY' })); assert.equal(called, false) }
  finally { globalThis.fetch = originalFetch }
})

test('fleet read helper performs GET only, disables caching, and propagates errors', async () => {
  assert.deepEqual(Object.keys(remoteSensorApi).sort(), ['buildRemoteSensorFleetQuery', 'loadRemoteSensorFleet'])
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (...args) => {
    calls.push(args)
    return { ok: true, json: async () => ({ evaluated_at: '2026-10-17T12:00:00Z', items: [] }) }
  }
  try {
    const result = await loadRemoteSensorFleet({ limit: 20, offset: 0 })
    assert.deepEqual(result.items, [])
    assert.match(calls[0][0], /\/sensors\?limit=20&offset=0$/)
    assert.deepEqual(calls[0][1], { signal: undefined, cache: 'no-store' })
    assert.equal(calls[0][1].method, undefined)
    globalThis.fetch = async () => ({ ok: false, status: 503 })
    await assert.rejects(loadRemoteSensorFleet(), /Sensor fleet request failed \(503\)/)
  } finally { globalThis.fetch = originalFetch }
})

test('changing filters or page size resets only the fleet offset', () => {
  const filters = { limit: 20, offset: 40, site_id: '', status: '', platform: '', enabled: '' }
  assert.deepEqual(updateFleetFilter(filters, 'status', 'OFFLINE'), { ...filters, status: 'OFFLINE', offset: 0 })
  assert.deepEqual(updateFleetLimit(filters, 50), { ...filters, limit: 50, offset: 0 })
  assert.deepEqual(updateFleetPage(filters, 'previous', false), { ...filters, offset: 20 })
  assert.deepEqual(updateFleetPage(filters, 'next', true), { ...filters, offset: 60 })
  assert.equal(updateFleetPage(filters, 'next', false), filters)
  assert.equal(updateFleetPage(filters, 'other', true), filters)
})

test('request generations ignore stale successes and stale errors', () => {
  const guard = createFleetRequestGuard()
  const oldRequest = guard.begin()
  const currentRequest = guard.begin()
  assert.equal(guard.isCurrent(oldRequest), false)
  assert.equal(guard.isCurrent(currentRequest), true)
  guard.invalidate()
  assert.equal(guard.isCurrent(currentRequest), false)
})

test('status display follows backend values and uses visible neutral labels', () => {
  for (const [status, label] of [['REVOKED', 'Revoked'], ['DISABLED', 'Disabled'],
    ['PENDING', 'Pending'], ['ONLINE', 'Online'], ['OFFLINE', 'Offline'], ['UNKNOWN', 'Unknown']]) {
    assert.equal(fleetStatusLabel(status), label)
  }
  assert.equal(fleetStatusLabel('unexpected'), 'Unknown')
})

test('heartbeat timestamp and age render safely without client-side status calculation', () => {
  assert.equal(formatFleetTimestamp(null), 'Never')
  assert.equal(formatFleetTimestamp('not-a-timestamp'), 'Unavailable')
  assert.equal(formatFleetHeartbeatAge(null), 'Unavailable')
  assert.equal(formatFleetHeartbeatAge(-1), 'Unavailable')
  assert.equal(formatFleetHeartbeatAge(45), '45 seconds ago')
  assert.equal(formatFleetHeartbeatAge(120), '2 minutes ago')
})

test('site state and sensor-declared capability labels are neutral', () => {
  assert.equal(PLATFORM_METADATA_LABEL, 'Sensor-declared metadata')
  assert.equal(fleetSiteState(true), 'Enabled')
  assert.equal(fleetSiteState(false), 'Disabled')
  assert.equal(fleetSiteState(null), 'Unavailable')
  assert.equal(fleetCapabilitiesLabel([]), 'No declared capabilities')
  assert.equal(fleetCapabilitiesLabel(null), 'Capabilities unavailable')
  assert.equal(fleetCapabilitiesLabel(['HOST_DISCOVERY']), 'HOST_DISCOVERY')
})

test('selected row detail toggles independently by sensor ID', () => {
  assert.equal(toggleFleetSelection(null, 8), 8)
  assert.equal(toggleFleetSelection(8, 8), null)
  assert.equal(toggleFleetSelection(8, 9), 9)
})

test('sensor detail projection excludes credentials and machine payload fields', () => {
  const detail = projectFleetDetail({ id: 4, name: 'Sensor', sensor_uuid: 'uuid', site_id: 2,
    credential_hash: 'hidden', credential_salt: 'hidden', token: 'hidden', raw_result: 'hidden' })
  assert.deepEqual(Object.keys(detail), ['id', 'sensor_uuid', 'name', 'site_id', 'site_name',
    'site_enabled', 'platform', 'version', 'enabled', 'registered_at', 'last_seen_at',
    'status', 'heartbeat_age_seconds', 'capabilities', 'assignment_count'])
  assert.equal(Object.hasOwn(detail, 'credential_hash'), false)
  assert.equal(projectFleetDetail(null), null)
})

test('loading, empty, ready, and error view states are explicit', () => {
  assert.equal(fleetResultViewState({ loading: true, error: null, result: null }), 'loading')
  assert.equal(fleetResultViewState({ loading: false, error: null, result: { items: [] } }), 'empty')
  assert.equal(fleetResultViewState({ loading: false, error: null, result: { items: [{ id: 1 }] } }), 'ready')
  assert.equal(fleetResultViewState({ loading: false, error: 'offline', result: null }), 'error')
})
