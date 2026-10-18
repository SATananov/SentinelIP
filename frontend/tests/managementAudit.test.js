import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { buildManagementAuditQuery, loadManagementAuditEvents } from '../src/services/managementAuditApi.js'
import {
  createManagementAuditRequestGuard,
  formatManagementAuditTimestamp,
  managementAuditActorLabel,
  managementAuditDetails,
  managementAuditEntityLabel,
  managementAuditEventLabel,
  managementAuditPage,
  managementAuditTransition,
  managementAuditViewState,
  MANAGEMENT_AUDIT_ENTITY_TYPES,
  MANAGEMENT_AUDIT_EVENT_TYPES,
  safePortList,
  updateManagementAuditFilters,
} from '../src/services/managementAuditState.js'

test('history API uses a fixed GET endpoint, safe caching, signal, and allowlisted query fields', async () => {
  const controller = new AbortController()
  const calls = []
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (...args) => {
    calls.push(args)
    return { ok: true, json: async () => ({ items: [] }) }
  }
  try {
    await loadManagementAuditEvents({ event_type: 'SITE_CREATED', entity_type: 'SITE', entity_id: '9',
      site_id: '3', limit: 50, offset: 100, free_text: 'ignored', arbitrary: 'ignored' }, controller.signal)
    assert.equal(calls[0][0], 'http://127.0.0.1:8000/management-audit-events?limit=50&offset=100&event_type=SITE_CREATED&entity_type=SITE&entity_id=9&site_id=3')
    assert.deepEqual(calls[0][1], { method: 'GET', signal: controller.signal, cache: 'no-store' })
    assert.equal(buildManagementAuditQuery(), 'limit=50&offset=0')
  } finally { globalThis.fetch = originalFetch }
})

test('history query validates exact enums, entity ID pairing, paging, and positive integer site ID', () => {
  assert.equal(buildManagementAuditQuery({ entity_type: 'SENSOR', entity_id: 'sensor:7' }),
    'limit=50&offset=0&entity_type=SENSOR&entity_id=sensor%3A7')
  for (const filters of [
    { entity_id: '7' }, { event_type: 'NOT_REAL' }, { entity_type: 'UNKNOWN' },
    { site_id: 0 }, { site_id: -1 }, { site_id: 'x' }, { site_id: '1.2' },
    { site_id: '1e2' }, { limit: 101 }, { offset: -1 }, { offset: 1.5 },
  ]) assert.throws(() => buildManagementAuditQuery(filters))
  assert.equal(buildManagementAuditQuery({ site_id: '' }), 'limit=50&offset=0')
})

test('history API propagates aborts and exposes only concise status errors', async () => {
  const originalFetch = globalThis.fetch
  const controller = new AbortController()
  const abort = new Error('aborted'); abort.name = 'AbortError'
  globalThis.fetch = async (_url, options) => { assert.equal(options.signal, controller.signal); throw abort }
  try { await assert.rejects(loadManagementAuditEvents({}, controller.signal), (error) => error === abort) }
  finally { globalThis.fetch = originalFetch }

  globalThis.fetch = async () => ({ ok: false, status: 403, json: async () => ({ detail: 'secret body' }) })
  try { await assert.rejects(loadManagementAuditEvents(), /Management history request failed \(403\)\./) }
  finally { globalThis.fetch = originalFetch }
})

test('every stored event and entity type has a neutral display label', () => {
  assert.equal(MANAGEMENT_AUDIT_EVENT_TYPES.length, 22)
  assert.equal(MANAGEMENT_AUDIT_ENTITY_TYPES.length, 9)
  for (const type of MANAGEMENT_AUDIT_EVENT_TYPES) assert.notEqual(managementAuditEventLabel(type), 'Management event')
  for (const type of MANAGEMENT_AUDIT_ENTITY_TYPES) assert.notEqual(managementAuditEntityLabel(type), 'Managed entity')
  assert.equal(managementAuditEventLabel('FUTURE'), 'Management event')
  assert.equal(managementAuditEntityLabel('FUTURE'), 'Managed entity')
  assert.equal(managementAuditActorLabel('LOCAL_OPERATOR'), 'Local operator')
  assert.equal(managementAuditActorLabel('API_CLIENT'), 'API client')
  assert.equal(managementAuditActorLabel('SENSOR'), 'Sensor')
  assert.equal(managementAuditActorLabel('FUTURE'), 'Unknown source class')
  assert.doesNotMatch(['Local operator', 'API client', 'Sensor'].join(' '), /user|username|admin|analyst|email/i)
})

test('view state, bounded paging, filter reset, entity ID gating, and request generations are explicit', () => {
  assert.equal(managementAuditViewState({ loading: true }), 'loading')
  assert.equal(managementAuditViewState({ loading: false, error: 'offline' }), 'error')
  assert.equal(managementAuditViewState({ loading: false, result: { items: [] } }), 'empty')
  assert.equal(managementAuditViewState({ loading: false, result: { items: [{ id: 1 }] } }), 'ready')
  const current = { limit: 50, offset: 100, entity_type: 'SENSOR', entity_id: '8' }
  assert.deepEqual(updateManagementAuditFilters(current, 'event_type', 'SENSOR_DISABLED'),
    { ...current, event_type: 'SENSOR_DISABLED', offset: 0 })
  assert.deepEqual(updateManagementAuditFilters(current, 'entity_type', 'SITE'),
    { ...current, entity_type: 'SITE', entity_id: '', offset: 0 })
  assert.deepEqual(updateManagementAuditFilters(current, 'entity_type', ''),
    { ...current, entity_type: '', entity_id: '', offset: 0 })
  assert.equal(managementAuditPage({ limit: 50, offset: 0 }, 'previous', false).offset, 0)
  assert.equal(managementAuditPage({ limit: 50, offset: 50 }, 'next', true).offset, 100)
  assert.equal(managementAuditPage({ limit: 50, offset: 50 }, 'next', false).offset, 50)
  const guard = createManagementAuditRequestGuard()
  const stale = guard.begin()
  const currentGeneration = guard.begin()
  assert.equal(guard.isCurrent(stale), false)
  assert.equal(guard.isCurrent(currentGeneration), true)
  guard.invalidate()
  assert.equal(guard.isCurrent(currentGeneration), false)
})

test('safe event detail projection covers transitions, policy, enrollment, tasks, cleanup, and deleted entities', () => {
  assert.equal(managementAuditTransition({ previous_state: 'DISABLED', new_state: 'ENABLED' }), 'Disabled → Enabled')
  assert.equal(managementAuditTransition({ previous_state: null, new_state: 'CREATED' }), 'Created')
  assert.equal(managementAuditTransition({ previous_state: null, new_state: null }), null)
  assert.equal(formatManagementAuditTimestamp('bad'), 'Time unavailable')
  assert.deepEqual(safePortList([22, 80]), [22, 80])
  assert.equal(safePortList('[22,80]'), null)

  const policy = managementAuditDetails({ event_type: 'EXPOSURE_POLICY_CONFIGURED', entity_id: 'deleted-scope',
    previous_expected_tcp_ports: [22, 80, 443], new_expected_tcp_ports: [22, 443], token: 'secret' })
  assert.deepEqual(policy.map((item) => item.value), ['22, 80, 443', '22, 443'])
  const enrollment = managementAuditDetails({ event_type: 'ENROLLMENT_ISSUED', enrollment_expires_at: '2026-01-01T00:00:00Z',
    token: 'secret', token_hash: 'secret' })
  assert.deepEqual(enrollment.map((item) => item.label), ['Expires'])
  const task = managementAuditDetails({ event_type: 'SENSOR_TASK_CREATED', task_type: 'DISCOVER_NETWORK',
    target_device_id: 42, target_ip: '192.0.2.1', payload: 'secret', result: 'secret', error: 'secret',
    sensor_id: 7, site_id: 3, scope_id: 8 })
  assert.deepEqual(task.map((item) => item.label), ['Task type', 'Target device ID', 'Site ID', 'Scope ID', 'Sensor ID'])
  const cleanup = managementAuditDetails({ event_type: 'DATA_LIFECYCLE_CLEANUP_EXECUTED',
    cleanup_data_class: 'WEB_OBSERVATIONS', cleanup_evaluated_at: '2026-01-01T00:00:00Z',
    cleanup_eligible_before: 10, cleanup_deleted_count: 5, cleanup_protected_count: 2,
    cleanup_remaining_eligible: 3, cleanup_batch_limit: 100, deleted_ids: [1, 2], hostname: 'secret' })
  assert.deepEqual(cleanup.map((item) => item.label), [
    'Data class', 'Evaluated at', 'Eligible before', 'Deleted count', 'Protected count', 'Remaining eligible', 'Batch limit',
  ])
  const rendered = JSON.stringify([...policy, ...enrollment, ...task, ...cleanup])
  assert.doesNotMatch(rendered, /secret|192\.0\.2\.1|deleted_ids|token_hash|payload|result|error/i)
  assert.equal(managementAuditEntityLabel('NETWORK'), 'Network') // Stored scalar identity needs no live entity.
})

test('management history UI is manually refreshed and contains no mutation controls or polling', async () => {
  const source = await readFile(new URL('../src/components/ManagementAuditHistory.jsx', import.meta.url), 'utf8')
  assert.match(source, /onClick=\{refresh\}/)
  assert.match(source, /Refresh history/)
  assert.match(source, /controller\.abort\(\)/)
  assert.match(source, /isCurrent\(generation\)/)
  assert.doesNotMatch(source, /setInterval|setTimeout|onSubmit|method:\s*['"](POST|PUT|PATCH|DELETE)['"]|rollback|replay/i)
})
