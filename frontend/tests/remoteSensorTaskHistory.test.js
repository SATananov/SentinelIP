import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'

import * as api from '../src/services/remoteSensorApi.js'
import {
  createTaskHistoryRequestGuard,
  formatTaskTimestamp,
  projectTaskHistoryDetail,
  taskHistoryViewState,
  taskStatusLabel,
  taskTimestampLabel,
  taskTypeLabel,
  updateTaskHistoryFilter,
  updateTaskHistoryPage,
} from '../src/services/remoteSensorTaskHistoryState.js'

test('task history query serializes only bounded allowlisted fields', () => {
  const query = api.buildRemoteSensorTaskHistoryQuery({ limit: 20, offset: 40, sensor_id: 2, site_id: 3,
    scope_id: 4, device_id: 5, task_type: 'DISCOVER_SERVICES', status: 'FAILED',
    created_after: '2026-10-01T00:00:00Z', created_before: '2026-10-02T00:00:00+00:00', ignored: 'secret' })
  const params = new URLSearchParams(query)
  assert.equal(params.get('sensor_id'), '2')
  assert.equal(params.get('device_id'), '5')
  assert.equal(params.has('ignored'), false)
  assert.equal(params.get('created_after'), '2026-10-01T00:00:00.000Z')
  assert.equal(api.buildRemoteSensorTaskHistoryQuery(), 'limit=100&offset=0')
})

test('invalid task history parameters are rejected before request', () => {
  for (const query of [{ limit: 101 }, { offset: 100001 }, { sensor_id: '1 OR 1=1' },
    { status: 'EXPIRED' }, { task_type: 'ARBITRARY_COMMAND' }, { created_after: '2026-10-01T00:00:00' },
    { created_after: '2026-10-01T00:00:00Z' },
    { created_after: '2026-10-03T00:00:00Z', created_before: '2026-10-01T00:00:00Z' },
    { created_after: '2026-01-01T00:00:00Z', created_before: '2026-10-01T00:00:00Z' }]) {
    assert.throws(() => api.buildRemoteSensorTaskHistoryQuery(query))
  }
})

test('task history helper performs a no-store GET and surfaces safe read errors', async (t) => {
  const original = globalThis.fetch
  const calls = []
  globalThis.fetch = async (...args) => {
    calls.push(args)
    return { ok: true, json: async () => ({ items: [], has_more: false }) }
  }
  t.after(() => { globalThis.fetch = original })
  const result = await api.loadRemoteSensorTaskHistory({ limit: 20, offset: 0 })
  assert.deepEqual(result.items, [])
  assert.match(calls[0][0], /\/sensor-tasks\?limit=20&offset=0$/)
  assert.deepEqual(calls[0][1], { signal: undefined, cache: 'no-store' })
  assert.equal(calls[0][1].method, undefined)
  globalThis.fetch = async () => ({ ok: false, status: 422, json: async () => ({ detail: { detail: 'Invalid filter.' } }) })
  await assert.rejects(api.loadRemoteSensorTaskHistory(), /Invalid filter/)
})

test('task pagination/filter state is independent and filter changes reset offset', () => {
  const filters = { limit: 20, offset: 40, sensor_id: '', status: '' }
  assert.deepEqual(updateTaskHistoryFilter(filters, 'status', 'FAILED'), { ...filters, status: 'FAILED', offset: 0 })
  assert.deepEqual(updateTaskHistoryPage(filters, 'previous', false), { ...filters, offset: 20 })
  assert.deepEqual(updateTaskHistoryPage(filters, 'next', true), { ...filters, offset: 60 })
  assert.equal(updateTaskHistoryPage(filters, 'next', false), filters)
})

test('request generation ignores stale task-history success and error results', () => {
  const guard = createTaskHistoryRequestGuard()
  const old = guard.begin()
  const current = guard.begin()
  assert.equal(guard.isCurrent(old), false)
  assert.equal(guard.isCurrent(current), true)
  guard.invalidate()
  assert.equal(guard.isCurrent(current), false)
})

test('task status/type labels preserve stored state and mark unknown values neutrally', () => {
  for (const [value, label] of [['PENDING', 'Pending'], ['CLAIMED', 'Claimed'], ['RUNNING', 'Running'],
    ['COMPLETED', 'Completed'], ['FAILED', 'Failed'], ['CANCELLED', 'Cancelled']]) assert.equal(taskStatusLabel(value), label)
  assert.equal(taskStatusLabel('EXPIRED'), 'Unknown')
  assert.equal(taskTypeLabel('DISCOVER_NETWORK'), 'Discover network')
  assert.equal(taskTypeLabel('UNSAFE'), 'Unknown')
})

test('task timestamp null and malformed values render safely', () => {
  assert.equal(taskTimestampLabel({}, 'claimed_at'), 'Not claimed')
  assert.equal(taskTimestampLabel({}, 'started_at'), 'Not started')
  assert.equal(taskTimestampLabel({}, 'completed_at'), 'Not completed')
  assert.equal(taskTimestampLabel({}, 'failed_at'), 'No terminal failure time')
  assert.equal(formatTaskTimestamp('bad'), 'Unavailable')
})

test('selected task detail is an explicit projection without internal fields', () => {
  const detail = projectTaskHistoryDetail({ id: 'task', status: 'FAILED', error_message: 'private',
    result_digest: 'private', created_by_source: 'private', payload: 'private' })
  assert.equal(detail.id, 'task')
  assert.equal(Object.hasOwn(detail, 'error_message'), false)
  assert.equal(Object.hasOwn(detail, 'result_digest'), false)
  assert.equal(Object.hasOwn(detail, 'payload'), false)
  assert.equal(projectTaskHistoryDetail(null), null)
})

test('task history view states and UI contain no polling or mutation controls', async () => {
  assert.equal(taskHistoryViewState({ loading: true, result: null }), 'loading')
  assert.equal(taskHistoryViewState({ loading: false, result: { items: [] } }), 'empty')
  assert.equal(taskHistoryViewState({ loading: false, result: { items: [{ id: 1 }] } }), 'ready')
  assert.equal(taskHistoryViewState({ loading: false, error: 'offline', result: null }), 'error')
  const component = await readFile(new URL('../src/components/RemoteSensorTaskHistory.jsx', import.meta.url), 'utf8')
  assert.match(component, /Refresh tasks/)
  assert.doesNotMatch(component, /setInterval|setTimeout|createRemoteSensorTask|retryRemoteSensorTask|cancelRemoteSensorTask|result_digest|raw_result|error_message/)
  assert.equal(Object.keys(api).some((name) => /^(create|retry|cancel|mutate).*task/i.test(name)), false)
})
