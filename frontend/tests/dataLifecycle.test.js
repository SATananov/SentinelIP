import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { loadDataLifecyclePreview } from '../src/services/dataLifecycleApi.js'
import {
  DATA_LIFECYCLE_CLASS_LABELS,
  DATA_LIFECYCLE_POLICY_LABELS,
  createDataLifecycleRequestGuard,
  dataLifecycleClassLabel,
  dataLifecyclePolicyLabel,
  dataLifecyclePreviewState,
  safeLifecycleTimestamp,
} from '../src/services/dataLifecycleState.js'

test('preview service is one fixed GET with no-store, signal, and no parameters', async () => {
  const originalFetch = globalThis.fetch
  let request
  globalThis.fetch = async (url, options) => {
    request = { url, options }
    return { ok: true, json: async () => ({ evaluated_at: '2026-10-17T12:00:00Z', items: [] }) }
  }
  const controller = new AbortController()
  try {
    await loadDataLifecyclePreview(controller.signal)
    assert.equal(request.url, 'http://127.0.0.1:8000/data-lifecycle/preview')
    assert.equal(request.options.method, 'GET')
    assert.equal(request.options.cache, 'no-store')
    assert.equal(request.options.signal, controller.signal)
    assert.equal(Object.hasOwn(request.options, 'body'), false)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('preview service reports status safely without leaking response body', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => ({ ok: false, status: 403, text: async () => 'private trace' })
  try {
    await assert.rejects(loadDataLifecyclePreview(), (error) => {
      assert.equal(error.message, 'Data lifecycle preview is unavailable (403).')
      assert.equal(error.message.includes('private trace'), false)
      return true
    })
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('policy and data-class labels are explicit and unknown values stay neutral', () => {
  assert.deepEqual(DATA_LIFECYCLE_POLICY_LABELS, {
    ACTIVE_RETENTION_POLICY: 'Active retention policy',
    POLICY_UNDEFINED: 'Policy undefined',
    PRESERVE: 'Preserve',
    TRANSIENT_INTERNAL: 'Internal transient',
  })
  assert.equal(dataLifecyclePolicyLabel('UNKNOWN'), 'Unknown policy state')
  assert.equal(dataLifecycleClassLabel('DNS_OBSERVATIONS'), 'DNS observations')
  assert.equal(dataLifecycleClassLabel('OTHER'), 'Unknown data class')
  assert.equal(Object.hasOwn(DATA_LIFECYCLE_CLASS_LABELS, 'SENSOR_TRANSPORT_NONCES'), true)
})

test('view state, counts contract, protected totals, and timestamps remain presentation-only', () => {
  assert.equal(dataLifecyclePreviewState({ loading: true }), 'loading')
  assert.equal(dataLifecyclePreviewState({ error: 'unavailable' }), 'error')
  assert.equal(dataLifecyclePreviewState({}), 'idle')
  assert.equal(dataLifecyclePreviewState({ preview: { items: [] } }), 'empty')
  assert.equal(dataLifecyclePreviewState({ preview: { items: [{ eligible_rows: 2 }] } }), 'ready')
  const item = { protected_by_review: 1, protected_by_dependency: 2, eligible_rows: 4 }
  assert.equal(item.protected_by_review + item.protected_by_dependency, 3)
  assert.equal(safeLifecycleTimestamp(null), 'None')
  assert.equal(safeLifecycleTimestamp('malformed'), 'Unavailable')
})

test('manual refresh guard aborts prior request and ignores stale results', () => {
  const guard = createDataLifecycleRequestGuard()
  const oldRequest = guard.begin()
  const latest = guard.begin()
  assert.equal(oldRequest.controller.signal.aborted, true)
  assert.equal(guard.isCurrent(oldRequest), false)
  assert.equal(guard.isCurrent(latest), true)
  guard.invalidate()
  assert.equal(latest.controller.signal.aborted, true)
  assert.equal(guard.isCurrent(latest), false)
})

test('UI stays preview-only, counts-only, manually refreshed, and never polls or mutates', async () => {
  const component = await readFile(new URL('../src/components/DataLifecycle.jsx', import.meta.url), 'utf8')
  const service = await readFile(new URL('../src/services/dataLifecycleApi.js', import.meta.url), 'utf8')
  assert.match(component, /Preview only — no data is deleted/)
  assert.match(component, /onClick=\{refresh\}/)
  assert.doesNotMatch(component, /setInterval|setTimeout|useInterval/)
  assert.doesNotMatch(component, /Delete|Purge|Clean all|cleanupData/)
  assert.doesNotMatch(component, /row_id|hostname|queried_domain|metadata_json/)
  assert.doesNotMatch(service, /POST|PATCH|DELETE|cleanup/)
  assert.match(component, /protected_by_review \+ item\.protected_by_dependency/)
})
