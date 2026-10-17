import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  INVESTIGATION_EVIDENCE_TYPES,
  INVESTIGATION_QUERY_TYPES,
  buildInvestigationLookupQuery,
  lookupInvestigation,
  validateInvestigationLookup,
} from '../src/services/investigationApi.js'
import {
  createInvestigationNavigationRequest,
  INVESTIGATION_DESTINATION_KINDS,
  INVESTIGATION_PANEL_BY_KIND,
  investigationPanelForKind,
} from '../src/services/investigationNavigation.js'
import {
  createInvestigationRequestGuard,
  investigationResultLabel,
  resetInvestigationQueryState,
} from '../src/services/investigationLookupState.js'
import {
  deviceContextPivots,
  evidenceSourcePivot,
  explicitRecordPivots,
  reviewAttributionPivots,
  taskContextPivots,
} from '../src/services/investigationPivots.js'

const validUuid = '3b12f1df-5232-4804-897e-917bf397618a'
const reviewKey = `IR-${'a'.repeat(32)}`

test('only the fixed 17B query types and evidence options are exposed', () => {
  assert.deepEqual(INVESTIGATION_QUERY_TYPES.map((item) => item.value), [
    'IP_ADDRESS', 'DEVICE_ID', 'SENSOR_ID', 'SITE_ID', 'SCOPE_ID',
    'INCIDENT_REVIEW_ID', 'INCIDENT_REVIEW_KEY', 'TASK_ID', 'EVIDENCE_REFERENCE',
  ])
  assert.deepEqual(INVESTIGATION_EVIDENCE_TYPES, [
    'PERIMETER_DETECTION', 'PERIMETER_POLICY_CORRELATION', 'PERIMETER_HOST_CORRELATION',
    'EXTERNAL_EXPOSURE_CHANGE', 'THREAT_DETECTION', 'THREAT_CORRELATION',
  ])
  assert.equal(INVESTIGATION_EVIDENCE_TYPES.includes('WEB_DETECTION'), false)
  assert.equal(validateInvestigationLookup({ queryType: 'HOSTNAME', value: 'host.local' }) !== '', true)
})

test('standard lookup builds only query_type and value for the fixed endpoint', async () => {
  const query = buildInvestigationLookupQuery({ queryType: 'DEVICE_ID', value: '42', arbitrary: 'ignored' })
  assert.deepEqual([...new URLSearchParams(query)], [['query_type', 'DEVICE_ID'], ['value', '42']])
  const originalFetch = globalThis.fetch
  let request
  globalThis.fetch = async (url, options) => {
    request = { url, options }
    return { ok: true, json: async () => ({ query_type: 'DEVICE_ID', items: [], truncated: false }) }
  }
  const controller = new AbortController()
  try {
    await lookupInvestigation({ queryType: 'DEVICE_ID', value: '42' }, controller.signal)
    assert.match(request.url, /^http:\/\/127\.0\.0\.1:8000\/investigation-lookup\?query_type=DEVICE_ID&value=42$/)
    assert.equal(request.options.method, 'GET')
    assert.equal(request.options.cache, 'no-store')
    assert.equal(request.options.signal, controller.signal)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('evidence lookup sends only query_type, evidence_type, and evidence_id', () => {
  const params = new URLSearchParams(buildInvestigationLookupQuery({
    queryType: 'EVIDENCE_REFERENCE', value: 'unused', evidenceType: 'THREAT_DETECTION', evidenceId: '7',
  }))
  assert.deepEqual([...params], [
    ['query_type', 'EVIDENCE_REFERENCE'], ['evidence_type', 'THREAT_DETECTION'], ['evidence_id', '7'],
  ])
})

test('identifier validation is exact and does not normalize input', () => {
  for (const queryType of ['DEVICE_ID', 'SENSOR_ID', 'SITE_ID', 'SCOPE_ID', 'INCIDENT_REVIEW_ID']) {
    assert.equal(validateInvestigationLookup({ queryType, value: '12' }), '')
    for (const value of ['', ' ', '0', '-1', '+1', '1.0', '01', ' 12']) {
      assert.notEqual(validateInvestigationLookup({ queryType, value }), '')
    }
  }
  assert.equal(validateInvestigationLookup({ queryType: 'INCIDENT_REVIEW_KEY', value: reviewKey }), '')
  for (const value of [reviewKey.toUpperCase(), 'IR-abc', `IR-${'A'.repeat(32)}`]) {
    assert.notEqual(validateInvestigationLookup({ queryType: 'INCIDENT_REVIEW_KEY', value }), '')
  }
  assert.equal(validateInvestigationLookup({ queryType: 'TASK_ID', value: validUuid }), '')
  for (const value of [validUuid.toUpperCase(), 'not-a-uuid', '3b12f1df-5232-4804-897e-917bf397618']) {
    assert.notEqual(validateInvestigationLookup({ queryType: 'TASK_ID', value }), '')
  }
})

test('IPv4 validation accepts canonical addresses and rejects alternate search forms', () => {
  assert.equal(validateInvestigationLookup({ queryType: 'IP_ADDRESS', value: '192.0.2.1' }), '')
  for (const value of ['192.000.2.1', '192.0.2', '192.0.2.256', '2001:db8::1', '192.0.2.0/24', 'host.example', '*.2.1']) {
    assert.notEqual(validateInvestigationLookup({ queryType: 'IP_ADDRESS', value }), '')
  }
})

test('evidence validation requires an allowlisted type and positive ID', () => {
  assert.equal(validateInvestigationLookup({ queryType: 'EVIDENCE_REFERENCE', evidenceType: 'THREAT_DETECTION', evidenceId: '4' }), '')
  assert.notEqual(validateInvestigationLookup({ queryType: 'EVIDENCE_REFERENCE', evidenceType: '', evidenceId: '4' }), '')
  assert.notEqual(validateInvestigationLookup({ queryType: 'EVIDENCE_REFERENCE', evidenceType: 'WEB_DETECTION', evidenceId: '4' }), '')
  assert.notEqual(validateInvestigationLookup({ queryType: 'EVIDENCE_REFERENCE', evidenceType: 'THREAT_DETECTION', evidenceId: '0' }), '')
})

test('lookup API errors are concise and do not expose raw response content', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => ({ ok: false, status: 403, text: async () => '<html>internal trace</html>' })
  try {
    await assert.rejects(lookupInvestigation({ queryType: 'SITE_ID', value: '1' }), /unavailable from this client/)
    await assert.rejects(lookupInvestigation({ queryType: 'SITE_ID', value: '1' }), /unavailable from this client/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('lookup request guard aborts old work and rejects stale completions', () => {
  const guard = createInvestigationRequestGuard()
  const oldRequest = guard.begin()
  const currentRequest = guard.begin()
  assert.equal(oldRequest.controller.signal.aborted, true)
  assert.equal(guard.isCurrent(oldRequest), false)
  assert.equal(guard.isCurrent(currentRequest), true)
  guard.invalidate()
  assert.equal(currentRequest.controller.signal.aborted, true)
  assert.equal(guard.isCurrent(currentRequest), false)
})

test('query-type reset clears incompatible values, results, and errors', () => {
  assert.deepEqual(resetInvestigationQueryState('SITE_ID'), {
    queryType: 'SITE_ID', value: '', evidenceType: '', evidenceId: '', result: null, error: '',
  })
})

test('result labels are explicit and unknown types are neutral', () => {
  assert.equal(investigationResultLabel('PERIMETER_POLICY_CORRELATION'), 'Policy Correlation')
  assert.equal(investigationResultLabel('UNKNOWN'), 'Unknown result type')
})

test('all 17B destination kinds map to existing app panels and repeated opens carry a nonce', () => {
  assert.deepEqual([...INVESTIGATION_DESTINATION_KINDS].sort(),
    Object.keys(INVESTIGATION_PANEL_BY_KIND).filter((kind) => kind !== 'SENSOR_TASK_DEVICE_FILTER').sort())
  for (const kind of INVESTIGATION_DESTINATION_KINDS) assert.ok(investigationPanelForKind(kind))
  assert.ok(investigationPanelForKind('SENSOR_TASK_DEVICE_FILTER'))
  assert.equal(investigationPanelForKind('WEB_DETECTION'), null)
  const item = { entity_type: 'DEVICE', entity_id: '9', destination_kind: 'DEVICE', destination_id: '9' }
  const first = createInvestigationNavigationRequest(item, { queryType: 'DEVICE_ID' }, 1)
  const second = createInvestigationNavigationRequest(item, { queryType: 'DEVICE_ID' }, 2)
  assert.equal(first.id, second.id)
  assert.notEqual(first.nonce, second.nonce)
  assert.equal(createInvestigationNavigationRequest({ ...item, destination_kind: 'UNSUPPORTED' }, {}, 3), null)
})

test('task pivots use only its explicit sensor, site, scope, and target_device_id', () => {
  const pivots = taskContextPivots({ sensor_id: 2, site_id: 3, scope_id: 4, target_device_id: 5, target_ip: '10.0.0.5' })
  assert.deepEqual(pivots.map(({ kind }) => kind), ['SENSOR', 'SITE', 'SCOPE', 'DEVICE'])
  assert.equal(taskContextPivots({ sensor_id: 2, site_id: 3, scope_id: 4, target_ip: '10.0.0.5' })
    .some(({ kind }) => kind === 'DEVICE'), false)
})

test('device pivots include explicit scope and bounded device-filtered task history only', () => {
  assert.deepEqual(deviceContextPivots({ id: 8, scope_id: 9 }).map(({ kind }) => kind), ['SCOPE', 'SENSOR_TASK_DEVICE_FILTER'])
  assert.deepEqual(deviceContextPivots({ id: 8 }).map(({ kind }) => kind), ['SENSOR_TASK_DEVICE_FILTER'])
  assert.deepEqual(deviceContextPivots({ id: 0 }), [])
})

test('review evidence pivots open only available supported canonical evidence references', () => {
  assert.equal(evidenceSourcePivot({ evidence_type: 'THREAT_DETECTION', evidence_id: 4, source_status: 'AVAILABLE' }).kind,
    'THREAT_DETECTION')
  assert.equal(evidenceSourcePivot({ evidence_type: 'WEB_DETECTION', evidence_id: 4, source_status: 'AVAILABLE' }), null)
  assert.equal(evidenceSourcePivot({ evidence_type: 'THREAT_DETECTION', evidence_id: 4, source_status: 'MISSING' }), null)
  assert.deepEqual(reviewAttributionPivots({ site_id: 1, scope_id: 2, device_id: 3 }).map(({ kind }) => kind),
    ['SITE', 'SCOPE', 'DEVICE'])
  assert.deepEqual(reviewAttributionPivots({}).length, 0)
})

test('threat and perimeter pivots use explicit IDs and never infer from address fields', () => {
  assert.deepEqual(explicitRecordPivots('THREAT_DETECTION', { source_ip: '192.0.2.4' }), [])
  assert.deepEqual(explicitRecordPivots('THREAT_DETECTION', { device_id: 10 }).map(({ kind }) => kind), ['DEVICE'])
  assert.deepEqual(explicitRecordPivots('PERIMETER_HOST_CORRELATION', { site_id: 1, scope_id: 2, device_id: 3 })
    .map(({ kind }) => kind), ['SITE', 'SCOPE', 'DEVICE'])
  assert.deepEqual(explicitRecordPivots('EXTERNAL_EXPOSURE_CHANGE', { target_ip: '192.0.2.4' }), [])
})

test('lookup component remains typed, compact, read-only, and without polling or storage', async () => {
  const source = await readFile(new URL('../src/components/InvestigationLookup.jsx', import.meta.url), 'utf8')
  assert.match(source, /Lookup type/)
  assert.match(source, /Evidence type/)
  assert.match(source, /AbortController|createInvestigationRequestGuard/)
  assert.match(source, /truncated/)
  assert.match(source, /No matching record found/)
  assert.doesNotMatch(source, /localStorage|sessionStorage|setInterval|createRemoteSensorTask|cancelRemoteSensorTask|retryRemoteSensorTask/)
  assert.doesNotMatch(source, /item\.(payload|result|metadata|evidence|raw)/)
})

test('App and existing panels use narrow controlled investigation navigation hooks', async () => {
  const app = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8')
  const [network, fleet, review, reviewEvidence, perimeter, exposure, taskHistory] = await Promise.all([
    readFile(new URL('../src/components/NetworkWorkspace.jsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/components/RemoteSensorFleet.jsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/components/SecurityReviewPanel.jsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/components/IncidentReviewSection.jsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/components/ExternalActivityDashboard.jsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/components/ExternalExposureDashboard.jsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/components/RemoteSensorTaskHistory.jsx', import.meta.url), 'utf8'),
  ])
  assert.match(app, /<InvestigationLookup onOpenResult=/)
  assert.match(app, /createInvestigationNavigationRequest/)
  assert.match(app, /investigationRequest=\{investigationNavigation\}/)
  assert.match(network, /investigationRequest/)
  assert.match(fleet, /investigationRequest/)
  assert.match(review, /THREAT_DETECTION.*THREAT_CORRELATION/s)
  assert.match(perimeter, /loadInvestigationPerimeterDetail/)
  assert.match(exposure, /loadInvestigationExposureDetail/)
  assert.match(taskHistory, /Task found by Investigation Search/)
  assert.match(taskHistory, /SENSOR_TASK_DEVICE_FILTER/)
  assert.match(network, /deviceContextPivots/)
  assert.match(reviewEvidence, /evidenceSourcePivot/)
  assert.doesNotMatch(app, /react-router|<BrowserRouter|<Routes/)
})
