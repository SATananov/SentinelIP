import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import {
  buildExportQuery,
  exportErrorMessage,
  isCustomExportRangeValid,
  localDateTimeToRfc3339,
} from '../src/services/exportRequest.js'

function localInput(year, month, day, hour = 10, minute = 0) {
  const value = new Date(year, month - 1, day, hour, minute)
  const pad = (part) => String(part).padStart(2, '0')
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}T${pad(value.getHours())}:${pad(value.getMinutes())}`
}

test('preset export query sends time_range and omits custom bounds', () => {
  const query = buildExportQuery({
    rangeMode: 'preset',
    timeRange: '24h',
    severity: 'ALERT',
    sourceIp: '192.0.2.1',
  })

  assert.equal(query.get('time_range'), '24h')
  assert.equal(query.has('from'), false)
  assert.equal(query.has('until'), false)
  assert.equal(query.get('severity'), 'ALERT')
  assert.equal(query.get('source_ip'), '192.0.2.1')
})

test('export query uses the applied filter when the draft differs', () => {
  const appliedIpFilter = '192.0.2.1'
  const draftIpInput = '10.0.0.1'
  const query = buildExportQuery({
    rangeMode: 'preset',
    timeRange: 'all',
    sourceIp: appliedIpFilter,
  })

  assert.equal(query.get('source_ip'), appliedIpFilter)
  assert.notEqual(query.get('source_ip'), draftIpInput)

  const appSource = readFileSync(new URL('../src/App.jsx', import.meta.url), 'utf8')
  assert.match(appSource, /sourceIp:\s*ipFilter\s*\|\|\s*'ALL'/)
  assert.doesNotMatch(appSource, /sourceIp:\s*ipDraft/)
})

test('custom export query sends offset-aware bounds and omits time_range', () => {
  const fromLocal = localInput(2026, 1, 1)
  const untilLocal = localInput(2026, 1, 31)
  const query = buildExportQuery({
    rangeMode: 'custom',
    timeRange: 'all',
    fromLocal,
    untilLocal,
  })

  assert.ok(query)
  assert.match(query.get('from'), /Z$/)
  assert.match(query.get('until'), /Z$/)
  assert.equal(query.get('from'), new Date(fromLocal).toISOString())
  assert.equal(query.get('until'), new Date(untilLocal).toISOString())
  assert.equal(query.has('time_range'), false)
})

test('incomplete, reversed, and over-31-day custom ranges are invalid', () => {
  assert.equal(buildExportQuery({ rangeMode: 'custom', fromLocal: localInput(2026, 1, 1) }), null)
  assert.equal(isCustomExportRangeValid(localInput(2026, 1, 2), localInput(2026, 1, 1)), false)
  assert.equal(isCustomExportRangeValid(localInput(2026, 1, 1), localInput(2026, 2, 2)), false)
  assert.equal(localDateTimeToRfc3339(''), null)
})

test('oversize errors ask the operator to narrow the range or filters', () => {
  const message = exportErrorMessage(413)
  assert.match(message, /too large/i)
  assert.match(message, /narrow the date range or filters/i)
})
