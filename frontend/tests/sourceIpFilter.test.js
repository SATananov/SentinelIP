import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import {
  buildEventsQuery,
  isCanonicalIpv4,
  resolveSourceIpApply,
  topIpBasisLabel,
} from '../src/services/sourceIpFilter.js'
import { createOperationsRequestGuard } from '../src/services/incidentReviewRequestGuard.js'

test('canonical IPv4 validation accepts boundary and ordinary addresses', () => {
  for (const address of ['0.0.0.0', '10.0.0.1', '192.0.2.1', '255.255.255.255']) {
    assert.equal(isCanonicalIpv4(address), true, address)
  }
})

test('canonical IPv4 validation rejects malformed and noncanonical addresses', () => {
  for (const address of [
    '192.168.001.1',
    '192.168.1',
    '256.1.1.1',
    '1.2.3.4.5',
    '::1',
    'abc',
    '1.2.3.4 ',
    '1.2.3.456',
  ]) {
    assert.equal(isCanonicalIpv4(address), false, address)
  }
})

test('top-IP basis label uses metadata and tolerates missing or invalid metadata', () => {
  assert.equal(
    topIpBasisLabel({ mode: 'latest_events', sample_size: 10_000 }),
    'Based on latest 10,000 stored events',
  )
  assert.equal(topIpBasisLabel(undefined), null)
  assert.equal(topIpBasisLabel({ mode: 'unknown', sample_size: 10_000 }), null)
})

test('applying a valid draft changes the applied filter; invalid draft preserves it', () => {
  assert.deepEqual(resolveSourceIpApply(' 192.0.2.1 ', ''), {
    draft: '192.0.2.1',
    applied: '192.0.2.1',
    error: '',
  })
  assert.deepEqual(resolveSourceIpApply('192.168.001.1', '192.0.2.1'), {
    draft: '192.168.001.1',
    applied: '192.0.2.1',
    error: 'Enter a valid IPv4 address.',
  })
  assert.deepEqual(resolveSourceIpApply('   ', '192.0.2.1'), {
    draft: '',
    applied: '',
    error: '',
  })
})

test('event query uses only the applied source IP and supports an unfiltered query', () => {
  const filtered = buildEventsQuery({
    limit: 5,
    offset: 0,
    timeRange: 'all',
    severity: 'ALL',
    sourceIp: '192.0.2.1',
  })
  assert.equal(filtered.get('source_ip'), '192.0.2.1')

  const unfiltered = buildEventsQuery({
    limit: 5,
    offset: 0,
    timeRange: 'all',
    severity: 'ALL',
    sourceIp: '',
  })
  assert.equal(unfiltered.has('source_ip'), false)
})

test('a stale dashboard request cannot replace a newer filter response', () => {
  const guard = createOperationsRequestGuard()
  const olderRequest = guard.begin('dashboard')
  const newerRequest = guard.begin('dashboard')
  let displayed = null

  if (guard.isCurrent('dashboard', newerRequest)) displayed = 'filter-B'
  if (guard.isCurrent('dashboard', olderRequest)) displayed = 'filter-A'

  assert.equal(displayed, 'filter-B')
})

test('dashboard wiring has no source catalog request and uses the applied filter', () => {
  const appSource = readFileSync(new URL('../src/App.jsx', import.meta.url), 'utf8')

  assert.doesNotMatch(appSource, /\/source-ips|sourceIps/)
  assert.match(appSource, /sourceIp:\s*ipFilter\s*,/)
  assert.match(appSource, /sourceIp:\s*ipFilter\s*\|\|\s*'ALL'/)
  assert.doesNotMatch(appSource, /sourceIp:\s*ipDraft/)
})
