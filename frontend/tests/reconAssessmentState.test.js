import test from 'node:test'
import assert from 'node:assert/strict'
import { availableAssessmentScopes, isAssessmentScopeAllowed } from '../src/services/reconAssessmentState.js'
const network = { id: 4, cidr: '192.168.0.0/24', authorized: true, enabled: true }
const scope = { id: 8, network_id: 4, scope_type: 'PRIVATE_NETWORK', canonical_target: network.cidr, authorized: true, enabled: true, authorization_confirmed_at: '2026-11-08', authorization_confirmation_version: 'v1', authorization_source: 'operator' }
test('only fully confirmed matching networks qualify', () => {
  assert.equal(isAssessmentScopeAllowed(scope, network, () => true), true)
  assert.equal(isAssessmentScopeAllowed({ ...scope, authorized: false }, network, () => true), false)
  assert.equal(isAssessmentScopeAllowed({ ...scope, authorization_source: null }, network, () => true), false)
  assert.equal(isAssessmentScopeAllowed(scope, { ...network, cidr: '10.0.0.0/24' }, () => true), false)
})
test('expired hostname and unapproved public CIDR do not qualify', () => {
  const host = { ...scope, scope_type: 'HOSTNAME', resolution_status: 'REAUTH_REQUIRED', approved_addresses: ['203.0.113.1'] }
  assert.equal(isAssessmentScopeAllowed(host, null, () => true), false)
  assert.equal(isAssessmentScopeAllowed({ ...host, resolution_status: 'CURRENT' }, null, () => true), true)
  assert.equal(isAssessmentScopeAllowed({ ...scope, scope_type: 'PUBLIC_CIDR' }, null, () => false), false)
})
test('scope selection lists only eligible entries', () => {
  const output = availableAssessmentScopes([scope, { ...scope, id: 9, enabled: false }], [network], () => true)
  assert.equal(output.length, 1)
  assert.equal(output[0].key, 'PRIVATE_NETWORK:8')
})
