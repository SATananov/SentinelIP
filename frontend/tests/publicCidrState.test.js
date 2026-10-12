import assert from 'node:assert/strict'
import test from 'node:test'
import { canSavePublicCidr, canScanPublicCidr, PUBLIC_CIDR_CONFIRMATION_VERSION } from '../src/services/publicCidrState.js'

const preview = { canonical_target: '8.8.8.0/29', address_count: 8, maximum_addresses: 8, enumeration: 'ALL_ADDRESSES' }
const scope = { scope_type: 'PUBLIC_CIDR', authorized: true, enabled: true, authorization_confirmed_at: '2026-10-12', authorization_source: 'fixture', authorization_confirmation_version: PUBLIC_CIDR_CONFIRMATION_VERSION, address_count: 8 }

test('saving needs successful bounded preview and fresh explicit confirmation', () => {
  assert.equal(canSavePublicCidr(preview, true, false), true)
  assert.equal(canSavePublicCidr(null, true, false), false)
  assert.equal(canSavePublicCidr(preview, false, false), false)
  assert.equal(canSavePublicCidr(preview, true, true), false)
  for (const count of [0, 3, 16, '8', null]) {
    assert.equal(canSavePublicCidr({ ...preview, address_count: count }, true, false), false)
  }
})

test('scope scan gating requires confirmed enabled server state within hard cap', () => {
  assert.equal(canScanPublicCidr(scope), true)
  for (const change of [
    { scope_type: 'PRIVATE_NETWORK' }, { authorized: false }, { enabled: false },
    { authorization_confirmed_at: null }, { authorization_source: '' },
    { authorization_confirmation_version: 'old' }, { address_count: 16 }, { address_count: null },
  ]) assert.equal(canScanPublicCidr({ ...scope, ...change }), false)
})
