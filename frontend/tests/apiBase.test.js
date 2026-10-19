import assert from 'node:assert/strict'
import test from 'node:test'

import {
  API_BASE,
  DEFAULT_API_BASE,
  resolveApiBase,
} from '../src/services/apiBase.js'

test('API base defaults to the current local development endpoint', () => {
  assert.equal(resolveApiBase(undefined), 'http://127.0.0.1:8000')
  assert.equal(resolveApiBase(''), 'http://127.0.0.1:8000')
  assert.equal(DEFAULT_API_BASE, 'http://127.0.0.1:8000')
  assert.equal(API_BASE, 'http://127.0.0.1:8000')
})

test('API base accepts explicit HTTPS loopback and removes trailing slashes', () => {
  assert.equal(resolveApiBase('https://127.0.0.1:8443'), 'https://127.0.0.1:8443')
  assert.equal(resolveApiBase('https://127.0.0.1:8443///'), 'https://127.0.0.1:8443')
})

test('API base rejects malformed values and unsupported schemes', () => {
  for (const value of ['ftp://127.0.0.1:8443', 'javascript:alert(1)', 'http://[', 'https://']) {
    assert.throws(() => resolveApiBase(value), TypeError)
  }
})
