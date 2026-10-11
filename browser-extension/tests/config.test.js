import assert from 'node:assert/strict'
import test from 'node:test'

import { validateApiBaseUrl, validateConfig } from '../src/config.js'

test('accepts localhost API URLs and rejects arbitrary targets', () => {
  assert.equal(validateApiBaseUrl('http://127.0.0.1:8000/'), 'http://127.0.0.1:8000')
  assert.equal(validateApiBaseUrl('http://localhost:8000'), 'http://localhost:8000')
  assert.throws(() => validateApiBaseUrl('https://example.test'))
  assert.throws(() => validateApiBaseUrl('javascript:alert(1)'))
})

test('requires complete sensor configuration', () => {
  assert.throws(() => validateConfig({ apiBaseUrl: 'http://localhost:8000' }))
  assert.deepEqual(
    validateConfig({
      apiBaseUrl: 'http://localhost:8000',
      sensorId: 'browser-1',
      sensorToken: 'token',
      enabled: true,
      privacyMode: 'DOMAIN_ONLY',
    }).enabled,
    true,
  )
})