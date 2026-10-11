import assert from 'node:assert/strict'
import test from 'node:test'

import { basename, sanitizeUrl, supportedPageUrl } from '../src/sanitize.js'

test('sanitizes URLs without userinfo, query, or fragment', () => {
  assert.deepEqual(
    sanitizeUrl('https://user:password@Login.Example.test/account?token=SECRET#private', 'DOMAIN_ONLY'),
    { scheme: 'https', hostname: 'login.example.test', url: 'https://login.example.test' },
  )
  assert.deepEqual(
    sanitizeUrl('https://Login.Example.test/account?token=SECRET#private', 'STANDARD'),
    { scheme: 'https', hostname: 'login.example.test', url: 'https://login.example.test/account' },
  )
})

test('rejects unsupported schemes and strips userinfo', () => {
  assert.equal(supportedPageUrl('file:///tmp/a.txt'), null)
  assert.deepEqual(
    sanitizeUrl('https://user:secret@example.test/account', 'STANDARD'),
    { scheme: 'https', hostname: 'example.test', url: 'https://example.test/account' },
  )
})

test('reduces download paths to basename', () => {
  assert.equal(basename('/home/user/downloads/file.exe'), 'file.exe')
  assert.equal(basename('C:\\Users\\user\\file.zip'), 'file.zip')
})