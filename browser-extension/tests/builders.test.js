import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildDownloadObservation,
  buildFormSignalObservation,
  buildNavigationObservation,
  buildRedirectObservation,
} from '../src/builders.js'

const url = 'https://Login.Example.test/account?token=SECRET#fragment'

test('builds safe navigation telemetry', () => {
  const event = buildNavigationObservation({
    url,
    privacyMode: 'DOMAIN_ONLY',
    eventId: 'web-1',
    observedAt: new Date('2026-01-01T00:00:00Z'),
  })
  assert.equal(event.event_type, 'NAVIGATION')
  assert.equal(event.url, 'https://login.example.test')
  assert.equal(event.external_event_id, 'web-1')
  assert.equal(JSON.stringify(event).includes('SECRET'), false)
})

test('builds redirect and structural form signals only', () => {
  const redirect = buildRedirectObservation({
    fromUrl: 'https://start.example.test',
    toUrl: url,
    eventId: 'redirect-1',
  })
  const form = buildFormSignalObservation({
    url,
    hasPasswordForm: true,
    eventId: 'form-1',
  })
  assert.equal(redirect.redirect_from_domain, 'start.example.test')
  assert.equal(redirect.redirect_to_domain, 'login.example.test')
  assert.equal(form.has_login_form, true)
  assert.equal(form.has_password_form, true)
  assert.equal(Object.hasOwn(form, 'password'), false)
})

test('builds download metadata without a local path', () => {
  const event = buildDownloadObservation({
    url,
    filename: '/home/user/file.exe',
    mimeType: 'application/octet-stream',
    sizeBytes: 10,
    eventId: 'download-1',
  })
  assert.equal(event.download_detected, true)
  assert.deepEqual(event.metadata, {
    filename: 'file.exe',
    mime_type: 'application/octet-stream',
    size_bytes: 10,
  })
})