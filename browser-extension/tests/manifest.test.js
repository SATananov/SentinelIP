import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('manifest requests only observational permissions', async () => {
  const manifest = JSON.parse(
    await readFile(new URL('../manifest.json', import.meta.url), 'utf8'),
  )
  const forbidden = new Set([
    'cookies', 'debugger', 'proxy', 'nativeMessaging', 'clipboardRead',
    'geolocation', 'camera', 'microphone',
  ])
  assert.equal(manifest.manifest_version, 3)
  assert.equal(manifest.permissions.some((permission) => forbidden.has(permission)), false)
  assert.deepEqual(manifest.permissions, ['storage', 'webNavigation', 'downloads'])
})