import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const cases = [
  ['NetworkWorkspace.jsx', 'investigationNavigationError'],
  ['RemoteSensorTaskHistory.jsx', 'lookupTask'],
  ['ExternalActivityDashboard.jsx', 'investigationDetailError'],
  ['ExternalActivityDashboard.jsx', 'investigationDetail'],
  ['ExternalExposureDashboard.jsx', 'investigationDetailError'],
  ['ExternalExposureDashboard.jsx', 'investigationDetail'],
]

for (const [file, name] of cases) {
  test(`${file} protects ${name} from null`, () => {
    const source = readFileSync(
      new URL(`../src/components/${file}`, import.meta.url),
      'utf8',
    )

    const expected = `${name} && ${name}.nonce === investigationRequest?.nonce`

    assert.ok(source.includes(expected))
    assert.ok(!source.includes(`${name}?.nonce === investigationRequest?.nonce`))
  })
}
