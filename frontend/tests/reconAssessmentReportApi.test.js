import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  assessmentReportExportUrl,
  assessmentReportFilename,
  assessmentReportUrl,
  AssessmentReportError,
  downloadAssessmentReport,
  loadAssessmentReport,
  MAX_ASSESSMENT_REPORT_BYTES,
  triggerAssessmentReportDownload,
} from '../src/services/reconAssessmentReportApi.js'
import { availableAssessmentScopes } from '../src/services/reconAssessmentState.js'

const validScope = { id: 11, network_id: 4, scope_type: 'PRIVATE_NETWORK', canonical_target: '192.168.20.0/24', authorized: true, enabled: true, authorization_confirmed_at: 'recorded', authorization_confirmation_version: 'v1', authorization_source: 'operator' }
const validNetwork = { id: 4, cidr: '192.168.20.0/24', authorized: true, enabled: true }
const report = { report_id: 'f9cefa57-bbd3-4c60-88b8-39840da97245', generated_at: '2026-11-15T08:00:00+00:00', schema_version: '1.0', assessment: { scope_id: 11, target: validScope.canonical_target }, devices: [], findings: [], recommendations: [], coverage: { discovered_assets: 0, assets_with_service_evidence: 0, assets_without_service_evidence: 0, potential_vulnerabilities: 0, confirmed_findings: 0, unverified_cve_matches: 0, data_incomplete: false, limitations: ['No findings do not prove security.'] } }

function response({ status = 200, body = report, type = 'application/json', disposition = '' } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => ({ 'content-type': type, 'content-disposition': disposition }[name.toLowerCase()] || null) },
    text: async () => typeof body === 'string' ? body : JSON.stringify(body),
    blob: async () => body instanceof Blob ? body : new Blob([String(body)], { type }),
  }
}

test('scope selection reuses only authorized and enabled private and public scopes', () => {
  const publicScope = { ...validScope, id: 12, network_id: null, scope_type: 'PUBLIC_IPV4', canonical_target: '203.0.113.7' }
  const disabledScope = { ...validScope, id: 13, enabled: false }
  const choices = availableAssessmentScopes([validScope, publicScope, disabledScope], [validNetwork], () => true)
  assert.deepEqual(choices.map((item) => item.key), ['PRIVATE_NETWORK:11', 'PUBLIC_IPV4:12'])
})

test('report URLs validate IDs and use the existing API base', () => {
  assert.equal(assessmentReportUrl(11), 'http://127.0.0.1:8000/recon/scopes/11/assessment-report')
  assert.equal(assessmentReportExportUrl(11, 'docx'), 'http://127.0.0.1:8000/recon/scopes/11/assessment-report/docx')
  for (const value of [0, -1, 1.5, NaN, Infinity, '11', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => assessmentReportUrl(value), TypeError)
    assert.throws(() => assessmentReportExportUrl(value, 'pdf'), TypeError)
  }
  assert.throws(() => assessmentReportExportUrl(11, '../pdf'), TypeError)
})

test('assessment preview fetches real JSON with GET and accepts an empty result', async () => {
  const originalFetch = globalThis.fetch
  let request
  const controller = new AbortController()
  globalThis.fetch = async (url, options) => { request = { url, options }; return response() }
  try {
    const result = await loadAssessmentReport(11, controller.signal)
    assert.deepEqual(result, report)
    assert.equal(request.url, assessmentReportUrl(11))
    assert.equal(request.options.method, 'GET')
    assert.equal(request.options.cache, 'no-store')
    assert.equal(request.options.signal, controller.signal)
    assert.deepEqual(result.devices, [])
    assert.equal(result.coverage.discovered_assets, 0)
  } finally { globalThis.fetch = originalFetch }
})

test('preview rejects scope mismatches, failed responses and oversized output', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => response({ body: { ...report, assessment: { scope_id: 99 } } })
  await assert.rejects(loadAssessmentReport(11), (error) => error instanceof AssessmentReportError)
  globalThis.fetch = async () => response({ status: 403 })
  await assert.rejects(loadAssessmentReport(11), /not currently authorized/)
  globalThis.fetch = async () => ({ ...response(), headers: { get: (name) => name === 'content-length' ? String(MAX_ASSESSMENT_REPORT_BYTES + 1) : null } })
  try { await assert.rejects(loadAssessmentReport(11), /exceeds the allowed size/) }
  finally { globalThis.fetch = originalFetch }
})

test('PDF, Word, and HTML downloads validate MIME, size and safe server filenames', async () => {
  const originalFetch = globalThis.fetch
  const cases = [
    ['pdf', 'application/pdf'],
    ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    ['html', 'text/html; charset=utf-8'],
  ]
  try {
    for (const [format, type] of cases) {
      let request
      globalThis.fetch = async (url, options) => {
        request = { url, options }
        return response({ body: new Blob(['document'], { type }), type,
          disposition: `attachment; filename="sentinelip-assessment-11-${report.report_id}.${format}"` })
      }
      const result = await downloadAssessmentReport(11, format)
      assert.equal(request.url, assessmentReportExportUrl(11, format))
      assert.equal(request.options.method, 'GET')
      assert.equal(request.options.cache, 'no-store')
      assert.equal(result.filename, `sentinelip-assessment-11-${report.report_id}.${format}`)
      assert.ok(result.blob.size > 0 && result.blob.size <= MAX_ASSESSMENT_REPORT_BYTES)
    }
  } finally { globalThis.fetch = originalFetch }
})

test('failed, empty, oversized, and wrong-MIME downloads do not return a file', async () => {
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => response({ status: 500 })
    await assert.rejects(downloadAssessmentReport(11, 'pdf'))
    globalThis.fetch = async () => response({ body: new Blob([]), type: 'application/pdf' })
    await assert.rejects(downloadAssessmentReport(11, 'pdf'), /empty/)
    globalThis.fetch = async () => response({ body: new Blob([new Uint8Array(MAX_ASSESSMENT_REPORT_BYTES + 1)], { type: 'application/pdf' }), type: 'application/pdf' })
    await assert.rejects(downloadAssessmentReport(11, 'pdf'), /allowed size/)
    globalThis.fetch = async () => response({ body: new Blob(['unexpected'], { type: 'text/html' }), type: 'text/html' })
    await assert.rejects(downloadAssessmentReport(11, 'pdf'), /unexpected report format/)
  } finally { globalThis.fetch = originalFetch }
})

test('unsafe or mismatched filenames fall back to a scope-only filename', () => {
  assert.equal(assessmentReportFilename(11, 'pdf', 'attachment; filename="../../private.pdf"'), 'sentinelip-assessment-11.pdf')
  assert.equal(assessmentReportFilename(11, 'html', `attachment; filename="sentinelip-assessment-12-${report.report_id}.html"`), 'sentinelip-assessment-11.html')
  assert.throws(() => assessmentReportFilename(11, 'json'), TypeError)
})

test('download triggers a temporary safe link and always cleans it up', () => {
  const events = []
  const anchor = { click: () => events.push('click'), remove: () => events.push('remove') }
  const browser = {
    URL: { createObjectURL: (blob) => { assert.equal(blob, 'file'); return 'blob:assessment' }, revokeObjectURL: () => events.push('revoke') },
    document: { createElement: () => anchor, body: { appendChild: () => events.push('append') } },
  }
  triggerAssessmentReportDownload('file', 'sentinelip-assessment-11.pdf', browser)
  assert.equal(anchor.href, 'blob:assessment')
  assert.equal(anchor.download, 'sentinelip-assessment-11.pdf')
  assert.deepEqual(events, ['append', 'click', 'remove', 'revoke'])
})

test('Recon Lab shares selected scope across tabs and reports never invoke scanners', async () => {
  const source = await readFile(new URL('../src/components/ReconLab.jsx', import.meta.url), 'utf8')
  assert.match(source, /const \[selectedId, setSelectedId\] = useState\(''\)/)
  assert.match(source, /onClick=\{\(\) => setStage\('setup'\)\}/)
  assert.match(source, /onClick=\{\(\) => setStage\('results'\)\}/)
  assert.match(source, /onChange=\{\(event\) => chooseReportScope\(event\.target\.value\)\}/)
  assert.match(source, /value=\{selectedId\}/)
  assert.match(source, /<ReconEvidence\b/)
  const apiSource = await readFile(new URL('../src/services/reconAssessmentReportApi.js', import.meta.url), 'utf8')
  assert.doesNotMatch(apiSource, /discoverNetwork|discoverPublicScope|discoverDeviceServices|discoverScopeDeviceServices/)
  assert.match(source, /Download PDF/)
  assert.match(source, /Download Word/)
  assert.match(source, /Download HTML/)
})

test('report view exposes actual coverage, evidence, limitations, and an empty-device state', async () => {
  const source = await readFile(new URL('../src/components/ReconLab.jsx', import.meta.url), 'utf8')
  for (const field of ['assets_with_service_evidence', 'assets_without_service_evidence',
    'potential_vulnerabilities', 'confirmed_findings', 'unverified_cve_matches',
    'data_incomplete', 'limitations', 'recommendations', 'generated_at']) {
    assert.ok(source.includes(`report.${field}`) || source.includes(`report.coverage.${field}`), `missing report field ${field}`)
  }
  assert.match(source, /No devices are recorded for this assessment\./)
  assert.match(source, /Historical observations and inventory status do not confirm current reachability or security\./)
  assert.match(source, /No findings are recorded\. This does not establish that the device is secure\./)
})
