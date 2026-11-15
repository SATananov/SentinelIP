import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  assessmentDeviceInventory,
  assessmentDisplayValue,
  assessmentFindingContext,
  assessmentObservationSummary,
  assessmentSummaryScrollBehavior,
  toggleExpandedAssessmentDevice,
} from '../src/services/reconAssessmentReportView.js'

const deviceReport = {
  device: { id: 17, ip_address: '192.0.2.17', hostname: 'lab-host', vendor: 'A very long network appliance vendor name that must remain readable and intact', status: 'ONLINE' },
  ports: [{ id: 21, port_number: 8443, transport: 'tcp', state: 'open' }],
  services: [{ id: 31, port_id: 21, service_name: 'https', product: 'Example Server', version: '4.2' }],
  findings: [{ id: 51, title: 'Recorded issue', severity: 'HIGH', finding_status: 'OPEN', verification_status: 'NOT_RECORDED', service_id: 31, description: 'Recorded technical evidence.' }],
  cve_matches: [{ id: 61, cve_id: 'CVE-2026-1234', match_status: 'POTENTIAL' }],
  evidence: [{ id: 71, description: 'Observed panel', filename: 'capture.png', finding_id: 51, created_at: '2026-11-15T08:00:00Z' }],
}

test('compact inventory preserves long identity and reports actual evidence counts', () => {
  const row = assessmentDeviceInventory(deviceReport)
  assert.equal(row.ipAddress, '192.0.2.17')
  assert.equal(row.identity, 'lab-host · A very long network appliance vendor name that must remain readable and intact')
  assert.equal(row.status, 'Online')
  assert.equal(row.portCount, 1)
  assert.equal(row.serviceCount, 1)
  assert.equal(row.findingCount, 1)
  assert.equal(row.evidenceCount, 1)
  assert.equal(assessmentDeviceInventory({ device: { id: 18 }, evidence: [] }).identity, 'Name not recorded')
})

test('finding view retains device, port, service, lifecycle, and verification context', () => {
  const finding = assessmentFindingContext(deviceReport, deviceReport.findings[0])
  assert.deepEqual(finding, {
    ipAddress: '192.0.2.17', title: 'Recorded issue', severity: 'High', lifecycleStatus: 'Open',
    verificationStatus: 'Not recorded', port: '8443/tcp', service: 'https Example Server 4.2',
    description: 'Recorded technical evidence.',
  })
  assert.equal(assessmentDisplayValue('NOT_VERIFIED'), 'Not verified')
  assert.equal(assessmentDisplayValue(null), 'Not recorded')
})

test('device expansion and observation history retain all records', () => {
  const first = toggleExpandedAssessmentDevice(new Set(), 17)
  assert.equal(first.has(17), true)
  assert.equal(toggleExpandedAssessmentDevice(first, 17).has(17), false)
  const rows = [
    { device_id: 17, latest_observed_at: '2026-11-14T10:00:00Z', sources: ['inventory'] },
    { device_id: 17, latest_observed_at: '2026-11-15T08:00:00Z', sources: ['service'] },
  ]
  assert.deepEqual(assessmentObservationSummary(rows), { count: 2, latestAt: '2026-11-15T08:00:00Z' })
  assert.deepEqual(rows.map((row) => row.sources[0]), ['inventory', 'service'])
})

test('report layout uses semantic controls, scope reset, bounded rows, and top-level actions', async () => {
  const source = await readFile(new URL('../src/components/ReconLab.jsx', import.meta.url), 'utf8')
  const styles = await readFile(new URL('../src/recon03-evidence.css', import.meta.url), 'utf8')
  assert.match(source, /aria-expanded=\{expanded\}/)
  assert.match(source, /aria-controls=\{panelId\}/)
  assert.match(source, /expanded \? 'Collapse' : 'Expand'/)
  assert.match(source, /aria-expanded=\{showAllObservations\}/)
  assert.match(source, /showAllObservations \? 'Hide' : `Show all/)
  assert.match(source, /setExpandedDeviceIds\(new Set\(\)\)/)
  assert.match(source, /setReport\(null\)/)
  assert.equal((source.match(/<ReportDownloadActions placement="(?:top|bottom)"/g) || []).length, 2)
  assert.ok(source.indexOf('<ReportDownloadActions placement="top"') < source.indexOf('recon-report-metrics'))
  assert.match(source, /assessmentFindingContext\(item, finding\)/)
  assert.match(source, /Potential match, not verified/)
  assert.match(styles, /grid-template-columns:minmax\(180px,1\.3fr\)/)
  assert.match(styles, /overflow-wrap:anywhere/)
  assert.match(styles, /@media\(max-width:620px\)/)
})

test('both download locations share state and Back to Summary preserves scope and report state', async () => {
  const source = await readFile(new URL('../src/components/ReconLab.jsx', import.meta.url), 'utf8')
  assert.equal((source.match(/onDownload=\{downloadReport\}/g) || []).length, 2)
  assert.equal((source.match(/async function downloadReport\(/g) || []).length, 1)
  assert.match(source, /function ReportDownloadActions\(\{ placement, busy, onDownload \}\)/)
  assert.match(source, /disabled=\{Boolean\(busy\)\}/)
  assert.match(source, /catch \(err\)[\s\S]*setReportDownloadError\(err\.message\)/)
  assert.ok(source.indexOf('>Back to Summary</button>') > source.indexOf('Coverage and limitations'))
  assert.match(source, /onClick=\{scrollToReportSummary\}/)
  assert.match(source, /reportSummaryRef\.current\?\.scrollIntoView/)
  assert.match(source, /window\.matchMedia\?\.\('\(prefers-reduced-motion: reduce\)'\)/)
  assert.doesNotMatch(source.match(/function\s+scrollToReportSummary\(\)\s*\{[\s\S]*?\n\s*\}/)?.[0] || '', /setSelectedId|setReport\(|loadAssessmentReport|discoverNetwork/)
  assert.equal(assessmentSummaryScrollBehavior(false), 'smooth')
  assert.equal(assessmentSummaryScrollBehavior(true), 'auto')
})

test('Reports use no scanner and Results retain Capture Evidence', async () => {
  const source = await readFile(new URL('../src/components/ReconLab.jsx', import.meta.url), 'utf8')
  const reportApi = await readFile(new URL('../src/services/reconAssessmentReportApi.js', import.meta.url), 'utf8')
  assert.match(source, /<ReconEvidence\b/)
  assert.doesNotMatch(reportApi, /discoverNetwork|discoverPublicScope|discoverDeviceServices|discoverScopeDeviceServices/)
})
