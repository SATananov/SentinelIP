import test from 'node:test'
import assert from 'node:assert/strict'
import { buildEvidenceCaptureCard, createEvidenceCaptureBlob, MAX_CAPTURE_BYTES } from '../src/services/reconEvidenceCapture.js'

const device = { id: 12, last_ip_address: '192.0.2.12', hostname: 'lab-host', vendor: 'Lab', status: 'ONLINE' }
const ports = [{ id: 3, port_number: 443, transport: 'tcp', state: 'open' }]
const services = [{ id: 8, port_id: 3, service_name: 'https', product: 'Example', version: '2.4' }]
const finding = { id: 44, title: 'Recorded finding', severity: 'MEDIUM', status: 'OPEN', service_id: 8 }

test('capture card binds the selected finding to its device and recorded service', () => {
  const card = buildEvidenceCaptureCard({ device, ports, services, finding })
  assert.equal(card.device_id, 12)
  assert.equal(card.finding_id, 44)
  assert.ok(card.lines.some((line) => line.label === 'Finding' && line.value.includes('#44')))
  assert.ok(card.lines.some((line) => line.label === 'Recorded services' && line.value.includes('443/tcp · https · Example 2.4')))
  assert.ok(card.lines.some((line) => line.label === 'Verification status' && line.value === 'Not recorded'))
  assert.ok(card.lines.at(-1).value.includes('does not independently verify'))
})

test('device capture states missing information without inventing details', () => {
  const card = buildEvidenceCaptureCard({ device: { id: 13 }, ports: [], services: [] })
  assert.equal(card.finding_id, null)
  assert.ok(card.lines.find((line) => line.label === 'IP address').value === 'Not recorded')
  assert.ok(card.lines.find((line) => line.label === 'Recorded services').value === 'No recorded service evidence')
})

test('finding with a port association includes its recorded service', () => {
  const card = buildEvidenceCaptureCard({
    device: { id: 14 },
    ports: [{ id: 31, port_number: 8443, transport: 'tcp', state: 'open' }],
    services: [{ id: 42, port_id: 31, service_name: 'https', product: 'Example', version: '2' }],
    finding: { id: 45, port_id: 31, title: 'Recorded issue' },
  })
  assert.match(card.lines.find((line) => line.label === 'Recorded services').value, /8443\/tcp · https · Example 2/)
})

function fakeCanvas(bytesAtWidth) {
  return () => ({
    width: 300,
    height: 150,
    getContext: () => ({
      measureText: (text) => ({ width: text.length * 8 }),
      fillRect() {}, fillText() {},
      set fillStyle(_value) {}, set font(_value) {},
    }),
    toBlob(callback, type) { callback(new Blob([new Uint8Array(bytesAtWidth(this.width))], { type })) },
  })
}

test('preview image is resized to stay within the existing 1 MB limit', async () => {
  const card = buildEvidenceCaptureCard({ device, ports, services, finding })
  const blob = await createEvidenceCaptureBlob(card, {
    canvasFactory: fakeCanvas((width) => width > 1100 ? 1_100_000 : 500_000),
  })
  assert.equal(blob.type, 'image/png')
  assert.ok(blob.size <= MAX_CAPTURE_BYTES)
})

test('capture refuses to return an oversized image after safe resizing attempts', async () => {
  const card = buildEvidenceCaptureCard({ device, ports, services, finding })
  await assert.rejects(
    createEvidenceCaptureBlob(card, { canvasFactory: fakeCanvas(() => 1_100_000) }),
    /1 MB screenshot/,
  )
})
