export const MAX_CAPTURE_BYTES = 1_048_576

const limit = (value, max = 180) => String(value ?? '').slice(0, max)

function serviceDescription(service, ports) {
  const port = ports.find((item) => String(item.id) === String(service.port_id))
  const endpoint = port ? `${port.port_number}/${port.transport}` : 'Port not recorded'
  const name = service.service_name || 'Service name not recorded'
  const product = [service.product, service.version].filter(Boolean).join(' ')
  return `${endpoint} · ${name}${product ? ` · ${product}` : ''}`
}

export function buildEvidenceCaptureCard({ device, ports = [], services = [], finding = null }) {
  if (!device?.id) throw new Error('Select a device before capturing evidence.')
  const lines = [
    { label: 'Device', value: `Device #${device.id}` },
    { label: 'IP address', value: device.last_ip_address || 'Not recorded' },
    { label: 'Hostname', value: device.hostname || 'Not recorded' },
    { label: 'Vendor', value: device.vendor || 'Not recorded' },
    { label: 'Recorded inventory status', value: device.status || 'Not recorded' },
  ]
  if (finding) {
    lines.push(
      { label: 'Finding', value: `#${finding.id} · ${finding.title || 'Title not recorded'}` },
      { label: 'Severity', value: finding.severity || 'Not recorded' },
      { label: 'Finding status', value: finding.status || 'Not recorded' },
      { label: 'Verification status', value: finding.verification_status || 'Not recorded' },
    )
  } else {
    lines.push({ label: 'Finding association', value: 'Device evidence; no finding selected' })
  }
  const relevantServices = finding
    ? services.filter((item) => (finding.service_id && String(item.id) === String(finding.service_id))
      || (finding.port_id && String(item.port_id) === String(finding.port_id)))
    : services
  const visibleServices = relevantServices.slice(0, 5)
  lines.push({ label: 'Recorded services', value: visibleServices.length
    ? visibleServices.map((item) => serviceDescription(item, ports)).join('\n')
    : 'No recorded service evidence' })
  const relevantPorts = finding?.service_id || finding?.port_id
    ? ports.filter((port) => relevantServices.some((service) => String(service.port_id) === String(port.id)))
    : ports
  if (relevantPorts.length && !visibleServices.length) {
    lines.push({ label: 'Recorded ports', value: relevantPorts.slice(0, 5)
      .map((item) => `${item.port_number}/${item.transport} · ${item.state || 'State not recorded'}`).join('\n') })
  }
  const omittedServices = Math.max(0, relevantServices.length - visibleServices.length)
  if (omittedServices) lines.push({ label: 'Additional services', value: `${omittedServices} more recorded service entries are available in Recon Lab.` })
  lines.push({ label: 'Capture note', value: 'SentinelIP application view. This image does not independently verify that a remote service is currently reachable.' })
  return {
    device_id: device.id,
    finding_id: finding?.id ?? null,
    lines: lines.map((line) => ({ label: limit(line.label, 80), value: limit(line.value, 600) })),
  }
}

function wrapText(context, text, maxWidth) {
  const words = String(text).split(/\s+/)
  const lines = []
  let current = ''
  for (const word of words) {
    const next = current ? `${current} ${word}` : word
    if (current && context.measureText(next).width > maxWidth) {
      lines.push(current)
      current = word
    } else current = next
  }
  if (current) lines.push(current)
  return lines.length ? lines : ['']
}

function renderCard(canvas, card, scale) {
  const width = Math.round(1200 * scale)
  const inset = Math.round(42 * scale)
  const context = canvas.getContext('2d')
  if (!context) throw new Error('The browser could not create the evidence preview.')
  const rowLayouts = card.lines.map((line) => {
    context.font = `${Math.round(18 * scale)}px Arial`
    const values = line.value.split('\n').flatMap((value) => wrapText(context, value, width - inset * 2))
    return { ...line, values }
  })
  const height = Math.round((120 + rowLayouts.reduce((sum, row) => sum + 60 + row.values.length * 28, 0)) * scale)
  canvas.width = width
  canvas.height = Math.min(height, Math.round(3000 * scale))
  context.fillStyle = '#081321'
  context.fillRect(0, 0, canvas.width, canvas.height)
  context.fillStyle = '#12345a'
  context.fillRect(0, 0, canvas.width, Math.round(90 * scale))
  context.fillStyle = '#ffffff'
  context.font = `bold ${Math.round(30 * scale)}px Arial`
  context.fillText('SENTINELIP  /  RECON EVIDENCE VIEW', inset, Math.round(56 * scale))
  let y = Math.round(130 * scale)
  for (const row of rowLayouts) {
    context.fillStyle = '#8eb7d3'
    context.font = `bold ${Math.round(17 * scale)}px Arial`
    context.fillText(row.label.toUpperCase(), inset, y)
    y += Math.round(27 * scale)
    context.fillStyle = '#edf5fb'
    context.font = `${Math.round(18 * scale)}px Arial`
    for (const line of row.values) {
      context.fillText(line, inset, y)
      y += Math.round(27 * scale)
    }
    y += Math.round(22 * scale)
  }
  return canvas
}

function canvasBlob(canvas) {
  return new Promise((resolve) => canvas.toBlob(resolve, 'image/png'))
}

export async function createEvidenceCaptureBlob(card, {
  canvasFactory = () => document.createElement('canvas'),
  maxBytes = MAX_CAPTURE_BYTES,
} = {}) {
  for (const scale of [1, 0.85, 0.7, 0.55, 0.4]) {
    const canvas = renderCard(canvasFactory(), card, scale)
    const blob = await canvasBlob(canvas)
    if (blob?.type === 'image/png' && blob.size <= maxBytes) return blob
  }
  throw new Error('This evidence view is too large to save as a 1 MB screenshot. Reduce its content and try again.')
}

export function fileToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('Could not prepare the captured image.'))
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '')
    reader.readAsDataURL(blob)
  })
}
