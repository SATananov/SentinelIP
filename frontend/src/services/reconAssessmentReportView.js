const readableValues = Object.freeze({
  NOT_RECORDED: 'Not recorded',
  NOT_VERIFIED: 'Not verified',
  IN_PROGRESS: 'In progress',
  ONLINE: 'Online',
  OFFLINE: 'Offline',
  UNKNOWN: 'Unknown',
})

export function assessmentDisplayValue(value, fallback = 'Not recorded') {
  if (typeof value !== 'string' || !value.trim()) return fallback
  const normalized = value.trim().toUpperCase()
  if (readableValues[normalized]) return readableValues[normalized]
  return value.trim().replaceAll('_', ' ').toLowerCase().replace(/\b\p{L}/gu, (letter) => letter.toUpperCase())
}

export function assessmentDeviceInventory(deviceReport) {
  const device = deviceReport?.device || {}
  return {
    id: device.id,
    ipAddress: device.ip_address || `Device #${device.id}`,
    identity: [device.hostname, device.vendor].filter((value) => typeof value === 'string' && value.trim()).join(' · ') || 'Name not recorded',
    status: assessmentDisplayValue(device.status),
    portCount: deviceReport?.ports?.length || 0,
    serviceCount: deviceReport?.services?.length || 0,
    findingCount: deviceReport?.findings?.length || 0,
    evidenceCount: deviceReport?.evidence?.length || 0,
  }
}

export function assessmentFindingContext(deviceReport, finding) {
  const ports = deviceReport?.ports || []
  const services = deviceReport?.services || []
  const service = services.find((item) => item.id === finding?.service_id)
    || services.find((item) => item.port_id === finding?.port_id)
  const port = ports.find((item) => item.id === (service?.port_id ?? finding?.port_id))
  return {
    ipAddress: deviceReport?.device?.ip_address || `Device #${deviceReport?.device?.id}`,
    title: finding?.title || `Finding #${finding?.id}`,
    severity: assessmentDisplayValue(finding?.severity),
    lifecycleStatus: assessmentDisplayValue(finding?.finding_status),
    verificationStatus: assessmentDisplayValue(finding?.verification_status),
    port: port ? `${port.port_number}/${port.transport}` : null,
    service: service ? [service.service_name, service.product, service.version].filter(Boolean).join(' ') : null,
    description: finding?.description || null,
  }
}

export function assessmentObservationSummary(observations = []) {
  const rows = Array.isArray(observations) ? observations : []
  const dated = rows.filter((item) => typeof item.latest_observed_at === 'string' && Number.isFinite(Date.parse(item.latest_observed_at)))
  const latest = dated.reduce((current, item) => !current || Date.parse(item.latest_observed_at) > Date.parse(current.latest_observed_at) ? item : current, null)
  return { count: rows.length, latestAt: latest?.latest_observed_at || null }
}

export function toggleExpandedAssessmentDevice(current, deviceId) {
  const next = new Set(current)
  if (next.has(deviceId)) next.delete(deviceId)
  else next.add(deviceId)
  return next
}

export function assessmentSummaryScrollBehavior(prefersReducedMotion) {
  return prefersReducedMotion ? 'auto' : 'smooth'
}
