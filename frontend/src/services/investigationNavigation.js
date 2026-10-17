export const INVESTIGATION_DESTINATION_KINDS = new Set([
  'DEVICE', 'SENSOR', 'SITE', 'SCOPE', 'INCIDENT_REVIEW', 'SENSOR_TASK', 'LEGACY_EVENT',
  'PERIMETER_EVENT', 'THREAT_DETECTION', 'THREAT_CORRELATION', 'PERIMETER_DETECTION',
  'PERIMETER_POLICY_CORRELATION', 'PERIMETER_HOST_CORRELATION', 'EXTERNAL_EXPOSURE',
  'EXTERNAL_EXPOSURE_CHANGE',
])

export const INVESTIGATION_PANEL_BY_KIND = Object.freeze({
  DEVICE: 'network-workspace', SCOPE: 'network-workspace',
  SENSOR: 'remote-sensor-fleet-title', SITE: 'remote-sensor-fleet-title', SENSOR_TASK: 'remote-sensor-fleet-title',
  INCIDENT_REVIEW: 'security-review', THREAT_DETECTION: 'security-review', THREAT_CORRELATION: 'security-review',
  PERIMETER_EVENT: 'external-activity', PERIMETER_DETECTION: 'external-activity',
  PERIMETER_POLICY_CORRELATION: 'external-activity', PERIMETER_HOST_CORRELATION: 'external-activity',
  EXTERNAL_EXPOSURE: 'external-exposure', EXTERNAL_EXPOSURE_CHANGE: 'external-exposure',
  LEGACY_EVENT: 'legacy-events-history',
})

export function createInvestigationNavigationRequest(item, query, nonce) {
  if (!item || !INVESTIGATION_DESTINATION_KINDS.has(item.destination_kind) ||
      typeof item.destination_id !== 'string' || !item.destination_id ||
      !Number.isSafeInteger(nonce) || nonce < 1) return null
  return { kind: item.destination_kind, id: item.destination_id, nonce, item, query }
}

export function investigationPanelForKind(kind) {
  return INVESTIGATION_PANEL_BY_KIND[kind] ?? null
}
