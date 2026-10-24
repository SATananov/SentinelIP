export const DATA_LIFECYCLE_POLICY_LABELS = Object.freeze({
  ACTIVE_RETENTION_POLICY: 'Active retention policy',
  POLICY_UNDEFINED: 'Policy undefined',
  PRESERVE: 'Preserve',
  TRANSIENT_INTERNAL: 'Internal transient',
})

export const DATA_LIFECYCLE_CLASS_LABELS = Object.freeze({
  LEGACY_EVENTS: 'Legacy events',
  NETWORKS: 'Networks',
  DEVICES: 'Devices',
  DEVICE_OBSERVATIONS: 'Device observations',
  INVENTORY_HISTORY: 'Inventory history',
  CVE_CATALOG: 'CVE catalog',
  TELEMETRY_SENSORS: 'Telemetry sensors',
  DNS_OBSERVATIONS: 'DNS observations',
  WEB_OBSERVATIONS: 'Web observations',
  WEB_DETECTIONS: 'Web detections',
  THREAT_DETECTIONS: 'Threat detections',
  THREAT_CORRELATIONS: 'Threat correlations',
  LEGACY_INCIDENTS: 'Legacy incidents',
  PERIMETER_EVIDENCE: 'Perimeter evidence',
  EXTERNAL_EXPOSURES: 'External exposures',
  EXTERNAL_EXPOSURE_OBSERVATIONS: 'External exposure observations',
  EXTERNAL_EXPOSURE_CHANGES: 'External exposure changes',
  EXTERNAL_EXPOSURE_ASSESSMENTS: 'External exposure assessments',
  REMOTE_SENSOR_TASKS: 'Remote sensor tasks',
  REMOTE_SENSORS: 'Remote sensors',
  ENROLLMENT_RECORDS: 'Enrollment records',
  SITES: 'Sites',
  SCOPES: 'Scopes and scope bindings',
  SENSOR_ASSIGNMENTS: 'Sensor assignments',
  INCIDENT_REVIEWS: 'Incident Reviews',
  REVIEW_EVIDENCE_LINKS: 'Review evidence links',
  REVIEW_NOTES: 'Review notes',
  REVIEW_TIMELINE: 'Review timeline',
  SENSOR_TRANSPORT_NONCES: 'Sensor transport nonces',
  SCHEMA_MIGRATIONS: 'Schema migration records',
})

export function createDataLifecycleRequestGuard() {
  let generation = 0
  let controller = null
  return {
    begin() {
      controller?.abort()
      controller = new AbortController()
      generation += 1
      return { generation, controller }
    },
    invalidate() {
      generation += 1
      controller?.abort()
      controller = null
    },
    isCurrent(request) {
      return request?.generation === generation
    },
  }
}

export function dataLifecyclePreviewState({ loading, error, preview }) {
  if (loading) return 'loading'
  if (error) return 'error'
  if (!preview) return 'idle'
  return Array.isArray(preview.items) && preview.items.length ? 'ready' : 'empty'
}

export function dataLifecycleClassLabel(dataClass) {
  return DATA_LIFECYCLE_CLASS_LABELS[dataClass] ?? 'Unknown data class'
}

export function dataLifecyclePolicyLabel(policyState) {
  return DATA_LIFECYCLE_POLICY_LABELS[policyState] ?? 'Unknown policy state'
}

export function safeLifecycleTimestamp(value) {
  if (typeof value !== 'string' || !value) return 'None'
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString() : 'Unavailable'
}
