export const FLEET_STATUS_LABELS = Object.freeze({
  REVOKED: 'Revoked', DISABLED: 'Disabled', PENDING: 'Pending',
  ONLINE: 'Online', OFFLINE: 'Offline', UNKNOWN: 'Unknown',
})
export const PLATFORM_METADATA_LABEL = 'Sensor-declared metadata'

export function createFleetRequestGuard() {
  let generation = 0
  return {
    begin() { generation += 1; return generation },
    invalidate() { generation += 1 },
    isCurrent(candidate) { return candidate === generation },
  }
}

export function fleetQueryKey(filters) {
  return JSON.stringify(filters)
}

export function updateFleetFilter(current, key, value) {
  return { ...current, [key]: value, offset: 0 }
}

export function updateFleetLimit(current, limit) {
  return { ...current, limit, offset: 0 }
}

export function updateFleetPage(current, direction, hasMore) {
  if (direction === 'next' && hasMore) return { ...current, offset: Math.min(100000, current.offset + current.limit) }
  if (direction === 'previous') return { ...current, offset: Math.max(0, current.offset - current.limit) }
  return current
}

export function toggleFleetSelection(current, sensorId) {
  return current === sensorId ? null : sensorId
}

export function projectFleetDetail(sensor) {
  if (!sensor || typeof sensor !== 'object') return null
  const fields = ['id', 'sensor_uuid', 'name', 'site_id', 'site_name', 'site_enabled',
    'platform', 'version', 'enabled', 'registered_at', 'last_seen_at', 'status',
    'heartbeat_age_seconds', 'capabilities', 'assignment_count']
  return Object.fromEntries(fields.map((field) => [field, sensor[field]]))
}

export function fleetResultViewState({ loading, error, result }) {
  if (loading) return 'loading'
  if (error) return 'error'
  if (!result || !Array.isArray(result.items) || result.items.length === 0) return 'empty'
  return 'ready'
}

export function fleetStatusLabel(status) {
  return FLEET_STATUS_LABELS[status] ?? FLEET_STATUS_LABELS.UNKNOWN
}

export function formatFleetTimestamp(value) {
  if (value === null || value === undefined || value === '') return 'Never'
  const time = Date.parse(value)
  if (!Number.isFinite(time)) return 'Unavailable'
  return new Date(time).toLocaleString()
}

export function formatFleetHeartbeatAge(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return 'Unavailable'
  if (seconds < 60) return `${seconds} seconds ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`
  return `${Math.floor(seconds / 86400)} days ago`
}

export function fleetSiteState(siteEnabled) {
  if (siteEnabled === true) return 'Enabled'
  if (siteEnabled === false) return 'Disabled'
  return 'Unavailable'
}

export function fleetCapabilitiesLabel(capabilities) {
  if (capabilities === null) return 'Capabilities unavailable'
  if (!Array.isArray(capabilities) || capabilities.length === 0) return 'No declared capabilities'
  return capabilities.join(', ')
}

export function fleetErrorMessage(error) {
  return typeof error?.message === 'string' && error.message ? error.message : 'Sensor fleet could not be loaded.'
}
