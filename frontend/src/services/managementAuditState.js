export const MANAGEMENT_AUDIT_EVENT_TYPES = Object.freeze([
  'SITE_CREATED', 'SITE_ENABLED', 'SITE_DISABLED', 'NETWORK_CREATED', 'NETWORK_ENABLED',
  'NETWORK_DISABLED', 'NETWORK_DELETED', 'SCOPE_AUTHORIZED', 'SCOPE_REAUTHORIZED',
  'EXPOSURE_POLICY_CONFIGURED', 'EXPOSURE_POLICY_REMOVED', 'ENROLLMENT_ISSUED',
  'ENROLLMENT_REVOKED', 'ENROLLMENT_CONSUMED', 'SENSOR_REGISTERED', 'SENSOR_ENABLED',
  'SENSOR_DISABLED', 'SENSOR_CREDENTIAL_REVOKED', 'SENSOR_SCOPE_ASSIGNED',
  'SENSOR_SCOPE_UNASSIGNED', 'SENSOR_TASK_CREATED', 'DATA_LIFECYCLE_CLEANUP_EXECUTED',
])

export const MANAGEMENT_AUDIT_ENTITY_TYPES = Object.freeze([
  'SITE', 'NETWORK', 'SCOPE', 'EXTERNAL_EXPOSURE_POLICY', 'SENSOR_ENROLLMENT',
  'SENSOR', 'SENSOR_SCOPE_ASSIGNMENT', 'SENSOR_TASK', 'DATA_LIFECYCLE',
])

const eventLabels = Object.freeze({
  SITE_CREATED: 'Site created', SITE_ENABLED: 'Site enabled', SITE_DISABLED: 'Site disabled',
  NETWORK_CREATED: 'Network created', NETWORK_ENABLED: 'Network enabled',
  NETWORK_DISABLED: 'Network disabled', NETWORK_DELETED: 'Network deleted',
  SCOPE_AUTHORIZED: 'Scope authorized', SCOPE_REAUTHORIZED: 'Scope reauthorized',
  EXPOSURE_POLICY_CONFIGURED: 'Exposure policy configured',
  EXPOSURE_POLICY_REMOVED: 'Exposure policy removed', ENROLLMENT_ISSUED: 'Enrollment issued',
  ENROLLMENT_REVOKED: 'Enrollment revoked', ENROLLMENT_CONSUMED: 'Enrollment consumed',
  SENSOR_REGISTERED: 'Sensor registered', SENSOR_ENABLED: 'Sensor enabled',
  SENSOR_DISABLED: 'Sensor disabled', SENSOR_CREDENTIAL_REVOKED: 'Sensor credential revoked',
  SENSOR_SCOPE_ASSIGNED: 'Sensor scope assigned', SENSOR_SCOPE_UNASSIGNED: 'Sensor scope unassigned',
  SENSOR_TASK_CREATED: 'Sensor task created', DATA_LIFECYCLE_CLEANUP_EXECUTED: 'Data lifecycle cleanup executed',
})

const entityLabels = Object.freeze({
  SITE: 'Site', NETWORK: 'Network', SCOPE: 'Scope',
  EXTERNAL_EXPOSURE_POLICY: 'Exposure policy', SENSOR_ENROLLMENT: 'Sensor enrollment',
  SENSOR: 'Sensor', SENSOR_SCOPE_ASSIGNMENT: 'Sensor-scope assignment',
  SENSOR_TASK: 'Sensor task', DATA_LIFECYCLE: 'Data lifecycle',
})

const actorLabels = Object.freeze({
  LOCAL_OPERATOR: 'Local operator', API_CLIENT: 'API client', SENSOR: 'Sensor',
})

const stateLabels = Object.freeze({
  ENABLED: 'Enabled', DISABLED: 'Disabled', AUTHORIZED_ENABLED: 'Authorized and enabled',
  AUTHORIZED_DISABLED: 'Authorized and disabled', AUTHORIZED: 'Authorized', ISSUED: 'Issued',
  REVOKED: 'Revoked', CONSUMED: 'Consumed', REGISTERED: 'Registered',
  CREDENTIAL_ACTIVE: 'Credential active', CREDENTIAL_REVOKED: 'Credential revoked',
  ASSIGNED: 'Assigned', UNASSIGNED: 'Unassigned', CREATED: 'Created',
})

export function managementAuditEventLabel(value) {
  return eventLabels[value] ?? 'Management event'
}

export function managementAuditEntityLabel(value) {
  return entityLabels[value] ?? 'Managed entity'
}

export function managementAuditActorLabel(value) {
  return actorLabels[value] ?? 'Unknown source class'
}

export function managementAuditStateLabel(value) {
  return stateLabels[value] ?? null
}

export function formatManagementAuditTimestamp(value) {
  if (typeof value !== 'string' || !value) return 'Time unavailable'
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : 'Time unavailable'
}

export function managementAuditTransition(event) {
  if (!event || (event.previous_state == null && event.new_state == null)) return null
  const previous = managementAuditStateLabel(event.previous_state)
  const next = managementAuditStateLabel(event.new_state)
  if (previous && next) return `${previous} → ${next}`
  return previous ?? next
}

export function safePortList(value) {
  if (!Array.isArray(value) || value.length > 64
      || value.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)
      || value.some((port, index) => index > 0 && value[index - 1] >= port)) return null
  return [...value]
}

export function managementAuditDetails(event) {
  if (!event || typeof event !== 'object') return []
  const details = []
  const transition = managementAuditTransition(event)
  if (transition) details.push({ label: 'State transition', value: transition })
  if (typeof event.event_type === 'string' && event.event_type.startsWith('EXPOSURE_POLICY_')) {
    for (const [field, label] of [
      ['previous_expected_tcp_ports', 'Previous expected TCP ports'],
      ['new_expected_tcp_ports', 'New expected TCP ports'],
    ]) {
      const ports = safePortList(event[field])
      if (ports) details.push({ label, value: ports.length ? ports.join(', ') : 'None' })
    }
  }
  if (typeof event.event_type === 'string' && event.event_type.startsWith('ENROLLMENT_')
      && event.enrollment_expires_at) {
    details.push({ label: 'Expires', value: formatManagementAuditTimestamp(event.enrollment_expires_at) })
  }
  if (event.event_type === 'SENSOR_TASK_CREATED') {
    if (event.task_type) details.push({ label: 'Task type', value: event.task_type })
    if (event.target_device_id != null) details.push({ label: 'Target device ID', value: event.target_device_id })
  }
  if (event.event_type === 'DATA_LIFECYCLE_CLEANUP_EXECUTED') {
    for (const [field, label] of [
      ['cleanup_data_class', 'Data class'], ['cleanup_evaluated_at', 'Evaluated at'],
      ['cleanup_eligible_before', 'Eligible before'], ['cleanup_deleted_count', 'Deleted count'],
      ['cleanup_protected_count', 'Protected count'], ['cleanup_remaining_eligible', 'Remaining eligible'],
      ['cleanup_batch_limit', 'Batch limit'],
    ]) {
      const value = field === 'cleanup_evaluated_at' && event[field]
        ? formatManagementAuditTimestamp(event[field]) : event[field]
      if (value !== null && value !== undefined && value !== '') details.push({ label, value })
    }
  }
  for (const [field, label] of [['site_id', 'Site ID'], ['scope_id', 'Scope ID'], ['sensor_id', 'Sensor ID']]) {
    if (event[field] != null) details.push({ label, value: event[field] })
  }
  if (event.scope_type) details.push({ label: 'Scope type', value: event.scope_type })
  return details
}

export function updateManagementAuditFilters(current, key, value) {
  const next = { ...current, [key]: value, offset: 0 }
  if (key === 'entity_type' && value !== current.entity_type) next.entity_id = ''
  return next
}

export function managementAuditPage(current, direction, hasMore) {
  if (direction === 'previous') return { ...current, offset: Math.max(0, current.offset - 50) }
  if (direction === 'next' && hasMore) return { ...current, offset: current.offset + 50 }
  return current
}

export function managementAuditViewState({ loading, error, result }) {
  if (loading) return 'loading'
  if (error) return 'error'
  if (!result || !Array.isArray(result.items) || result.items.length === 0) return 'empty'
  return 'ready'
}

export function createManagementAuditRequestGuard() {
  let generation = 0
  return {
    begin() { generation += 1; return generation },
    invalidate() { generation += 1 },
    isCurrent(candidate) { return candidate === generation },
  }
}
