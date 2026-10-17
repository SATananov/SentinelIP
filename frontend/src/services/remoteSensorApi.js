const API_BASE = 'http://127.0.0.1:8000'
const FLEET_STATUSES = new Set(['REVOKED', 'DISABLED', 'PENDING', 'ONLINE', 'OFFLINE', 'UNKNOWN'])
const TASK_TYPES = new Set(['DISCOVER_NETWORK', 'DISCOVER_SERVICES'])
const TASK_STATES = new Set(['PENDING', 'CLAIMED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'])

function positiveId(value, label) {
  const id = Number(value)
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error(`${label} must be a positive integer.`)
  return id
}

function boundedPage(options = {}) {
  const limit = options.limit ?? 100
  const offset = options.offset ?? 0
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('Limit must be between 1 and 100.')
  if (!Number.isInteger(offset) || offset < 0 || offset > 100000) throw new Error('Offset must be between 0 and 100000.')
  return new URLSearchParams({ limit: String(limit), offset: String(offset) }).toString()
}

async function managementRequest(path, { method = 'GET', body, signal } = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    method, signal, cache: 'no-store',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    let detail = ''
    try {
      const payload = await response.json()
      if (typeof payload?.detail === 'string') detail = `: ${payload.detail}`
      else if (typeof payload?.detail?.detail === 'string') detail = `: ${payload.detail.detail}`
    } catch { /* Keep a status-only message for non-JSON errors. */ }
    throw new Error(`Sensor management request failed (${response.status})${detail}`)
  }
  if (response.status === 204) return null
  return response.json()
}

export function buildRemoteSensorFleetQuery(filters = {}) {
  const limit = filters.limit ?? 100
  const offset = filters.offset ?? 0
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new Error('Fleet limit must be between 1 and 100.')
  }
  if (!Number.isInteger(offset) || offset < 0 || offset > 100000) {
    throw new Error('Fleet offset must be between 0 and 100000.')
  }

  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  if (filters.site_id !== undefined && filters.site_id !== null && filters.site_id !== '') {
    const siteId = Number(filters.site_id)
    if (!Number.isSafeInteger(siteId) || siteId <= 0) throw new Error('Site ID must be a positive integer.')
    params.set('site_id', String(siteId))
  }
  if (filters.status) {
    if (!FLEET_STATUSES.has(filters.status)) throw new Error('Fleet status is unsupported.')
    params.set('status', filters.status)
  }
  if (filters.platform !== undefined && filters.platform !== '') {
    if (typeof filters.platform !== 'string' || filters.platform.length > 64) throw new Error('Platform filter is invalid.')
    params.set('platform', filters.platform)
  }
  if (filters.enabled !== undefined && filters.enabled !== '') {
    if (typeof filters.enabled !== 'boolean') throw new Error('Enabled filter must be boolean.')
    params.set('enabled', String(filters.enabled))
  }
  return params.toString()
}

export async function loadRemoteSensorFleet(filters = {}, signal) {
  const query = buildRemoteSensorFleetQuery(filters)
  const response = await fetch(`${API_BASE}/sensors?${query}`, { signal, cache: 'no-store' })
  if (!response.ok) {
    let detail = ''
    try {
      const body = await response.json()
      detail = body?.detail ? `: ${body.detail}` : ''
    } catch {
      // Keep the status-only message when the response has no JSON body.
    }
    throw new Error(`Sensor fleet request failed (${response.status})${detail}`)
  }
  return response.json()
}

export function buildRemoteSensorTaskHistoryQuery(filters = {}) {
  const limit = filters.limit ?? 100
  const offset = filters.offset ?? 0
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('Task history limit must be between 1 and 100.')
  if (!Number.isInteger(offset) || offset < 0 || offset > 100000) throw new Error('Task history offset must be between 0 and 100000.')
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  for (const key of ['sensor_id', 'site_id', 'scope_id', 'device_id']) {
    if (filters[key] !== undefined && filters[key] !== null && filters[key] !== '') {
      params.set(key, String(positiveId(filters[key], key.replace('_', ' ').toUpperCase())))
    }
  }
  if (filters.task_type) {
    if (!TASK_TYPES.has(filters.task_type)) throw new Error('Task type filter is unsupported.')
    params.set('task_type', filters.task_type)
  }
  if (filters.status) {
    if (!TASK_STATES.has(filters.status)) throw new Error('Task status filter is unsupported.')
    params.set('status', filters.status)
  }
  for (const key of ['created_after', 'created_before']) {
    if (filters[key] !== undefined && filters[key] !== '') {
      if (typeof filters[key] !== 'string' || !/(Z|[+-]\d{2}:\d{2})$/i.test(filters[key]) || !Number.isFinite(Date.parse(filters[key]))) {
        throw new Error('Creation time filters must be timezone-aware timestamps.')
      }
      params.set(key, new Date(filters[key]).toISOString())
    }
  }
  if (params.has('created_after') !== params.has('created_before')) throw new Error('Provide both creation time bounds.')
  if (params.has('created_after')) {
    const after = Date.parse(params.get('created_after'))
    const before = Date.parse(params.get('created_before'))
    if (after >= before || before - after > 90 * 24 * 60 * 60 * 1000) {
      throw new Error('Creation time range must be ordered and no longer than 90 days.')
    }
  }
  return params.toString()
}

export async function loadRemoteSensorTaskHistory(filters = {}, signal) {
  const query = buildRemoteSensorTaskHistoryQuery(filters)
  const response = await fetch(`${API_BASE}/sensor-tasks?${query}`, { signal, cache: 'no-store' })
  if (!response.ok) {
    let detail = ''
    try {
      const body = await response.json()
      detail = typeof body?.detail === 'string' ? `: ${body.detail}`
        : typeof body?.detail?.detail === 'string' ? `: ${body.detail.detail}` : ''
    } catch { /* Use a status-only error for non-JSON responses. */ }
    throw new Error(`Task history request failed (${response.status})${detail}`)
  }
  return response.json()
}

export function listRemoteSensorSites(options = {}, signal) {
  return managementRequest(`/sites?${boundedPage(options)}`, { signal })
}

export function createRemoteSensorSite({ name, description = '', enabled = true }, signal) {
  if (typeof name !== 'string' || !name.trim() || name.length > 128) throw new Error('Site name is required and must be at most 128 characters.')
  if (typeof description !== 'string' || description.length > 1000 || typeof enabled !== 'boolean') throw new Error('Site details are invalid.')
  return managementRequest('/sites', { method: 'POST', body: { name: name.trim(), description, enabled }, signal })
}

export function setRemoteSensorSiteEnabled(siteId, enabled, signal) {
  if (typeof enabled !== 'boolean') throw new Error('Site enabled state must be boolean.')
  return managementRequest(`/sites/${positiveId(siteId, 'Site ID')}`, { method: 'PATCH', body: { enabled }, signal })
}

export function listRemoteSensorEnrollments(siteId, options = {}, signal) {
  return managementRequest(`/sites/${positiveId(siteId, 'Site ID')}/sensor-enrollments?${boundedPage(options)}`, { signal })
}

export function issueRemoteSensorEnrollment(siteId, ttlSeconds = 900, signal) {
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 3600) throw new Error('Enrollment lifetime must be between 60 and 3600 seconds.')
  return managementRequest(`/sites/${positiveId(siteId, 'Site ID')}/sensor-enrollments`, { method: 'POST', body: { ttl_seconds: ttlSeconds }, signal })
}

export function revokeRemoteSensorEnrollment(enrollmentId, signal) {
  return managementRequest(`/sensor-enrollments/${positiveId(enrollmentId, 'Enrollment ID')}`, { method: 'DELETE', signal })
}

export function setRemoteSensorEnabled(sensorId, enabled, signal) {
  if (typeof enabled !== 'boolean') throw new Error('Sensor enabled state must be boolean.')
  return managementRequest(`/sensors/${positiveId(sensorId, 'Sensor ID')}`, { method: 'PATCH', body: { enabled }, signal })
}

export function revokeRemoteSensorCredential(sensorId, signal) {
  return managementRequest(`/sensors/${positiveId(sensorId, 'Sensor ID')}/credential`, { method: 'DELETE', signal })
}

export function listRemoteSensorAssignments(sensorId, options = {}, signal) {
  return managementRequest(`/sensors/${positiveId(sensorId, 'Sensor ID')}/scope-assignments?${boundedPage(options)}`, { signal })
}

export function listEligibleSensorScopes(siteId, sensorId, options = {}, signal) {
  const query = new URLSearchParams(boundedPage(options))
  query.set('sensor_id', String(positiveId(sensorId, 'Sensor ID')))
  return managementRequest(`/sites/${positiveId(siteId, 'Site ID')}/eligible-sensor-scopes?${query}`, { signal })
}

export function addRemoteSensorAssignment(sensorId, scopeId, signal) {
  return managementRequest(`/sensors/${positiveId(sensorId, 'Sensor ID')}/scope-assignments`, {
    method: 'POST', body: { scope_id: positiveId(scopeId, 'Scope ID') }, signal,
  })
}

export function removeRemoteSensorAssignment(sensorId, scopeId, signal) {
  return managementRequest(`/sensors/${positiveId(sensorId, 'Sensor ID')}/scope-assignments/${positiveId(scopeId, 'Scope ID')}`, { method: 'DELETE', signal })
}
