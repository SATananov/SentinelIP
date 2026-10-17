const API_BASE = 'http://127.0.0.1:8000'
const FLEET_STATUSES = new Set(['REVOKED', 'DISABLED', 'PENDING', 'ONLINE', 'OFFLINE', 'UNKNOWN'])

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
