import { API_BASE } from './apiBase.js'

export const HTTP_ENDPOINT_HISTORY_PAGE_SIZE = 20
export const HTTP_ENDPOINT_HISTORY_MAX_ROWS = 200
export const HTTP_ENDPOINT_HISTORY_MAX_PAGE_SIZE = 100

function validateId(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive integer.`)
  return value
}

export function httpEndpointPath(scopeId, deviceId, portId) {
  return `/scopes/${validateId(scopeId, 'scopeId')}/devices/${validateId(deviceId, 'deviceId')}/ports/${validateId(portId, 'portId')}`
}

export function httpInspectionUrl(scopeId, deviceId, portId) {
  return `${API_BASE}${httpEndpointPath(scopeId, deviceId, portId)}/fingerprint-http`
}

export function httpHistoryUrl(scopeId, deviceId, portId, { cursor, limit } = {}) {
  const query = new URLSearchParams()
  if (limit !== undefined) {
    if (!Number.isInteger(limit) || limit < 1 || limit > HTTP_ENDPOINT_HISTORY_MAX_PAGE_SIZE) {
      throw new TypeError('limit must be between 1 and 100.')
    }
    query.set('limit', String(limit))
  }
  if (cursor !== undefined && cursor !== null) {
    if (typeof cursor !== 'string' || cursor.length < 1 || cursor.length > 512) {
      throw new TypeError('cursor is invalid.')
    }
    query.set('cursor', cursor)
  }
  const suffix = query.toString()
  return `${API_BASE}${httpEndpointPath(scopeId, deviceId, portId)}/http-observations${suffix ? `?${suffix}` : ''}`
}

export class HttpEndpointApiError extends Error {
  constructor(kind, message, { status = 0, inspectionOutcome = null } = {}) {
    super(message)
    this.name = 'HttpEndpointApiError'
    this.kind = kind
    this.status = status
    this.inspectionOutcome = inspectionOutcome
  }
}

function errorForStatus(status, detail) {
  const code = detail && typeof detail === 'object' ? detail.code : null
  if (status === 403) return new HttpEndpointApiError('authorization', 'The local operator or authorized scope check was rejected.', { status })
  if (status === 404) return new HttpEndpointApiError('missing_resource', 'The selected device or observed TCP port is no longer available.', { status })
  if (status === 409) return new HttpEndpointApiError('scope_changed', 'The approved hostname or target authorization changed. Review the scope before inspecting again.', { status })
  if (status === 422) return new HttpEndpointApiError('request_rejected', 'The inspection request or history cursor was rejected.', { status })
  if (status === 503 && code === 'observation_persistence_failed') {
    return new HttpEndpointApiError('persistence_failure', 'Inspection completed, but its observation could not be stored.', {
      status,
      inspectionOutcome: detail.inspection_outcome || null,
    })
  }
  if (status === 504) return new HttpEndpointApiError('timeout', 'The request timed out. Review the endpoint before starting another inspection.', { status })
  return new HttpEndpointApiError('server_error', `The local API could not complete the request (${status}).`, { status })
}

async function requestJson(url, options) {
  let response
  try {
    response = await fetch(url, { cache: 'no-store', ...options })
  } catch (error) {
    if (error?.name === 'AbortError') throw error
    throw new HttpEndpointApiError('network_error', 'The local API could not be reached.')
  }
  let payload
  try { payload = await response.json() } catch { payload = null }
  if (!response.ok) throw errorForStatus(response.status, payload?.detail)
  return payload
}

export async function inspectHttpEndpoint({ scopeId, deviceId, portId, scheme, signal }) {
  if (scheme !== 'http' && scheme !== 'https') throw new TypeError('scheme must be http or https.')
  const result = await requestJson(httpInspectionUrl(scopeId, deviceId, portId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scheme }),
    signal,
  })
  if (!result || typeof result !== 'object' || typeof result.outcome !== 'string'
      || !result.persistence || typeof result.persistence.status !== 'string') {
    throw new HttpEndpointApiError('invalid_response', 'The local API returned an invalid inspection result.')
  }
  return result
}

export async function loadHttpEndpointHistory({ scopeId, deviceId, portId, cursor, signal }) {
  const result = await requestJson(httpHistoryUrl(scopeId, deviceId, portId, { cursor }), { method: 'GET', signal })
  if (!result || !Array.isArray(result.items) || typeof result.returned !== 'number'
      || typeof result.limit !== 'number' || !(result.next_cursor === null || typeof result.next_cursor === 'string')) {
    throw new HttpEndpointApiError('invalid_response', 'The local API returned invalid observation history.')
  }
  return result
}
