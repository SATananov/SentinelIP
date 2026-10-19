import {
  MANAGEMENT_AUDIT_ENTITY_TYPES,
  MANAGEMENT_AUDIT_EVENT_TYPES,
} from './managementAuditState.js'

import { API_BASE } from './apiBase.js'

function positiveSiteId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return value
  if (typeof value === 'string' && /^\d+$/.test(value)) {
    const parsed = Number(value)
    if (Number.isSafeInteger(parsed) && parsed > 0) return parsed
  }
  throw new Error('Site ID must be a positive integer.')
}

export function buildManagementAuditQuery(filters = {}) {
  const params = new URLSearchParams()
  const limit = filters.limit ?? 50
  const offset = filters.offset ?? 0
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('History limit must be between 1 and 100.')
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('History offset must be a nonnegative integer.')
  params.set('limit', String(limit))
  params.set('offset', String(offset))

  if (filters.event_type !== undefined && filters.event_type !== '') {
    if (!MANAGEMENT_AUDIT_EVENT_TYPES.includes(filters.event_type)) throw new Error('Event type is unsupported.')
    params.set('event_type', filters.event_type)
  }
  if (filters.entity_type !== undefined && filters.entity_type !== '') {
    if (!MANAGEMENT_AUDIT_ENTITY_TYPES.includes(filters.entity_type)) throw new Error('Entity type is unsupported.')
    params.set('entity_type', filters.entity_type)
  }
  if (filters.entity_id !== undefined && filters.entity_id !== '') {
    if (!filters.entity_type) throw new Error('Choose an entity type before filtering by entity ID.')
    if (typeof filters.entity_id !== 'string' || filters.entity_id.length > 128) throw new Error('Entity ID is invalid.')
    params.set('entity_id', filters.entity_id)
  }
  if (filters.site_id !== undefined && filters.site_id !== '') {
    params.set('site_id', String(positiveSiteId(filters.site_id)))
  }
  return params.toString()
}

export async function loadManagementAuditEvents(filters = {}, signal) {
  const query = buildManagementAuditQuery(filters)
  let response
  try {
    response = await fetch(`${API_BASE}/management-audit-events?${query}`, {
      method: 'GET', signal, cache: 'no-store',
    })
  } catch (error) {
    if (error?.name === 'AbortError') throw error
    throw new Error('Management history could not be reached.', { cause: error })
  }
  if (!response.ok) throw new Error(`Management history request failed (${response.status}).`)
  try {
    return await response.json()
  } catch (error) {
    throw new Error('Management history response was invalid.', { cause: error })
  }
}
