const API_BASE = 'http://127.0.0.1:8000'

async function getJson(path, signal) {
  const response = await fetch(`${API_BASE}${path}`, { signal })

  if (!response.ok) {
    throw new Error(
      `Security API request failed (${response.status})`,
    )
  }

  return response.json()
}

async function mutateJson(path, method, payload) {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
  })
  if (!response.ok) {
    let detail = ''
    try {
      const body = await response.json()
      detail = body?.detail ? `: ${body.detail}` : ''
    } catch {
      // Keep the status-only error when the response has no JSON body.
    }
    throw new Error(`Security API request failed (${response.status})${detail}`)
  }
  return response.json()
}

export function loadIncidentReviews(signal) {
  return getJson('/incident-reviews?limit=20&offset=0', signal)
}

export function buildIncidentReviewOperationsQuery(filters = {}) {
  const params = new URLSearchParams({
    limit: String(filters.limit ?? 20),
    offset: String(filters.offset ?? 0),
    sort: filters.sort ?? 'newest',
  })
  for (const key of ['state', 'priority', 'disposition', 'site_id', 'scope_id',
    'device_id', 'has_evidence', 'age_bucket', 'has_attention', 'attention_signal',
    'unattributed_only', 'unattributed_scope_only', 'unattributed_device_only']) {
    const value = filters[key]
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  }
  if (filters.unresolved_only) params.set('unresolved_only', 'true')
  return params.toString()
}

export function buildIncidentReviewSitesQuery({ sort = 'unresolved_desc', limit = 20, offset = 0 } = {}) {
  return new URLSearchParams({ sort, limit: String(limit), offset: String(offset) }).toString()
}

export function loadIncidentReviewSites(options = {}, signal) {
  return getJson(`/incident-review-operations/sites?${buildIncidentReviewSitesQuery(options)}`, signal)
}

function buildScopedWorkloadQuery(context, { sort, limit = 20, offset = 0 }) {
  const hasSiteId = Number.isSafeInteger(context?.site_id) && context.site_id > 0
  const unattributed = context?.unattributed_only === true
  if (hasSiteId === unattributed) {
    throw new Error('Provide exactly one selected site or the Unattributed site context.')
  }
  if (context?.unattributed_only !== undefined && typeof context.unattributed_only !== 'boolean') {
    throw new Error('unattributed_only must be a boolean.')
  }
  const params = new URLSearchParams({ sort, limit: String(limit), offset: String(offset) })
  if (hasSiteId) params.set('site_id', String(context.site_id))
  else params.set('unattributed_only', 'true')
  return params.toString()
}

export function buildIncidentReviewScopesQuery(context, options = {}) {
  return buildScopedWorkloadQuery(context, { ...options, sort: options.sort ?? 'unresolved_desc' })
}

export function buildIncidentReviewDevicesQuery(context, options = {}) {
  return buildScopedWorkloadQuery(context, { ...options, sort: options.sort ?? 'unresolved_desc' })
}

export function loadIncidentReviewScopes(context, options = {}, signal) {
  return getJson(`/incident-review-operations/scopes?${buildIncidentReviewScopesQuery(context, options)}`, signal)
}

export function loadIncidentReviewDevices(context, options = {}, signal) {
  return getJson(`/incident-review-operations/devices?${buildIncidentReviewDevicesQuery(context, options)}`, signal)
}

export function loadIncidentReviewOperations(filters = {}, signal) {
  return getJson(`/incident-review-operations?${buildIncidentReviewOperationsQuery(filters)}`, signal)
}

export function buildIncidentReviewActivityQuery(filters = {}) {
  const params = new URLSearchParams({
    limit: String(filters.limit ?? 20),
    offset: String(filters.offset ?? 0),
  })
  for (const key of ['event_type', 'incident_review_id', 'site_id', 'scope_id', 'device_id', 'since', 'until']) {
    const value = filters[key]
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  }
  return params.toString()
}

export function loadIncidentReviewActivity(filters = {}, signal) {
  return getJson(`/incident-review-operations/activity?${buildIncidentReviewActivityQuery(filters)}`, signal)
}

export function loadIncidentReview(id, signal) {
  return getJson(`/incident-reviews/${id}`, signal)
}

export function loadIncidentReviewEvidence(id, signal) {
  return getJson(`/incident-reviews/${id}/evidence?limit=100&offset=0`, signal)
}

export function loadRelatedIncidentEvidence(id, signal) {
  return getJson(`/incident-reviews/${id}/related-evidence?limit=100`, signal)
}

export function loadIncidentReviewTimeline(id, signal) {
  return getJson(`/incident-reviews/${id}/timeline?limit=100&offset=0`, signal)
}

export function loadIncidentReviewNotes(id, signal) {
  return getJson(`/incident-reviews/${id}/notes?limit=100&offset=0`, signal)
}

export function addIncidentReviewNote(id, noteText) {
  return mutateJson(`/incident-reviews/${id}/notes`, 'POST', { note_text: noteText })
}

export function updateIncidentReview(id, updates) {
  return mutateJson(`/incident-reviews/${id}`, 'PATCH', updates)
}

export function attachIncidentEvidence(id, suggestion) {
  return mutateJson(`/incident-reviews/${id}/evidence`, 'POST', {
    evidence_type: suggestion.evidence_type,
    evidence_id: suggestion.evidence_id,
  })
}

export function detachIncidentEvidence(id, evidence) {
  return mutateJson(
    `/incident-reviews/${id}/evidence/${encodeURIComponent(evidence.evidence_type)}/${evidence.evidence_id}`,
    'DELETE',
  )
}

export async function loadSecurityOverview(signal) {
  const [threats, correlations, incidents] = await Promise.all([
    getJson('/threats?limit=5&offset=0', signal),
    getJson('/correlations?limit=5&offset=0', signal),
    getJson('/incidents?limit=5&offset=0', signal),
  ])

  return {
    threats,
    correlations,
    incidents,
  }
}

export async function loadSecurityDetail(kind, id, signal) {
  const routes = {
    threat: '/threats',
    correlation: '/correlations',
    incident: '/incidents',
  }

  const base = routes[kind]

  if (!base) {
    throw new Error('Unsupported security detail type.')
  }

  return getJson(`${base}/${id}`, signal)
}
