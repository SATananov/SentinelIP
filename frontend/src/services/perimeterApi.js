import { API_BASE } from './apiBase.js'

export async function loadPerimeterDashboard(filters = {}, signal) {
  const params = new URLSearchParams()

  if (filters.siteId) {
    params.set('site_id', filters.siteId)
  }

  if (filters.sourceType) {
    params.set('source_type', filters.sourceType)
  }

  params.set('time_range', filters.timeRange || '24h')

  const response = await fetch(
    `${API_BASE}/perimeter-dashboard?${params.toString()}`,
    { signal },
  )

  if (!response.ok) {
    throw new Error(
      `Perimeter dashboard request failed (${response.status})`,
    )
  }

  return response.json()
}

export async function loadPerimeterHostCorrelations({ siteId = '', limit = 8, offset = 0 } = {}, signal) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  if (siteId) params.set('site_id', String(siteId))
  const response = await fetch(`${API_BASE}/perimeter-host-correlations?${params.toString()}`, { signal })
  if (!response.ok) {
    throw new Error(`Perimeter host correlation request failed (${response.status})`)
  }
  return response.json()
}

const INVESTIGATION_PERIMETER_ROUTES = {
  PERIMETER_EVENT: '/perimeter-events',
  PERIMETER_DETECTION: '/perimeter-detections',
  PERIMETER_POLICY_CORRELATION: '/perimeter-policy-correlations',
  PERIMETER_HOST_CORRELATION: '/perimeter-host-correlations',
}

export async function loadInvestigationPerimeterDetail(kind, id, signal) {
  const route = INVESTIGATION_PERIMETER_ROUTES[kind]
  const recordId = Number(id)
  if (!route || !Number.isSafeInteger(recordId) || recordId <= 0) throw new Error('Perimeter detail is unavailable.')
  const response = await fetch(`${API_BASE}${route}/${recordId}`, { method: 'GET', cache: 'no-store', signal })
  if (!response.ok) throw new Error(`Perimeter detail unavailable (${response.status}).`)
  return response.json()
}
