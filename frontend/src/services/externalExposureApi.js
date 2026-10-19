import { API_BASE } from './apiBase.js'

export async function loadExternalExposureDashboard(filters = {}, signal) {
  const params = new URLSearchParams()

  if (filters.scopeId) {
    params.set('scope_id', filters.scopeId)
  }

  params.set('time_range', filters.timeRange || '7d')

  const response = await fetch(
    `${API_BASE}/external-exposure-dashboard?${params.toString()}`,
    { signal },
  )

  if (!response.ok) {
    throw new Error(
      `External exposure dashboard request failed (${response.status})`,
    )
  }

  return response.json()
}

export async function loadInvestigationExposureDetail(kind, id, signal) {
  const recordId = Number(id)
  const route = kind === 'EXTERNAL_EXPOSURE'
    ? '/external-exposures'
    : kind === 'EXTERNAL_EXPOSURE_CHANGE'
      ? '/external-exposure-changes'
      : null
  if (!route || !Number.isSafeInteger(recordId) || recordId <= 0) throw new Error('Exposure detail is unavailable.')
  const response = await fetch(`${API_BASE}${route}/${recordId}`, { method: 'GET', cache: 'no-store', signal })
  if (!response.ok) throw new Error(`Exposure detail unavailable (${response.status}).`)
  return response.json()
}
