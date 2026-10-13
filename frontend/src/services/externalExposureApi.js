const API_BASE = 'http://127.0.0.1:8000'

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
