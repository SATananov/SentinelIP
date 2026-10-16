const API_BASE = 'http://127.0.0.1:8000'

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
