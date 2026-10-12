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
