const API_BASE = 'http://127.0.0.1:8000'

async function requestJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options)

  if (!response.ok) {
    let detail

    try {
      const payload = await response.json()
      detail = payload?.detail ? `: ${payload.detail}` : ''
    } catch {
      detail = ''
    }

    throw new Error(
      `Network API request failed (${response.status})${detail}`,
    )
  }

  return response.json()
}

export function loadNetworks(signal) {
  return requestJson('/networks', { signal })
}

export function loadScopes(signal) {
  return requestJson('/scopes', { signal })
}

export function createPublicIPv4Scope(payload) {
  return requestJson('/scopes/public-ipv4', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function loadScopeDevices(scopeId, signal) {
  return requestJson(`/scopes/${scopeId}/devices`, { signal })
}

export function discoverPublicScope(scopeId) {
  return requestJson(`/scopes/${scopeId}/discover`, { method: 'POST' })
}

export function discoverScopeDeviceServices(scopeId, deviceId) {
  return requestJson(`/scopes/${scopeId}/devices/${deviceId}/discover-services`, {
    method: 'POST',
  })
}

export function discoverNetworkCandidates(signal) {
  return requestJson('/network-candidates', { signal })
}

export function loadNetworkDevices(networkId, signal) {
  return requestJson(`/networks/${networkId}/devices`, { signal })
}

export function discoverNetwork(networkId) {
  return requestJson(`/networks/${networkId}/discover`, {
    method: 'POST',
  })
}

export function loadDevice(deviceId, signal) {
  return requestJson(`/devices/${deviceId}`, { signal })
}

export function discoverDeviceServices(deviceId) {
  return requestJson(`/devices/${deviceId}/discover-services`, {
    method: 'POST',
  })
}

export async function loadDeviceReview(deviceId, signal) {
  const [
    device,
    ports,
    services,
    findings,
    cveMatches,
  ] = await Promise.all([
    loadDevice(deviceId, signal),
    requestJson(`/devices/${deviceId}/ports`, { signal }),
    requestJson(`/devices/${deviceId}/services`, { signal }),
    requestJson(`/devices/${deviceId}/findings`, { signal }),
    requestJson(`/devices/${deviceId}/cve-matches`, { signal }),
  ])

  return {
    device,
    ports,
    services,
    findings,
    cveMatches,
  }
}
