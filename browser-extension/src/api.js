import { validateApiBaseUrl } from './config.js'

export async function sendWebObservation(config, payload, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('Fetch is unavailable.')
  }

  const baseUrl = validateApiBaseUrl(config.apiBaseUrl)
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 5000)

  try {
    const response = await fetchImpl(`${baseUrl}/telemetry/web`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SentinelIP-Sensor-ID': config.sensorId,
        'X-SentinelIP-Sensor-Token': config.sensorToken,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    })

    if (!response.ok) {
      const error = new Error(`Telemetry delivery failed with HTTP ${response.status}.`)
      error.category = response.status === 401 || response.status === 403
        ? 'AUTHENTICATION'
        : 'HTTP'
      throw error
    }

    return await response.json()
  } catch (error) {
    if (error?.name === 'AbortError') {
      error.category = 'TIMEOUT'
    }
    throw error
  } finally {
    clearTimeout(timeout)
  }
}