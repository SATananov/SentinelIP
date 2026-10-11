import { getBrowserApi } from './browser-api.js'

export const DEFAULT_CONFIG = Object.freeze({
  apiBaseUrl: 'http://127.0.0.1:8000',
  sensorId: '',
  sensorToken: '',
  enabled: false,
  privacyMode: 'DOMAIN_ONLY',
})

export function validateApiBaseUrl(value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('API URL is required.')
  }

  const url = new URL(value.trim())
  const allowedHost = url.hostname === 'localhost' || url.hostname === '127.0.0.1'

  if (!allowedHost || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('API URL must target localhost or 127.0.0.1.')
  }

  url.pathname = url.pathname.replace(/\/+$/, '')
  url.search = ''
  url.hash = ''
  return url.toString().replace(/\/$/, '')
}

export function validateConfig(config) {
  const normalized = {
    ...DEFAULT_CONFIG,
    ...config,
    apiBaseUrl: validateApiBaseUrl(config.apiBaseUrl),
  }

  if (typeof normalized.sensorId !== 'string' || !normalized.sensorId.trim()) {
    throw new Error('Sensor ID is required.')
  }
  if (typeof normalized.sensorToken !== 'string' || !normalized.sensorToken.trim()) {
    throw new Error('Sensor token is required.')
  }
  if (!['DOMAIN_ONLY', 'STANDARD'].includes(normalized.privacyMode)) {
    throw new Error('Privacy mode is invalid.')
  }

  return {
    ...normalized,
    sensorId: normalized.sensorId.trim(),
    sensorToken: normalized.sensorToken.trim(),
    enabled: normalized.enabled === true,
  }
}

export async function loadConfig() {
  const api = getBrowserApi()
  if (!api?.storage?.local) {
    return { ...DEFAULT_CONFIG }
  }
  return {
    ...DEFAULT_CONFIG,
    ...(await api.storage.local.get(DEFAULT_CONFIG)),
  }
}

export async function saveConfig(config) {
  const normalized = validateConfig(config)
  const api = getBrowserApi()
  if (!api?.storage?.local) {
    throw new Error('Browser storage is unavailable.')
  }

  await api.storage.local.set(normalized)
  return normalized
}

export async function updateStatus(status) {
  const api = getBrowserApi()
  if (!api?.storage?.local) {
    return
  }
  await api.storage.local.set({
    lastStatus: status,
  })
}