export const DEFAULT_API_BASE = 'http://127.0.0.1:8000'

export function resolveApiBase(configuredValue) {
  if (configuredValue === undefined || configuredValue === null
      || (typeof configuredValue === 'string' && configuredValue.trim() === '')) {
    return DEFAULT_API_BASE
  }
  if (typeof configuredValue !== 'string') {
    throw new TypeError('VITE_SENTINELIP_API_BASE must be an HTTP or HTTPS URL.')
  }

  const value = configuredValue.trim()
  if (!/^https?:\/\//i.test(value)) {
    throw new TypeError('VITE_SENTINELIP_API_BASE must use http:// or https://.')
  }

  let parsed
  try {
    parsed = new URL(value)
  } catch {
    throw new TypeError('VITE_SENTINELIP_API_BASE must be a valid HTTP or HTTPS URL.')
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname
      || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError('VITE_SENTINELIP_API_BASE must be a valid HTTP or HTTPS base URL.')
  }

  return value.replace(/\/+$/, '')
}

const viteEnvironment = import.meta.env ?? {}
export const API_BASE = resolveApiBase(viteEnvironment.VITE_SENTINELIP_API_BASE)
