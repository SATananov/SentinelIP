export function sanitizeUrl(rawUrl, privacyMode = 'DOMAIN_ONLY') {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new Error('URL is required.')
  }

  const parsed = new URL(rawUrl.trim())
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP and HTTPS URLs are supported.')
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '')
  const path = privacyMode === 'DOMAIN_ONLY'
    ? ''
    : (parsed.pathname || '/')

  return {
    scheme: parsed.protocol.slice(0, -1),
    hostname,
    url: `${parsed.protocol}//${hostname}${path}`,
  }
}

export function basename(value) {
  if (typeof value !== 'string') {
    return undefined
  }

  const normalized = value.replaceAll('\\', '/')
  const last = normalized.split('/').pop()
  return last || undefined
}

export function supportedPageUrl(value) {
  try {
    return sanitizeUrl(value, 'DOMAIN_ONLY')
  } catch {
    return null
  }
}