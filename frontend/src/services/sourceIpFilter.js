export function isCanonicalIpv4(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 15) return false

  const octets = value.split('.')
  if (octets.length !== 4) return false

  return octets.every((octet) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(octet)) return false
    const number = Number(octet)
    return number >= 0 && number <= 255
  })
}

export function resolveSourceIpApply(draft, applied) {
  const candidate = draft.trim()
  if (!candidate) return { draft: '', applied: '', error: '' }
  if (!isCanonicalIpv4(candidate)) {
    return { draft, applied, error: 'Enter a valid IPv4 address.' }
  }
  return { draft: candidate, applied: candidate, error: '' }
}

export function buildEventsQuery({ limit, offset, timeRange, severity, sourceIp }) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    time_range: timeRange,
  })
  if (severity !== 'ALL') params.set('severity', severity)
  if (sourceIp) params.set('source_ip', sourceIp)
  return params
}

export function topIpBasisLabel(basis) {
  if (basis?.mode !== 'latest_events'
      || !Number.isSafeInteger(basis.sample_size)
      || basis.sample_size <= 0) return null

  return `Based on latest ${basis.sample_size.toLocaleString()} stored events`
}
