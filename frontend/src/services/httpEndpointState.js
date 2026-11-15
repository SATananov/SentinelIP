import { HTTP_ENDPOINT_HISTORY_MAX_ROWS } from './httpEndpointApi.js'

export function httpEndpointIdentity(scopeId, deviceId, portId) {
  return `${scopeId ?? ''}:${deviceId ?? ''}:${portId ?? ''}`
}

export function isCurrentHttpEndpointRequest(requestIdentity, currentIdentity, requestGeneration, currentGeneration, signal) {
  return requestIdentity === currentIdentity && requestGeneration === currentGeneration && !signal?.aborted
}

export function tryBeginHttpEndpointRequest(lock) {
  if (lock.current) return false
  lock.current = true
  return true
}

export function endHttpEndpointRequest(lock) {
  lock.current = false
}

export function selectableTcpPorts(ports) {
  return (Array.isArray(ports) ? ports : [])
    .filter((port) => Number.isSafeInteger(port?.id) && port.id > 0
      && Number.isInteger(port?.port_number) && port.port_number >= 1 && port.port_number <= 65535
      && String(port?.transport).toLowerCase() === 'tcp'
      && String(port?.state).toLowerCase() === 'open')
    .slice()
    .sort((left, right) => left.port_number - right.port_number || left.id - right.id)
}

export function appendUniqueObservations(existing, incoming, maxRows = HTTP_ENDPOINT_HISTORY_MAX_ROWS) {
  const rows = Array.isArray(existing) ? existing : []
  const next = Array.isArray(incoming) ? incoming : []
  const seen = new Set()
  const merged = []
  for (const row of [...rows, ...next]) {
    if (!row || !Number.isSafeInteger(row.id) || row.id <= 0 || seen.has(row.id)) continue
    seen.add(row.id)
    merged.push(row)
    if (merged.length >= maxRows) break
  }
  return merged
}

export function inspectionPresentation(result, error) {
  if (error) {
    if (error.kind === 'persistence_failure') return {
      tone: 'warning', title: 'Inspection completed; observation not stored',
      message: error.inspectionOutcome ? `Inspection outcome: ${error.inspectionOutcome}.` : 'The result was not stored.',
    }
    if (error.kind === 'authorization') return { tone: 'error', title: 'Inspection rejected', message: error.message }
    if (error.kind === 'missing_resource') return { tone: 'error', title: 'Selected endpoint unavailable', message: error.message }
    if (error.kind === 'scope_changed') return { tone: 'warning', title: 'Authorization changed', message: error.message }
    if (error.kind === 'timeout') return { tone: 'warning', title: 'Inspection timed out', message: error.message }
    return { tone: 'error', title: 'Inspection request failed', message: error.message }
  }
  if (!result) return null
  const persisted = result.persistence?.status === 'PERSISTED'
  if (result.outcome === 'CAPACITY_REJECTED') return {
    tone: 'warning', title: 'Inspection skipped due to capacity limits',
    message: 'No inspection or history record was created.',
  }
  if (result.outcome === 'RESPONSE_RECEIVED' && result.scheme === 'https'
      && result.tls?.certificate_verification !== 'VERIFIED') return {
    tone: 'error', title: 'HTTPS response was not verified',
    message: persisted ? 'The failed TLS result was stored for review.' : 'The HTTPS response was not trusted.',
  }
  if (result.outcome === 'RESPONSE_RECEIVED') return {
    tone: 'good', title: result.scheme === 'https' ? 'HTTPS response received; TLS identity verified' : 'HTTP response received',
    message: persisted ? 'Observation stored in endpoint history.' : 'Observation storage was not confirmed.',
  }
  const titles = {
    TLS_VERIFICATION_FAILED: 'TLS certificate verification failed',
    TLS_HANDSHAKE_FAILED: 'TLS handshake failed',
    TIMEOUT: 'Inspection timed out',
    CONNECTION_FAILED: 'Connection failed',
    DNS_REVALIDATION_FAILED: 'Hostname authorization could not be revalidated',
    HEADER_LIMIT_EXCEEDED: 'Response header limit exceeded',
    MALFORMED_RESPONSE: 'Malformed HTTP response',
  }
  return {
    tone: 'warning', title: titles[result.outcome] || 'Inspection did not receive an HTTP response',
    message: persisted ? 'The failed inspection result was stored in endpoint history.' : 'No stored observation was confirmed.',
  }
}

export function verifiedTlsFacts(tls) {
  return tls?.verification_status === 'VERIFIED' ? tls : null
}

export function safeResponseHeaders(headers) {
  const allowed = new Set([
    'date', 'cache-control', 'strict-transport-security', 'x-content-type-options',
    'x-frame-options', 'content-security-policy', 'referrer-policy', 'permissions-policy',
  ])
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return []
  return Object.entries(headers).filter(([name, value]) => allowed.has(name) && typeof value === 'string')
}
