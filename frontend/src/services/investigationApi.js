import { API_BASE } from './apiBase.js'

export const INVESTIGATION_QUERY_TYPES = [
  { value: 'IP_ADDRESS', label: 'IP address' },
  { value: 'DEVICE_ID', label: 'Device ID' },
  { value: 'SENSOR_ID', label: 'Sensor ID' },
  { value: 'SITE_ID', label: 'Site ID' },
  { value: 'SCOPE_ID', label: 'Scope ID' },
  { value: 'INCIDENT_REVIEW_ID', label: 'Incident Review ID' },
  { value: 'INCIDENT_REVIEW_KEY', label: 'Incident Review key' },
  { value: 'TASK_ID', label: 'Sensor Task ID' },
  { value: 'EVIDENCE_REFERENCE', label: 'Evidence reference' },
]

export const INVESTIGATION_EVIDENCE_TYPES = [
  'PERIMETER_DETECTION',
  'PERIMETER_POLICY_CORRELATION',
  'PERIMETER_HOST_CORRELATION',
  'EXTERNAL_EXPOSURE_CHANGE',
  'THREAT_DETECTION',
  'THREAT_CORRELATION',
]

const QUERY_TYPE_SET = new Set(INVESTIGATION_QUERY_TYPES.map(({ value }) => value))
const POSITIVE_ID = /^[1-9][0-9]*$/
const REVIEW_KEY = /^IR-[0-9a-f]{32}$/
const TASK_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function positiveId(value) {
  return typeof value === 'string' && POSITIVE_ID.test(value) && Number.isSafeInteger(Number(value))
}

function canonicalIPv4(value) {
  const parts = value.split('.')
  return parts.length === 4 && parts.every((part) => (
    /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255
  ))
}

export function validateInvestigationLookup({ queryType, value = '', evidenceType = '', evidenceId = '' }) {
  if (!QUERY_TYPE_SET.has(queryType)) return 'Choose a supported lookup type.'
  if (queryType === 'EVIDENCE_REFERENCE') {
    if (!INVESTIGATION_EVIDENCE_TYPES.includes(evidenceType)) return 'Choose a supported evidence type.'
    if (!positiveId(evidenceId)) return 'Evidence ID must be a positive integer.'
    return ''
  }
  if (typeof value !== 'string' || !value || !value.trim() || value !== value.trim()) {
    return 'Enter a value without surrounding whitespace.'
  }
  if (['DEVICE_ID', 'SENSOR_ID', 'SITE_ID', 'SCOPE_ID', 'INCIDENT_REVIEW_ID'].includes(queryType)) {
    return positiveId(value) ? '' : 'ID must be a positive integer.'
  }
  if (queryType === 'IP_ADDRESS') return canonicalIPv4(value) ? '' : 'Enter a canonical IPv4 address.'
  if (queryType === 'INCIDENT_REVIEW_KEY') return REVIEW_KEY.test(value) ? '' : 'Use IR- followed by 32 lowercase hexadecimal characters.'
  if (queryType === 'TASK_ID') return TASK_UUID.test(value) ? '' : 'Enter a canonical lowercase task UUID.'
  return ''
}

export function buildInvestigationLookupQuery(input) {
  const error = validateInvestigationLookup(input)
  if (error) throw new Error(error)
  const params = new URLSearchParams({ query_type: input.queryType })
  if (input.queryType === 'EVIDENCE_REFERENCE') {
    params.set('evidence_type', input.evidenceType)
    params.set('evidence_id', input.evidenceId)
  } else {
    params.set('value', input.value)
  }
  return params.toString()
}

export async function lookupInvestigation(input, signal) {
  const query = buildInvestigationLookupQuery(input)
  const response = await fetch(`${API_BASE}/investigation-lookup?${query}`, {
    method: 'GET',
    cache: 'no-store',
    signal,
  })
  if (!response.ok) {
    const message = response.status === 403
      ? 'Investigation lookup is unavailable from this client.'
      : response.status === 422
        ? 'The lookup request was rejected. Check the selected type and value.'
        : `Investigation lookup failed (${response.status}).`
    throw new Error(message)
  }
  const result = await response.json()
  if (!result || !Array.isArray(result.items) || typeof result.truncated !== 'boolean') {
    throw new Error('Investigation lookup returned an unavailable response.')
  }
  return result
}
