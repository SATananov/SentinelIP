export const WORKSPACE_MODULES = Object.freeze([
  { id: 'overview', label: 'Overview' },
  { id: 'scope-discovery', label: 'Scope & Discovery' },
  { id: 'remote-sensors', label: 'Remote Sensors' },
  { id: 'operations', label: 'Operations' },
  { id: 'detections', label: 'Detections' },
  { id: 'perimeter', label: 'Perimeter' },
  { id: 'events-analytics', label: 'Events & Analytics' },
  { id: 'data-lifecycle', label: 'Data Lifecycle' },
])

const VALID_MODULES = new Set(WORKSPACE_MODULES.map(({ id }) => id))
VALID_MODULES.add('help')
VALID_MODULES.add('about')

export function moduleFromHash(hash) {
  if (typeof hash !== 'string') return 'overview'
  let candidate = ''
  if (hash.startsWith('#workspace/')) candidate = hash.slice('#workspace/'.length).split(/[/?]/, 1)[0]
  else if (hash.startsWith('#module-')) candidate = hash.slice('#module-'.length)
  return VALID_MODULES.has(candidate) ? candidate : 'overview'
}

export function workspaceHash(moduleId, topicId = '') {
  if (!VALID_MODULES.has(moduleId)) throw new TypeError('Unsupported workspace module.')
  if (moduleId === 'help' && topicId) return `#workspace/help?topic=${encodeURIComponent(topicId)}`
  return `#workspace/${moduleId}`
}

export function helpTopicFromHash(hash) {
  if (typeof hash !== 'string' || !hash.startsWith('#workspace/help')) return 'getting-started'
  try { return new URLSearchParams(hash.split('?')[1] ?? '').get('topic') || 'getting-started' }
  catch { return 'getting-started' }
}

export function moduleForInvestigationKind(kind) {
  if (kind === 'LEGACY_EVENT') return 'events-analytics'
  if (['SENSOR', 'SITE', 'SENSOR_TASK', 'SENSOR_TASK_DEVICE_FILTER'].includes(kind)) return 'remote-sensors'
  if (['PERIMETER_EVENT', 'PERIMETER_DETECTION', 'PERIMETER_POLICY_CORRELATION',
    'PERIMETER_HOST_CORRELATION', 'EXTERNAL_EXPOSURE', 'EXTERNAL_EXPOSURE_CHANGE'].includes(kind)) return 'perimeter'
  if (kind === 'INCIDENT_REVIEW') return 'operations'
  if (['THREAT_DETECTION', 'THREAT_CORRELATION', 'WEB_DETECTION'].includes(kind)) return 'detections'
  return 'scope-discovery'
}
