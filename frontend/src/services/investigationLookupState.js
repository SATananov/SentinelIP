export const INVESTIGATION_ENTITY_LABELS = Object.freeze({
  DEVICE: 'Device', SENSOR: 'Sensor', SITE: 'Site', SCOPE: 'Scope',
  INCIDENT_REVIEW: 'Incident Review', SENSOR_TASK: 'Sensor Task', LEGACY_EVENT: 'Event',
  PERIMETER_EVENT: 'Perimeter Event', THREAT_DETECTION: 'Threat Detection',
  THREAT_CORRELATION: 'Threat Correlation', PERIMETER_DETECTION: 'Perimeter Detection',
  PERIMETER_POLICY_CORRELATION: 'Policy Correlation',
  PERIMETER_HOST_CORRELATION: 'Host Correlation', EXTERNAL_EXPOSURE: 'External Exposure',
  EXTERNAL_EXPOSURE_CHANGE: 'Exposure Change',
})

export function createInvestigationRequestGuard() {
  let generation = 0
  let controller = null
  return {
    begin() {
      controller?.abort()
      controller = new AbortController()
      generation += 1
      return { generation, controller }
    },
    invalidate() {
      generation += 1
      controller?.abort()
      controller = null
    },
    isCurrent(request) {
      return request?.generation === generation && controller === request.controller && !controller.signal.aborted
    },
  }
}

export function investigationResultLabel(entityType) {
  return INVESTIGATION_ENTITY_LABELS[entityType] ?? 'Unknown result type'
}

export function resetInvestigationQueryState(queryType) {
  return {
    queryType,
    value: '',
    evidenceType: '',
    evidenceId: '',
    result: null,
    error: '',
  }
}
