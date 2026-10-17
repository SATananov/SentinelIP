const EVIDENCE_DESTINATIONS = Object.freeze({
  THREAT_DETECTION: 'THREAT_DETECTION',
  THREAT_CORRELATION: 'THREAT_CORRELATION',
  PERIMETER_DETECTION: 'PERIMETER_DETECTION',
  PERIMETER_POLICY_CORRELATION: 'PERIMETER_POLICY_CORRELATION',
  PERIMETER_HOST_CORRELATION: 'PERIMETER_HOST_CORRELATION',
  EXTERNAL_EXPOSURE_CHANGE: 'EXTERNAL_EXPOSURE_CHANGE',
})

const PERIMETER_KINDS = new Set([
  'PERIMETER_EVENT', 'PERIMETER_DETECTION', 'PERIMETER_POLICY_CORRELATION',
  'PERIMETER_HOST_CORRELATION',
])

function validId(value) {
  const id = typeof value === 'number' ? value : Number(value)
  return Number.isSafeInteger(id) && id > 0 ? String(id) : null
}

function pivot(kind, label, rawId, context = {}) {
  const id = validId(rawId)
  if (!id) return null
  return {
    kind,
    id,
    label,
    item: {
      entity_type: kind,
      entity_id: id,
      destination_kind: kind,
      destination_id: id,
      ...context,
    },
  }
}

export function taskContextPivots(task) {
  if (!task) return []
  const context = {
    sensor_id: task.sensor_id ?? null,
    site_id: task.site_id ?? null,
    scope_id: task.scope_id ?? null,
    device_id: task.target_device_id ?? task.device_id ?? null,
  }
  return [
    pivot('SENSOR', 'Open sensor', task.sensor_id, context),
    pivot('SITE', 'Open site', task.site_id, context),
    pivot('SCOPE', 'Open scope', task.scope_id, context),
    pivot('DEVICE', 'Open device', task.target_device_id ?? task.device_id, context),
  ].filter(Boolean)
}

export function deviceTaskHistoryPivot(device) {
  const id = validId(device?.id)
  if (!id) return null
  return {
    kind: 'SENSOR_TASK_DEVICE_FILTER',
    id,
    label: 'View sensor tasks for this device',
    item: { entity_type: 'DEVICE', entity_id: id, device_id: Number(id) },
  }
}

export function deviceContextPivots(device) {
  if (!device) return []
  const context = { device_id: device.id, scope_id: device.scope_id ?? null }
  const scope = pivot('SCOPE', 'Open scope', device.scope_id, context)
  const tasks = deviceTaskHistoryPivot(device)
  return [scope, tasks].filter(Boolean)
}

export function reviewAttributionPivots(review) {
  if (!review) return []
  const context = {
    site_id: review.site_id ?? null,
    scope_id: review.scope_id ?? null,
    device_id: review.device_id ?? null,
  }
  return [
    pivot('SITE', 'Open site', review.site_id, context),
    pivot('SCOPE', 'Open scope', review.scope_id, context),
    pivot('DEVICE', 'Open device', review.device_id, context),
  ].filter(Boolean)
}

export function evidenceSourcePivot(evidence) {
  const kind = EVIDENCE_DESTINATIONS[evidence?.evidence_type]
  if (!kind || evidence?.source_status !== 'AVAILABLE') return null
  return pivot(kind, 'Open evidence', evidence.evidence_id, {
    evidence_type: evidence.evidence_type,
    evidence_id: Number(evidence.evidence_id),
    site_id: evidence.site_id ?? null,
    scope_id: evidence.scope_id ?? null,
    device_id: evidence.device_id ?? null,
  })
}

export function explicitRecordPivots(recordType, record) {
  if (!record) return []
  const context = {
    site_id: record.site_id ?? null,
    scope_id: record.scope_id ?? null,
    device_id: record.device_id ?? null,
    sensor_id: record.sensor_id ?? null,
  }
  if (recordType === 'THREAT_DETECTION' || recordType === 'THREAT_CORRELATION') {
    return [
      pivot('DEVICE', 'Open device', record.device_id, context),
      pivot('SENSOR', 'Open sensor', record.sensor_id, context),
    ].filter(Boolean)
  }
  if (PERIMETER_KINDS.has(recordType)) {
    return [
      pivot('SITE', 'Open site', record.site_id, context),
      pivot('SCOPE', 'Open scope', record.scope_id, context),
      pivot('DEVICE', 'Open device', record.device_id, context),
    ].filter(Boolean)
  }
  if (recordType === 'EXTERNAL_EXPOSURE' || recordType === 'EXTERNAL_EXPOSURE_CHANGE') {
    return [
      pivot('SITE', 'Open site', record.site_id, context),
      pivot('SCOPE', 'Open scope', record.scope_id, context),
      pivot('DEVICE', 'Open device', record.device_id, context),
    ].filter(Boolean)
  }
  return []
}
