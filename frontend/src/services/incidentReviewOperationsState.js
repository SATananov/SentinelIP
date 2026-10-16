export function siteContextFromWorkloadRow(row) {
  if (row?.site_id === null) return { site_id: null, unattributed_only: true }
  if (Number.isSafeInteger(row?.site_id) && row.site_id > 0) {
    return { site_id: row.site_id, unattributed_only: false }
  }
  throw new Error('Site workload row has an invalid site identifier.')
}

export function applySiteContextToQueue(filters, context) {
  const next = { ...filters }
  for (const key of ['site_id', 'unattributed_only', 'scope_id', 'device_id',
    'unattributed_scope_only', 'unattributed_device_only']) delete next[key]
  if (context.site_id === null) next.unattributed_only = true
  else next.site_id = context.site_id
  return { ...next, offset: 0 }
}

export function applyScopeDrilldown(filters, scopeId) {
  const next = { ...filters }
  delete next.scope_id
  delete next.unattributed_scope_only
  if (scopeId === null) next.unattributed_scope_only = true
  else next.scope_id = scopeId
  return { ...next, offset: 0 }
}

export function applyDeviceDrilldown(filters, deviceId) {
  const next = { ...filters }
  delete next.device_id
  delete next.unattributed_device_only
  if (deviceId === null) next.unattributed_device_only = true
  else next.device_id = deviceId
  return { ...next, offset: 0 }
}

export function isCurrentReviewQueueResult(data, queryKey) {
  return data?.queryKey === queryKey ? data.result : null
}

export function requestIncidentReviewSelection(reviewId, onSelectReview) {
  onSelectReview?.(reviewId)
}

