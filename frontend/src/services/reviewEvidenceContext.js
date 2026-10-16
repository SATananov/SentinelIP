const EVIDENCE_CONTEXTS = Object.freeze({
  PERIMETER_DETECTION: 'Perimeter detection',
  PERIMETER_POLICY_CORRELATION: 'Perimeter policy correlation',
  PERIMETER_HOST_CORRELATION: 'Perimeter host correlation',
  EXTERNAL_EXPOSURE_CHANGE: 'Exposure change',
  THREAT_DETECTION: 'Threat detection',
  THREAT_CORRELATION: 'Threat correlation',
  WEB_DETECTION: 'Web detection',
})

export function buildReviewEvidenceContext(evidenceType, record) {
  const labelPrefix = EVIDENCE_CONTEXTS[evidenceType]
  const evidenceId = record?.id
  if (!labelPrefix || !Number.isSafeInteger(evidenceId) || evidenceId <= 0) return null

  return {
    evidence_type: evidenceType,
    evidence_id: evidenceId,
    label: `${labelPrefix} #${evidenceId}`,
    sourceContext: {
      site_name: record.site_name ?? null,
      site_id: record.site_id ?? null,
      scope_name: record.scope_name ?? record.canonical_target ?? null,
      scope_id: record.scope_id ?? null,
      device_label: record.device_hostname ?? record.hostname ?? null,
      device_id: record.device_id ?? null,
      target: record.target_ip && record.port_number
        ? `${record.target_ip}:${record.port_number}`
        : null,
    },
  }
}

export function isValidReviewEvidenceContext(context) {
  return Boolean(
    context
    && EVIDENCE_CONTEXTS[context.evidence_type]
    && Number.isSafeInteger(context.evidence_id)
    && context.evidence_id > 0,
  )
}

export function matchesReviewEvidenceResponse(response, context) {
  return Boolean(
    isValidReviewEvidenceContext(context)
    && response?.evidence?.evidence_type === context.evidence_type
    && response?.evidence?.evidence_id === context.evidence_id,
  )
}

export function isValidPromotedReviewResponse(response, context) {
  const review = response?.review
  return Boolean(
    matchesReviewEvidenceResponse(response, context)
    && Number.isSafeInteger(review?.id) && review.id > 0
    && review.state === 'OPEN'
    && review.disposition === 'UNREVIEWED',
  )
}

export function createReviewIntakeRequest(token, evidence) {
  if (!Number.isSafeInteger(token) || token <= 0 || !isValidReviewEvidenceContext(evidence)) return null
  return Object.freeze({
    token,
    evidence: Object.freeze({
      evidence_type: evidence.evidence_type,
      evidence_id: evidence.evidence_id,
      label: evidence.label,
      sourceContext: evidence.sourceContext ? Object.freeze({ ...evidence.sourceContext }) : null,
    }),
  })
}

export function clearReviewIntakeRequest(current, token) {
  return current?.token === token ? null : current
}
