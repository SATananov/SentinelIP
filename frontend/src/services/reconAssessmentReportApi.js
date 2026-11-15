import { API_BASE } from './apiBase.js'

export const ASSESSMENT_REPORT_MIME_TYPES = Object.freeze({
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  html: 'text/html',
})

export const MAX_ASSESSMENT_REPORT_BYTES = 15_728_640
const MAX_ASSESSMENT_JSON_BYTES = MAX_ASSESSMENT_REPORT_BYTES

export class AssessmentReportError extends Error {
  constructor(message = 'The assessment report could not be loaded.', status = null) {
    super(message)
    this.name = 'AssessmentReportError'
    this.status = status
  }
}

export function validateAssessmentScopeId(scopeId) {
  if (!Number.isSafeInteger(scopeId) || scopeId <= 0) {
    throw new TypeError('Assessment scope must be a positive integer.')
  }
  return scopeId
}

export function assessmentReportUrl(scopeId) {
  validateAssessmentScopeId(scopeId)
  return `${API_BASE}/recon/scopes/${scopeId}/assessment-report`
}

export function assessmentReportExportUrl(scopeId, format) {
  validateAssessmentScopeId(scopeId)
  if (!Object.hasOwn(ASSESSMENT_REPORT_MIME_TYPES, format)) {
    throw new TypeError('Unsupported assessment report format.')
  }
  return `${assessmentReportUrl(scopeId)}/${format}`
}

async function responseError(response) {
  const message = response.status === 403
    ? 'This assessment scope is not currently authorized.'
    : response.status === 404
      ? 'No assessment data is available for this scope.'
      : response.status === 413
        ? 'The assessment report exceeds the allowed size.'
        : 'The assessment report request failed.'
  return new AssessmentReportError(message, response.status)
}

export async function loadAssessmentReport(scopeId, signal) {
  const response = await fetch(assessmentReportUrl(scopeId), {
    method: 'GET',
    cache: 'no-store',
    signal,
    headers: { Accept: 'application/json' },
  })
  if (!response.ok) throw await responseError(response)
  const contentLength = Number(response.headers?.get?.('content-length') || 0)
  if (contentLength > MAX_ASSESSMENT_JSON_BYTES) {
    throw new AssessmentReportError('The assessment preview exceeds the allowed size.', response.status)
  }
  let text
  try {
    text = await response.text()
    if (new TextEncoder().encode(text).byteLength > MAX_ASSESSMENT_JSON_BYTES) {
      throw new AssessmentReportError('The assessment preview exceeds the allowed size.', response.status)
    }
    const report = JSON.parse(text)
    if (!report || report.assessment?.scope_id !== scopeId || !Array.isArray(report.devices)
        || !Array.isArray(report.findings) || !Array.isArray(report.recommendations)
        || !report.coverage || typeof report.report_id !== 'string' || typeof report.generated_at !== 'string') {
      throw new AssessmentReportError('The assessment response was incomplete.', response.status)
    }
    return report
  } catch (error) {
    if (error instanceof AssessmentReportError) throw error
    throw new AssessmentReportError('The assessment response could not be read.', response.status)
  }
}

export function assessmentReportFilename(scopeId, format, contentDisposition = '') {
  validateAssessmentScopeId(scopeId)
  if (!Object.hasOwn(ASSESSMENT_REPORT_MIME_TYPES, format)) {
    throw new TypeError('Unsupported assessment report format.')
  }
  const extension = format === 'docx' ? 'docx' : format
  const match = /^attachment; filename="(sentinelip-assessment-(\d+)-([0-9a-f-]{36})\.(pdf|docx|html))"$/i.exec(contentDisposition)
  if (match && match[2] === String(scopeId) && match[4].toLowerCase() === extension) return match[1]
  return `sentinelip-assessment-${scopeId}.${extension}`
}

export async function downloadAssessmentReport(scopeId, format, signal) {
  const response = await fetch(assessmentReportExportUrl(scopeId, format), {
    method: 'GET',
    cache: 'no-store',
    signal,
    headers: { Accept: ASSESSMENT_REPORT_MIME_TYPES[format] },
  })
  if (!response.ok) throw await responseError(response)
  const actualType = (response.headers?.get?.('content-type') || '').split(';', 1)[0].trim().toLowerCase()
  if (actualType !== ASSESSMENT_REPORT_MIME_TYPES[format]) {
    throw new AssessmentReportError('The server returned an unexpected report format.', response.status)
  }
  const blob = await response.blob()
  if (!blob.size || blob.size > MAX_ASSESSMENT_REPORT_BYTES) {
    throw new AssessmentReportError(blob.size ? 'The assessment report exceeds the allowed size.' : 'The assessment report was empty.', response.status)
  }
  return {
    blob,
    filename: assessmentReportFilename(scopeId, format,
      response.headers?.get?.('content-disposition') ?? ''),
  }
}

export function triggerAssessmentReportDownload(blob, filename, browser = globalThis) {
  const objectUrl = browser.URL.createObjectURL(blob)
  let anchor
  try {
    anchor = browser.document.createElement('a')
    anchor.href = objectUrl
    anchor.download = filename
    browser.document.body.appendChild(anchor)
    anchor.click()
  } finally {
    anchor?.remove()
    browser.URL.revokeObjectURL(objectUrl)
  }
}
