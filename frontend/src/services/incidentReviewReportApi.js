import { API_BASE } from './apiBase.js'

export class IncidentReviewReportError extends Error {
  constructor(status = null) {
    const message = status === 404
      ? 'Incident Review report is no longer available.'
      : status === 413
        ? 'Incident Review report exceeds the allowed export size.'
        : 'Incident Review report request failed.'
    super(message)
    this.name = 'IncidentReviewReportError'
    this.status = status
  }
}

export function validateIncidentReviewReportId(reviewId) {
  if (!Number.isSafeInteger(reviewId) || reviewId <= 0) {
    throw new TypeError('Incident Review ID must be a positive integer.')
  }
  return reviewId
}

export function buildIncidentReviewJsonReportUrl(reviewId) {
  validateIncidentReviewReportId(reviewId)
  return `${API_BASE}/incident-reviews/${reviewId}/report.json`
}

export function buildIncidentReviewHtmlReportUrl(reviewId) {
  validateIncidentReviewReportId(reviewId)
  return `${API_BASE}/incident-reviews/${reviewId}/report.html`
}

export function incidentReviewJsonFilename(reviewId, contentDisposition = '') {
  validateIncidentReviewReportId(reviewId)
  const match = /^attachment; filename="(sentinelip-incident-review-(\d+)-(\d{8}T\d{6}Z)\.json)"$/i.exec(contentDisposition)
  if (match && match[2] === String(reviewId)) return match[1]
  return `sentinelip-incident-review-${reviewId}.json`
}

export async function downloadIncidentReviewJson(reviewId, signal) {
  const response = await fetch(buildIncidentReviewJsonReportUrl(reviewId), {
    method: 'GET',
    cache: 'no-store',
    signal,
  })
  if (!response.ok) throw new IncidentReviewReportError(response.status)
  const blob = await response.blob()
  return {
    blob,
    filename: incidentReviewJsonFilename(reviewId, response.headers?.get?.('content-disposition') ?? ''),
  }
}

export function triggerIncidentReviewJsonDownload(blob, filename, browser = globalThis) {
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

export function openIncidentReviewHtmlReport(reviewId, browser = globalThis) {
  const url = buildIncidentReviewHtmlReportUrl(reviewId)
  const popup = browser.window.open('about:blank', '_blank')
  if (!popup) return null
  popup.opener = null
  const referrerPolicy = popup.document.createElement('meta')
  referrerPolicy.name = 'referrer'
  referrerPolicy.content = 'no-referrer'
  popup.document.head.appendChild(referrerPolicy)
  popup.location.replace(url)
  return popup
}
