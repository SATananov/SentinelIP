import { useLayoutEffect, useRef, useState } from 'react'

import {
  downloadIncidentReviewJson,
  openIncidentReviewHtmlReport,
  triggerIncidentReviewJsonDownload,
} from '../services/incidentReviewReportApi.js'

function safeReportError(error) {
  if (error?.name === 'AbortError') return null
  if (error?.status === 404) return 'Incident Review report is no longer available.'
  if (error?.status === 413) return 'Incident Review report exceeds the allowed export size.'
  return 'Incident Review report request failed.'
}

function IncidentReviewHandoffActions({ reviewId }) {
  const [pending, setPending] = useState(false)
  const [message, setMessage] = useState('')
  const requestRef = useRef(null)
  const generationRef = useRef(0)
  const selectedIdRef = useRef(reviewId)
  const validReviewId = Number.isSafeInteger(reviewId) && reviewId > 0

  useLayoutEffect(() => {
    selectedIdRef.current = reviewId
    return () => {
      generationRef.current += 1
      requestRef.current?.abort()
      requestRef.current = null
    }
  }, [reviewId])

  async function downloadJson() {
    if (!validReviewId) return
    requestRef.current?.abort()
    const controller = new AbortController()
    const generation = ++generationRef.current
    const requestedId = reviewId
    requestRef.current = controller
    setPending(true)
    setMessage('')
    try {
      const result = await downloadIncidentReviewJson(requestedId, controller.signal)
      if (generation !== generationRef.current || selectedIdRef.current !== requestedId) return
      triggerIncidentReviewJsonDownload(result.blob, result.filename)
    } catch (error) {
      if (generation !== generationRef.current || selectedIdRef.current !== requestedId) return
      const safeMessage = safeReportError(error)
      if (safeMessage) setMessage(safeMessage)
    } finally {
      if (generation === generationRef.current && selectedIdRef.current === requestedId) {
        requestRef.current = null
        setPending(false)
      }
    }
  }

  function openPrintableReport() {
    if (!validReviewId) return
    setMessage('')
    try {
      if (!openIncidentReviewHtmlReport(reviewId)) setMessage('Allow pop-ups to open the printable report.')
    } catch {
      setMessage('Printable report could not be opened.')
    }
  }

  return (
    <div className="incident-review-handoff-actions" aria-label="Incident Review reports">
      <button className="security-detail-close" type="button" disabled={!validReviewId || pending}
        onClick={downloadJson}>{pending ? 'Preparing JSON…' : 'Download JSON'}</button>
      <button className="security-detail-close" type="button" disabled={!validReviewId}
        onClick={openPrintableReport}>Printable Report</button>
      {message && <span className="incident-review-report-message" role="status">{message}</span>}
    </div>
  )
}

export default IncidentReviewHandoffActions
