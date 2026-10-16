import { useEffect, useRef, useState } from 'react'

import {
  buildIncidentReviewCreatePayload,
  createIncidentReview,
  createIncidentReviewFromEvidence,
} from '../services/securityApi.js'
import { createIncidentReviewAttemptGuard } from '../services/incidentReviewCreationState.js'
import { isValidPromotedReviewResponse } from '../services/reviewEvidenceContext.js'

const INITIAL_FORM = {
  title: '',
  summary: '',
  priority: 'MEDIUM',
  confidence: 'MEDIUM',
  site_id: '',
  scope_id: '',
  device_id: '',
}

function CreateIncidentReviewForm({ getSelectionVersion, onCreated, onCancel, onSubmittingChange,
  initiatingEvidence = null }) {
  const [form, setForm] = useState(INITIAL_FORM)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const attemptGuard = useRef(createIncidentReviewAttemptGuard())

  useEffect(() => () => attemptGuard.current.invalidate(), [])

  async function submit(event) {
    event.preventDefault()
    if (submitting) return

    let payload
    try {
      payload = buildIncidentReviewCreatePayload(form)
    } catch (err) {
      setError(err.message)
      return
    }

    const selectionVersion = getSelectionVersion?.() ?? 0
    const attempt = attemptGuard.current.begin(selectionVersion)
    if (!attempt) return
    setSubmitting(true)
    onSubmittingChange?.(true)
    setError(null)
    try {
      const result = initiatingEvidence
        ? await createIncidentReviewFromEvidence(payload, initiatingEvidence)
        : await createIncidentReview(payload)
      if (initiatingEvidence && !isValidPromotedReviewResponse(result, initiatingEvidence)) {
        throw new Error('Promotion response did not match the initiating evidence or expected review state.')
      }
      const review = initiatingEvidence ? result.review : result
      if (!attemptGuard.current.isCurrent(attempt)) return
      await onCreated(review, attempt)
      if (!attemptGuard.current.isCurrent(attempt)) return
      setForm(INITIAL_FORM)
      attemptGuard.current.finish(attempt)
      onCancel()
    } catch (err) {
      if (attemptGuard.current.isCurrent(attempt)) setError(err.message)
    } finally {
      if (attemptGuard.current.isCurrent(attempt)) {
        attemptGuard.current.finish(attempt)
        setSubmitting(false)
        onSubmittingChange?.(false)
      }
    }
  }

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }))
    setError(null)
  }

  return (
    <form className="incident-review-create-form" onSubmit={submit}>
      <div className="incident-review-create-heading">
        <div>
          <p className="panel-kicker">Analyst workflow</p>
          <h4>New Incident Review</h4>
        </div>
        <button className="security-detail-close" type="button" disabled={submitting} onClick={onCancel}>
          Cancel
        </button>
      </div>
      <p className="security-layer-copy">
        Incident Reviews are analyst investigation records and do not by themselves confirm an attack or compromise.
      </p>
      {initiatingEvidence && <div className="incident-review-evidence-context" aria-label="Initiating Evidence">
        <strong>Initiating Evidence</strong>
        <span>{initiatingEvidence.label || initiatingEvidence.evidence_type} · Reference {initiatingEvidence.evidence_id}</span>
        {Object.entries(initiatingEvidence.sourceContext || {}).filter(([, value]) => value !== null && value !== undefined && value !== '')
          .map(([key, value]) => <small key={key}>Source {key.replaceAll('_', ' ')}: {String(value)}</small>)}
      </div>}
      {error && <p className="security-detail-error" role="alert">{error}</p>}

      <label>Review Title
        <input aria-label="Review Title" required maxLength={160} value={form.title}
          disabled={submitting} onChange={(event) => update('title', event.target.value)} />
      </label>
      <label>Summary
        <textarea aria-label="Summary" maxLength={4000} rows={3} value={form.summary}
          disabled={submitting} onChange={(event) => update('summary', event.target.value)}
          placeholder="Optional review context" />
      </label>

      <div className="incident-review-create-fields">
        <label>Review Priority
          <select aria-label="Review Priority" value={form.priority} disabled={submitting}
            onChange={(event) => update('priority', event.target.value)}>
            {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((value) => <option key={value}>{value}</option>)}
          </select>
        </label>
        <label>Review Confidence
          <select aria-label="Review Confidence" value={form.confidence} disabled={submitting}
            onChange={(event) => update('confidence', event.target.value)}>
            {['LOW', 'MEDIUM', 'HIGH'].map((value) => <option key={value}>{value}</option>)}
          </select>
        </label>
        {['site_id', 'scope_id', 'device_id'].map((key) => (
          <label key={key}>{key.replace('_id', '').replace(/^./, (letter) => letter.toUpperCase())} ID (optional)
            <input aria-label={`${key.replace('_id', '')} ID`} type="number" min="1" step="1"
              inputMode="numeric" value={form[key]} disabled={submitting}
              onChange={(event) => update(key, event.target.value)} />
          </label>
        ))}
      </div>
      <p className="security-layer-copy">
        Attribution IDs are optional and validated by the server. Missing site, scope, or device attribution is not inferred.
      </p>
      <div className="incident-review-create-actions">
        <button className="security-detail-close" type="submit" disabled={submitting}>
          {submitting ? 'Creating…' : 'Create Review'}
        </button>
      </div>
    </form>
  )
}

export default CreateIncidentReviewForm
