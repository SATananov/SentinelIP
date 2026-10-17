import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

import {
  attachIncidentEvidence,
  addIncidentReviewNote,
  detachIncidentEvidence,
  loadIncidentReviewEvidence,
  loadIncidentReview,
  loadIncidentReviewNotes,
  loadIncidentReviews,
  loadIncidentReviewTimeline,
  loadRelatedIncidentEvidence,
  updateIncidentReview,
} from '../services/securityApi.js'
import { createIncidentReviewRequestGuard } from '../services/incidentReviewRequestGuard.js'
import CreateIncidentReviewForm from './CreateIncidentReviewForm.jsx'
import InvestigationPivotActions from './InvestigationPivotActions.jsx'
import { evidenceSourcePivot, reviewAttributionPivots } from '../services/investigationPivots.js'
import {
  completeCreatedIncidentReview,
  createIncidentReviewListGuard,
  upsertCreatedIncidentReview,
} from '../services/incidentReviewCreationState.js'

function displayTime(value) {
  return value ? value.replace('T', ' ').replace('+00:00', 'Z') : '—'
}

function IncidentReviewSection({ refreshSignal, selectedReviewId = null, onSelectReview = null,
  getSelectionVersion = null, onReviewCreated = null, intakeRequest = null,
  onClearIntakeRequest = null, onPromotionSubmitting = null, onOpenInvestigationContext = null }) {
  const [reviews, setReviews] = useState([])
  const [selected, setSelected] = useState(null)
  const [evidence, setEvidence] = useState([])
  const [suggestions, setSuggestions] = useState([])
  const [timeline, setTimeline] = useState([])
  const [notes, setNotes] = useState([])
  const [noteText, setNoteText] = useState('')
  const [reviewDraft, setReviewDraft] = useState(null)
  const [error, setError] = useState(null)
  const [listError, setListError] = useState(null)
  const [busy, setBusy] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [createFormOpen, setCreateFormOpen] = useState(false)
  const requestGuard = useRef(createIncidentReviewRequestGuard())
  const reviewListGuard = useRef(createIncidentReviewListGuard())
  const localSelectionVersion = useRef(0)
  const createFormContainer = useRef(null)

  function currentSelectionVersion() {
    return `${getSelectionVersion?.() ?? 0}:${localSelectionVersion.current}`
  }

  const loadReviewData = useCallback(async (reviewId, request) => {
    const [linked, related, history, analystNotes] = await Promise.all([
      loadIncidentReviewEvidence(reviewId),
      loadRelatedIncidentEvidence(reviewId),
      loadIncidentReviewTimeline(reviewId),
      loadIncidentReviewNotes(reviewId),
    ])
    if (!requestGuard.current.isCurrent(request)) return false
    setEvidence(linked.items)
    setSuggestions(related.items)
    setTimeline(history.items)
    setNotes(analystNotes.items)
    return true
  }, [])

  useEffect(() => {
    const listGuard = reviewListGuard.current
    const generation = listGuard.begin()
    loadIncidentReviews()
      .then((result) => {
        if (listGuard.isCurrent(generation)) {
          setReviews(result.items)
          setListError(null)
        }
      })
      .catch((err) => {
        if (listGuard.isCurrent(generation)) setListError(err.message)
      })
    return () => { listGuard.invalidate() }
  }, [refreshSignal])

  const initiatingEvidence = intakeRequest?.evidence ?? null
  const createFormVisible = createFormOpen || Boolean(initiatingEvidence)

  const intakeToken = intakeRequest?.token
  useEffect(() => {
    if (intakeToken === undefined) return
    createFormContainer.current?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  }, [intakeToken])

  async function handleCreatedReview(review, attempt) {
    reviewListGuard.current.invalidate()
    setReviews((current) => upsertCreatedIncidentReview(current, review))
    setListError(null)
    completeCreatedIncidentReview({
      review,
      attempt,
      currentSelectionVersion: currentSelectionVersion(),
      requestGuard: requestGuard.current,
      setSelectedReview: (created) => {
        setEvidence([]); setSuggestions([]); setTimeline([]); setNotes([]); setNoteText('')
        setBusy(null); setError(null); setDetailLoading(true)
        setSelected(created)
        setReviewDraft({ state: created.state, priority: created.priority,
          confidence: created.confidence, disposition: created.disposition,
          final_summary: created.final_summary })
      },
      onSelectReview,
      refreshOperations: onReviewCreated,
    })
  }

  const selectedId = selected?.id
  const displaySelected = selected && (!selectedReviewId || selectedReviewId === selected.id)
  useLayoutEffect(() => {
    if (!selectedReviewId || selectedReviewId === selected?.id) return undefined
    const request = requestGuard.current.selectAndBegin(selectedReviewId)
    Promise.resolve().then(() => {
      if (!requestGuard.current.isCurrent(request)) return null
      setEvidence([]); setSuggestions([]); setTimeline([]); setNotes([])
      setDetailLoading(true); setError(null)
      return loadIncidentReview(selectedReviewId)
    })
      .then((review) => {
        if (!review) return
        if (!requestGuard.current.isCurrent(request)) return
        setSelected(review)
        setReviewDraft({ state: review.state, priority: review.priority,
          confidence: review.confidence, disposition: review.disposition,
          final_summary: review.final_summary })
      })
      .catch((err) => {
        if (requestGuard.current.isCurrent(request)) setError(err.message)
      })
      .finally(() => {
        if (requestGuard.current.isCurrent(request)) setDetailLoading(false)
      })
    return undefined
  }, [selectedReviewId, selected?.id])
  useEffect(() => {
    if (!selectedId) return undefined
    const request = requestGuard.current.begin(selectedId)
    Promise.all([
      loadIncidentReviewEvidence(selectedId),
      loadRelatedIncidentEvidence(selectedId),
      loadIncidentReviewTimeline(selectedId),
      loadIncidentReviewNotes(selectedId),
    ])
      .then(([linked, related, history, analystNotes]) => {
        if (!requestGuard.current.isCurrent(request)) return
        setEvidence(linked.items)
        setSuggestions(related.items)
        setTimeline(history.items)
        setNotes(analystNotes.items)
        setError(null)
      })
      .catch((err) => {
        if (requestGuard.current.isCurrent(request)) setError(err.message)
      })
      .finally(() => {
        if (requestGuard.current.isCurrent(request)) setDetailLoading(false)
      })
    return undefined
  }, [selectedId, refreshSignal])

  async function perform(key, action) {
    if (!selectedId) return
    const reviewId = selectedId
    const request = requestGuard.current.begin(reviewId)
    setBusy(key)
    setDetailLoading(true)
    setError(null)
    try {
      const result = await action()
      if (!requestGuard.current.isCurrent(request)) return
      if (key === 'review' && result) {
        setSelected(result)
        setReviewDraft({ state: result.state, priority: result.priority,
          confidence: result.confidence, disposition: result.disposition,
          final_summary: result.final_summary })
        setReviews((current) => current.map((item) => item.id === result.id ? result : item))
      }
      if (key === 'note') setNoteText('')
      await loadReviewData(reviewId, request)
    } catch (err) {
      if (requestGuard.current.isCurrent(request)) setError(err.message)
    } finally {
      if (requestGuard.current.isCurrent(request)) {
        setBusy(null)
        setDetailLoading(false)
      }
    }
  }

  async function submitNote(event) {
    event.preventDefault()
    const value = noteText.trim()
    if (!value || !selected) return
    await perform('note', () => addIncidentReviewNote(selected.id, value))
  }

  return (
    <article className="panel incident-review-workflow">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Analyst workflow</p>
          <h3>Incident Reviews</h3>
        </div>
        <div className="incident-review-heading-actions">
          <span className="panel-count">{reviews.length}</span>
          {!createFormVisible && <button className="security-detail-close" type="button"
            onClick={() => setCreateFormOpen(true)}>Create Review</button>}
        </div>
      </div>
      <p className="security-layer-copy">
        Reviews group observations for investigation. Suggestions are review aids and do not establish a cause or confirm an attack or compromise.
      </p>
      {error && <p className="security-detail-error">{error}</p>}
      {listError && <p className="security-detail-error">{listError}</p>}
      {createFormVisible && <div ref={createFormContainer}>
        <CreateIncidentReviewForm
        key={intakeRequest ? `promotion-${intakeRequest.token}` : 'manual'}
        getSelectionVersion={currentSelectionVersion}
        onCreated={handleCreatedReview}
        onSubmittingChange={(value) => onPromotionSubmitting?.(Boolean(initiatingEvidence && value))}
        onCancel={() => {
          setCreateFormOpen(false)
          if (intakeRequest) onClearIntakeRequest?.(intakeRequest.token)
        }}
        initiatingEvidence={initiatingEvidence}
        />
      </div>}
      {selectedReviewId && selectedReviewId !== selected?.id && !error && <p className="security-empty" role="status">Loading selected Incident Review…</p>}
      {reviews.length === 0 ? (
        <p className="security-empty">No analyst incident reviews.</p>
      ) : (
        <div className="security-record-list">
          {reviews.map((review) => (
            <button
              className="security-record"
              key={review.id}
              type="button"
              onClick={() => {
                if (selected?.id === review.id) return
                localSelectionVersion.current += 1
                requestGuard.current.select(review.id)
                onSelectReview?.(review.id)
                setEvidence([])
                setSuggestions([])
                setTimeline([])
                setNotes([])
                setNoteText('')
                setBusy(null)
                setSelected(review)
                setReviewDraft({ state: review.state, priority: review.priority,
                  confidence: review.confidence, disposition: review.disposition,
                  final_summary: review.final_summary })
                setDetailLoading(true)
                setError(null)
              }}
            >
              <span className="security-record-id">#{review.id}</span>
              <span className="security-record-main">
                <strong>{review.title}</strong>
                <small>{review.state} · {review.priority} · {review.disposition}</small>
              </span>
            </button>
          ))}
        </div>
      )}

      {displaySelected && (
        <div className="incident-review-detail">
          <div className="security-detail-heading">
            <div>
              <p className="panel-kicker">Analyst incident review</p>
              <h3>{selected.title}</h3>
            </div>
            <button className="security-detail-close" type="button" onClick={() => {
              requestGuard.current.invalidate()
              onSelectReview?.(null)
              setSelected(null)
              setEvidence([])
              setSuggestions([])
              setTimeline([])
              setNotes([])
              setBusy(null)
              setReviewDraft(null)
              setDetailLoading(false)
            }}>
              Close
            </button>
          </div>
          <p className="incident-review-disclaimer">
            Evidence links and suggestions do not mean causal relationship, attack, compromise, intrusion, exploitation, or vulnerability.
          </p>
          <InvestigationPivotActions pivots={reviewAttributionPivots(selected)} onNavigate={onOpenInvestigationContext} />

          {selected.state === 'CLOSED' ? (
            <section className="incident-review-resolution">
              <p className="panel-kicker">Review closed</p>
              <p><strong>Disposition:</strong> {selected.disposition.replaceAll('_', ' ')}</p>
              <p><strong>Final analyst summary</strong></p>
              <p>{selected.final_summary || 'No final analyst summary was recorded for this legacy closed review.'}</p>
              <small>Closed at {displayTime(selected.closed_at)}</small>
              <p className="security-layer-copy">Closure records completion of the analyst review workflow; it does not confirm an attack or compromise.</p>
              <button className="security-detail-close" type="button" disabled={Boolean(busy)}
                onClick={() => perform('review', () => updateIncidentReview(selected.id, { state: 'OPEN' }))}>
                Reopen Review
              </button>
            </section>
          ) : (
            <>
              {timeline.some((entry) => entry.event_type === 'REVIEW_REOPENED') && (
                <p className="security-layer-copy">This review was reopened. Its disposition and final analyst summary are retained from the previous closure until you update them.</p>
              )}
              <form className="incident-review-edit-form" onSubmit={async (event) => {
                event.preventDefault()
                await perform('review', () => updateIncidentReview(selected.id, reviewDraft))
              }}>
                {[
                  ['state', ['OPEN', 'IN_REVIEW']],
                  ['priority', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']],
                  ['confidence', ['LOW', 'MEDIUM', 'HIGH']],
                  ['disposition', ['UNREVIEWED', 'EXPECTED_ACTIVITY', 'BENIGN', 'NEEDS_MONITORING', 'ACTION_REQUIRED', 'FALSE_POSITIVE', 'INCONCLUSIVE']],
                ].map(([field, options]) => (
                  <label key={field}>{field.replaceAll('_', ' ')}
                    <select value={reviewDraft?.[field] ?? selected[field]}
                      onChange={(event) => setReviewDraft((current) => ({ ...current, [field]: event.target.value }))}>
                      {options.map((option) => <option key={option} value={option}>{option.replaceAll('_', ' ')}</option>)}
                    </select>
                  </label>
                ))}
                <label>Final analyst summary
                  <textarea aria-label="Final analyst summary" maxLength={4000} rows={4}
                    value={reviewDraft?.final_summary ?? ''}
                    onChange={(event) => setReviewDraft((current) => ({ ...current, final_summary: event.target.value }))}
                    placeholder="Summarize the review outcome" />
                </label>
                <button className="security-detail-close" type="submit" disabled={Boolean(busy)}>Save Draft</button>
                <button className="security-detail-close" type="button" disabled={Boolean(busy)} onClick={() => {
                  if (reviewDraft?.disposition === 'UNREVIEWED') {
                    setError('Choose a review disposition before closing.')
                    return
                  }
                  if (!reviewDraft?.final_summary?.trim()) {
                    setError('Add a final analyst summary before closing.')
                    return
                  }
                  perform('review', () => updateIncidentReview(selected.id, {
                    ...reviewDraft, state: 'CLOSED',
                  }))
                }}>Close Review</button>
              </form>
            </>
          )}

          <section className="incident-review-history">
            <h4>Analyst Notes</h4>
            <form className="incident-review-note-form" onSubmit={submitNote}>
              <textarea aria-label="Analyst note" maxLength={4000} rows={3} value={noteText}
                onChange={(event) => setNoteText(event.target.value)}
                placeholder="Add a factual investigation note" />
              <button className="security-detail-close" type="submit"
                disabled={Boolean(busy) || !noteText.trim()}>Add Note</button>
            </form>
            {detailLoading ? <p className="security-empty">Loading analyst notes…</p> : notes.length === 0 ? <p className="security-empty">No analyst notes.</p> : (
              <div className="incident-review-items">
                {notes.map((note) => <div className="incident-review-item" key={note.id}>
                  <small>{displayTime(note.created_at)} · {note.actor_source}</small>
                  <span className="incident-review-note-text">{note.note_text}</span>
                </div>)}
              </div>
            )}

            <h4>Investigation History</h4>
            {detailLoading ? <p className="security-empty">Loading investigation history…</p> : timeline.length === 0 ? <p className="security-empty">No post-13C review history yet.</p> : (
              <div className="incident-review-items">
                {timeline.map((entry) => <div className="incident-review-item" key={entry.id}>
                  <span><strong>{entry.event_type.replaceAll('_', ' ')}</strong></span>
                  <small>{displayTime(entry.created_at)} · {entry.actor_source}</small>
                  {entry.summary && <span>{entry.summary}</span>}
                  {entry.field_name && <small>{entry.field_name}: {entry.old_value ?? '—'} → {entry.new_value ?? '—'}</small>}
                  {entry.event_type === 'FINAL_SUMMARY_CHANGED' && <small>Final analyst summary: {entry.old_value ?? '—'} → {entry.new_value ?? '—'}</small>}
                  {entry.evidence_type && <small>{entry.evidence_type} #{entry.evidence_id}</small>}
                </div>)}
              </div>
            )}
          </section>

          <h4>Linked evidence</h4>
          {detailLoading ? <p className="security-empty">Loading linked evidence…</p> : evidence.length === 0 ? <p className="security-empty">No evidence linked.</p> : (
            <div className="incident-review-items">
              {evidence.map((item) => {
                const key = `${item.evidence_type}:${item.evidence_id}`
                return (
                  <div className="incident-review-item" key={key}>
                    <span><strong>{item.evidence_type}</strong> #{item.evidence_id}</span>
                    <small>{displayTime(item.observed_at)} · {item.source_status}</small>
                    {item.source_status === 'MISSING' && <span className="incident-review-missing">Source missing</span>}
                    <InvestigationPivotActions pivots={[evidenceSourcePivot(item)].filter(Boolean)} onNavigate={onOpenInvestigationContext} />
                    <button
                      className="security-detail-close"
                      type="button"
                      disabled={Boolean(busy)}
                      onClick={() => perform(key, () => detachIncidentEvidence(selected.id, item))}
                    >Detach</button>
                  </div>
                )
              })}
            </div>
          )}

          <h4>Suggestions for review</h4>
          <p className="security-empty">Suggestions use exact established attribution and a fixed time window. Review each source before attaching.</p>
          {detailLoading ? <p className="security-empty">Loading suggestions…</p> : suggestions.length === 0 ? <p className="security-empty">No available suggestions in the review time window.</p> : (
            <div className="incident-review-items">
              {suggestions.map((item) => {
                const key = `${item.evidence_type}:${item.evidence_id}`
                return (
                  <div className="incident-review-item" key={key}>
                    <span><strong>{item.evidence_type}</strong> #{item.evidence_id}</span>
                    <small>{displayTime(item.observed_at)} · {item.match_reason}</small>
                    {item.already_linked ? (
                      <span className="incident-review-linked">Already linked</span>
                    ) : item.source_status === 'AVAILABLE' ? (
                      <button
                        className="security-detail-close"
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() => perform(key, () => attachIncidentEvidence(selected.id, item))}
                      >Attach</button>
                    ) : <span className="incident-review-missing">Source missing</span>}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </article>
  )
}

export default IncidentReviewSection
