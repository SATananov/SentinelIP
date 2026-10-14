import { useCallback, useEffect, useState } from 'react'

import {
  attachIncidentEvidence,
  addIncidentReviewNote,
  detachIncidentEvidence,
  loadIncidentReviewEvidence,
  loadIncidentReviewNotes,
  loadIncidentReviews,
  loadIncidentReviewTimeline,
  loadRelatedIncidentEvidence,
  updateIncidentReview,
} from '../services/securityApi.js'

function displayTime(value) {
  return value ? value.replace('T', ' ').replace('+00:00', 'Z') : '—'
}

function IncidentReviewSection({ refreshSignal }) {
  const [reviews, setReviews] = useState([])
  const [selected, setSelected] = useState(null)
  const [evidence, setEvidence] = useState([])
  const [suggestions, setSuggestions] = useState([])
  const [timeline, setTimeline] = useState([])
  const [notes, setNotes] = useState([])
  const [noteText, setNoteText] = useState('')
  const [reviewDraft, setReviewDraft] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const loadReviewData = useCallback(async (reviewId) => {
    const [linked, related, history, analystNotes] = await Promise.all([
      loadIncidentReviewEvidence(reviewId),
      loadRelatedIncidentEvidence(reviewId),
      loadIncidentReviewTimeline(reviewId),
      loadIncidentReviewNotes(reviewId),
    ])
    setEvidence(linked.items)
    setSuggestions(related.items)
    setTimeline(history.items)
    setNotes(analystNotes.items)
  }, [])

  useEffect(() => {
    let active = true
    loadIncidentReviews()
      .then((result) => {
        if (active) setReviews(result.items)
      })
      .catch((err) => {
        if (active) setError(err.message)
      })
    return () => { active = false }
  }, [refreshSignal])

  useEffect(() => {
    if (!selected) return undefined
    let active = true
    Promise.all([
      loadIncidentReviewEvidence(selected.id),
      loadRelatedIncidentEvidence(selected.id),
      loadIncidentReviewTimeline(selected.id),
      loadIncidentReviewNotes(selected.id),
    ])
      .then(([linked, related, history, analystNotes]) => {
        if (!active) return
        setEvidence(linked.items)
        setSuggestions(related.items)
        setTimeline(history.items)
        setNotes(analystNotes.items)
        setError(null)
      })
      .catch((err) => {
        if (active) setError(err.message)
      })
      .finally(() => {
        if (active) setDetailLoading(false)
      })
    return () => { active = false }
  }, [selected, refreshSignal])

  async function perform(key, action) {
    setBusy(key)
    setDetailLoading(true)
    setError(null)
    try {
      await action()
      await loadReviewData(selected.id)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(null)
      setDetailLoading(false)
    }
  }

  async function submitNote(event) {
    event.preventDefault()
    const value = noteText.trim()
    if (!value || !selected) return
    await perform('note', async () => {
      await addIncidentReviewNote(selected.id, value)
      setNoteText('')
    })
  }

  return (
    <article className="panel incident-review-workflow">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Analyst workflow</p>
          <h3>Incident Reviews</h3>
        </div>
        <span className="panel-count">{reviews.length}</span>
      </div>
      <p className="security-layer-copy">
        Reviews group observations for investigation. Suggestions are review aids and do not establish a cause or confirm an attack or compromise.
      </p>
      {error && <p className="security-detail-error">{error}</p>}
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
                setSelected(review)
        setReviewDraft({ state: review.state, priority: review.priority,
          confidence: review.confidence, disposition: review.disposition })
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

      {selected && (
        <div className="incident-review-detail">
          <div className="security-detail-heading">
            <div>
              <p className="panel-kicker">Analyst incident review</p>
              <h3>{selected.title}</h3>
            </div>
            <button className="security-detail-close" type="button" onClick={() => {
              setSelected(null)
              setReviewDraft(null)
              setDetailLoading(false)
            }}>
              Close
            </button>
          </div>
          <p className="incident-review-disclaimer">
            Evidence links and suggestions do not mean causal relationship, attack, compromise, intrusion, exploitation, or vulnerability.
          </p>

          <form className="incident-review-edit-form" onSubmit={async (event) => {
            event.preventDefault()
            await perform('review', async () => {
              const updated = await updateIncidentReview(selected.id, reviewDraft)
              setSelected(updated)
              setReviews((current) => current.map((item) => item.id === updated.id ? updated : item))
            })
          }}>
            {[
              ['state', ['OPEN', 'IN_REVIEW', 'CLOSED']],
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
            <button className="security-detail-close" type="submit" disabled={Boolean(busy)}>Save Review</button>
          </form>

          <section className="incident-review-history">
            <h4>Analyst Notes</h4>
            <form className="incident-review-note-form" onSubmit={submitNote}>
              <textarea aria-label="Analyst note" maxLength={4000} rows={3} value={noteText}
                onChange={(event) => setNoteText(event.target.value)}
                placeholder="Add a factual investigation note" />
              <button className="security-detail-close" type="submit"
                disabled={Boolean(busy) || !noteText.trim()}>Add Note</button>
            </form>
            {notes.length === 0 ? <p className="security-empty">No analyst notes.</p> : (
              <div className="incident-review-items">
                {notes.map((note) => <div className="incident-review-item" key={note.id}>
                  <small>{displayTime(note.created_at)} · {note.actor_source}</small>
                  <span className="incident-review-note-text">{note.note_text}</span>
                </div>)}
              </div>
            )}

            <h4>Investigation History</h4>
            {timeline.length === 0 ? <p className="security-empty">No post-13C review history yet.</p> : (
              <div className="incident-review-items">
                {timeline.map((entry) => <div className="incident-review-item" key={entry.id}>
                  <span><strong>{entry.event_type.replaceAll('_', ' ')}</strong></span>
                  <small>{displayTime(entry.created_at)} · {entry.actor_source}</small>
                  {entry.summary && <span>{entry.summary}</span>}
                  {entry.field_name && <small>{entry.field_name}: {entry.old_value ?? '—'} → {entry.new_value ?? '—'}</small>}
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
