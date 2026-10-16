import { useEffect, useRef, useState } from 'react'

import { loadIncidentReviewActivity } from '../services/securityApi.js'
import { createOperationsRequestGuard } from '../services/incidentReviewRequestGuard.js'
import { requestIncidentReviewSelection } from '../services/incidentReviewOperationsState.js'

const EVENT_TYPES = [
  'REVIEW_CREATED', 'STATE_CHANGED', 'REVIEW_CLOSED', 'REVIEW_REOPENED',
  'PRIORITY_CHANGED', 'CONFIDENCE_CHANGED', 'DISPOSITION_CHANGED', 'REVIEW_FIELD_CHANGED',
  'FINAL_SUMMARY_CHANGED', 'ANALYST_NOTE_ADDED', 'ANALYST_NOTE_CLEARED',
  'EVIDENCE_ATTACHED', 'EVIDENCE_DETACHED',
]

function ReviewActivitySection({ refreshSignal, onSelectReview }) {
  const [expanded, setExpanded] = useState(false)
  const [options, setOptions] = useState({ limit: 20, offset: 0, event_type: '', site_id: '' })
  const [request, setRequest] = useState({ data: null, error: null, loading: false })
  const queryKey = JSON.stringify(options)
  const requestGuard = useRef(createOperationsRequestGuard())

  useEffect(() => {
    if (!expanded) return undefined
    const guard = requestGuard.current
    const generation = guard.begin('activity')
    const controller = new AbortController()
    Promise.resolve()
      .then(() => {
        if (controller.signal.aborted) return null
        setRequest((current) => ({ ...current, error: null, loading: true, loadingKey: queryKey }))
        return loadIncidentReviewActivity(options, controller.signal)
      })
      .then((data) => {
        if (!controller.signal.aborted && guard.isCurrent('activity', generation) && data) setRequest({ data, dataKey: queryKey, error: null, errorKey: null, loading: false, loadingKey: queryKey })
      })
      .catch((error) => {
        if (!controller.signal.aborted && guard.isCurrent('activity', generation) && error.name !== 'AbortError') {
          setRequest((current) => ({ ...current, error: error.message, errorKey: queryKey, loading: false, loadingKey: queryKey }))
        }
      })
      .finally(() => {
        if (!controller.signal.aborted && guard.isCurrent('activity', generation)) setRequest((current) => ({ ...current, loading: false }))
      })
    return () => { controller.abort(); guard.invalidate('activity') }
  }, [expanded, options, queryKey, refreshSignal])

  const activityData = request.dataKey === queryKey ? request.data : null
  const activityError = request.errorKey === queryKey ? request.error : null
  const activityLoading = request.loadingKey === queryKey ? request.loading : expanded && !activityData && !activityError
  const page = activityData?.pagination
  const changeOptions = (key, value) => setOptions((current) => ({ ...current, [key]: value, offset: 0 }))

  return (
    <details className="review-activity-feed review-secondary-section" onToggle={(event) => setExpanded(event.currentTarget.open)}>
      <summary><h3>Recent Review Activity</h3></summary>
      <p className="security-layer-copy">Site, scope, and device context reflects the review’s current attribution.</p>
      <div className="review-activity-filters">
        <label><span>Event type</span><select value={options.event_type} onChange={(event) => changeOptions('event_type', event.target.value)}>
          <option value="">All activity</option>{EVENT_TYPES.map((kind) => <option key={kind} value={kind}>{kind.replaceAll('_', ' ')}</option>)}
        </select></label>
        <label><span>Site ID</span><input type="number" min="1" value={options.site_id} onChange={(event) => changeOptions('site_id', event.target.value)} placeholder="All sites" /></label>
      </div>
      {activityError && <div className="error-box">{activityError}</div>}
      {activityLoading && activityData && <p className="security-layer-copy" role="status">Updating review activity…</p>}
      {activityLoading && !activityData ? <p className="security-empty">Loading review activity…</p>
        : activityError && !activityData ? null
          : !activityData?.activity?.length ? <p className="security-empty">No review activity matches the selected filters.</p>
            : <div className="review-queue-table-wrap"><table className="review-queue-table"><thead><tr>
              <th>Time</th><th>Review</th><th>Activity</th><th>Current Site</th><th>Actor</th>
            </tr></thead><tbody>{activityData.activity.map((item) => <tr key={item.event_id}>
              <td>{item.created_at.replace('T', ' ').replace('+00:00', 'Z')}</td>
              <td><button type="button" className="review-queue-select" onClick={() => requestIncidentReviewSelection(item.incident_review_id, onSelectReview)}><strong>{item.incident_key}</strong><small>{item.review_title}</small></button></td>
              <td>{item.summary}</td><td>{item.site_name ?? (item.site_id === null ? 'Unattributed' : `Site ${item.site_id}`)}</td><td>{item.actor_source}</td>
            </tr>)}</tbody></table></div>}
      {page && <div className="pagination"><span className="pagination-summary">{page.total ? `Page ${Math.floor(page.offset / page.limit) + 1} of ${Math.max(1, Math.ceil(page.total / page.limit))} · ${page.total} events` : 'No matching activity'}</span><div className="pagination-actions">
        <button type="button" disabled={page.offset === 0 || activityLoading} onClick={() => setOptions((current) => ({ ...current, offset: Math.max(0, current.offset - current.limit) }))}>Previous</button>
        <button type="button" disabled={page.offset + page.limit >= page.total || page.offset >= 100000 || activityLoading} onClick={() => setOptions((current) => ({ ...current, offset: current.offset + current.limit }))}>Next</button>
      </div></div>}
    </details>
  )
}

export default ReviewActivitySection
