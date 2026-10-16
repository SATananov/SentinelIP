import { useEffect, useMemo, useState } from 'react'

import { loadIncidentReviewOperations } from '../services/securityApi.js'
import { formatReviewAge } from '../services/incidentReviewFormat.js'

const AGE_LABELS = { LT_1H: '< 1h', H1_24: '1h–24h', D1_3: '1d–3d', D3_7: '3d–7d', GT_7D: '> 7d' }

function IncidentReviewOperations({ refreshSignal, onSelectReview }) {
  const [filters, setFilters] = useState({ sort: 'oldest_open', limit: 20, offset: 0 })
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const query = useMemo(() => ({ ...filters }), [filters])

  useEffect(() => {
    const controller = new AbortController()
    Promise.resolve().then(() => {
      if (!controller.signal.aborted) { setLoading(true); setError(null) }
      return loadIncidentReviewOperations(query, controller.signal)
    })
      .then((result) => { if (!controller.signal.aborted) setData(result) })
      .catch((err) => { if (err.name !== 'AbortError') setError(err.message) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [query, refreshSignal])

  function updateFilter(key, value) {
    setFilters((current) => ({ ...current, [key]: value, offset: 0 }))
  }

  const summary = data?.summary
  const page = data?.pagination
  const totalPages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1
  const currentPage = page ? Math.floor(page.offset / page.limit) + 1 : 1

  return (
    <section className="panel review-operations">
      <div className="panel-heading"><div><p className="panel-kicker">Analyst Operations</p><h2>Review Queue</h2>
        <p className="security-layer-copy">Priority reflects analyst review workload. Review age is time since creation and does not indicate severity.</p></div>
        <span className="panel-count">{loading ? '…' : page?.total ?? 0}</span></div>
      {summary && <div className="review-operations-cards">
        <article><span>Total Reviews</span><strong>{summary.total_reviews}</strong></article>
        <article><span>Open Reviews</span><strong>{summary.open_count}</strong></article>
        <article><span>In Review</span><strong>{summary.in_review_count}</strong></article>
        <article><span>Closed Reviews</span><strong>{summary.closed_count}</strong></article>
        <article><span>Unresolved</span><strong>{summary.unresolved_count}</strong></article>
        <article><span>Created · 24h</span><strong>{summary.created_last_24h}</strong></article>
        <article><span>Closed · 24h</span><strong>{summary.closed_last_24h}</strong></article>
      </div>}
      {summary && <div className="review-operations-breakdown">
        <div><strong>Priority</strong>{Object.entries(summary.priority_distribution).map(([key, count]) => <span key={key}>{key}: {count}</span>)}</div>
        <div><strong>Active Review Age</strong>{Object.entries(summary.active_age_buckets).map(([key, count]) => <span key={key}>{AGE_LABELS[key]}: {count}</span>)}</div>
        <div><strong>Disposition</strong>{Object.entries(summary.disposition_distribution).map(([key, count]) => <span key={key}>{key.replaceAll('_',' ')}: {count}</span>)}</div>
        <div><strong>Reviews by Site</strong>{summary.reviews_by_site.map(({ site_id, count }) => <span key={site_id ?? 'unattributed'}>{site_id === null ? 'Unattributed' : `Site ${site_id}`}: {count}</span>)}</div>
      </div>}
      <div className="filters review-operations-filters">
        <label><span>State</span><select value={filters.state || ''} onChange={(e) => updateFilter('state', e.target.value)}><option value="">All states</option><option>OPEN</option><option>IN_REVIEW</option><option>CLOSED</option></select></label>
        <label><span>Priority</span><select value={filters.priority || ''} onChange={(e) => updateFilter('priority', e.target.value)}><option value="">All priorities</option>{['CRITICAL','HIGH','MEDIUM','LOW'].map((v) => <option key={v}>{v}</option>)}</select></label>
        <label><span>Disposition</span><select value={filters.disposition || ''} onChange={(e) => updateFilter('disposition', e.target.value)}><option value="">All dispositions</option>{['UNREVIEWED','EXPECTED_ACTIVITY','BENIGN','NEEDS_MONITORING','ACTION_REQUIRED','FALSE_POSITIVE','INCONCLUSIVE'].map((v) => <option key={v}>{v}</option>)}</select></label>
        <label><span>Review Age</span><select value={filters.age_bucket || ''} onChange={(e) => updateFilter('age_bucket', e.target.value)}><option value="">Any age</option>{Object.entries(AGE_LABELS).map(([v, label]) => <option key={v} value={v}>{label}</option>)}</select></label>
        {['site_id','scope_id','device_id'].map((key) => <label key={key}><span>{key.replace('_id','').replace('_',' ')}</span><input aria-label={key} type="number" min="1" value={filters[key] || ''} onChange={(e) => updateFilter(key, e.target.value)} placeholder="All" /></label>)}
        <label><span>Evidence</span><select value={filters.has_evidence === true ? 'true' : filters.has_evidence === false ? 'false' : ''} onChange={(e) => updateFilter('has_evidence', e.target.value === '' ? '' : e.target.value === 'true')}><option value="">Any</option><option value="true">Has evidence</option><option value="false">No evidence</option></select></label>
        <label><span>Sort</span><select value={filters.sort} onChange={(e) => updateFilter('sort', e.target.value)}>{[['oldest_open','Oldest open'],['newest','Newest'],['oldest','Oldest'],['priority','Priority'],['recently_updated','Recently updated']].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label className="review-operations-check"><input type="checkbox" checked={Boolean(filters.unresolved_only)} onChange={(e) => updateFilter('unresolved_only', e.target.checked)} /> Unresolved only</label>
        <label className="review-operations-check"><input type="checkbox" checked={filters.has_evidence === true} onChange={(e) => updateFilter('has_evidence', e.target.checked ? true : '')} /> Has linked evidence</label>
        <button type="button" className="clear-filters" onClick={() => setFilters({ sort: 'oldest_open', limit: 20, offset: 0 })}>Clear filters</button>
      </div>
      {error && <div className="error-box">{error}</div>}
      {loading && !data ? <p className="security-empty">Loading review queue…</p> : error && !data ? null : !data?.queue?.length ? <p className="security-empty">No reviews match the selected filters.</p> : (
        <div className="review-queue-table-wrap"><table className="review-queue-table"><thead><tr><th>Review</th><th>State</th><th>Priority</th><th>Disposition</th><th>Review Age</th><th>Evidence</th><th>Notes</th><th>Latest Activity</th></tr></thead><tbody>
          {data.queue.map((row) => <tr key={row.id}><td><button type="button" className="review-queue-select" onClick={() => onSelectReview(row.id)}><strong>{row.title}</strong><small>{row.incident_key}</small></button></td><td>{row.state.replaceAll('_',' ')}</td><td>{row.priority}</td><td>{row.disposition.replaceAll('_',' ')}</td><td>{formatReviewAge(row.age_seconds, row.age_bucket)}</td><td>{row.linked_evidence_count}</td><td>{row.note_count}</td><td>{row.latest_activity_at?.replace('T',' ').replace('+00:00','Z') || '—'}</td></tr>)}
        </tbody></table></div>
      )}
      {page && <div className="pagination"><span className="pagination-summary">{page.total ? `Page ${currentPage} of ${totalPages} · ${page.total} reviews` : 'No matching reviews'}</span><div className="pagination-actions"><button type="button" disabled={page.offset === 0} onClick={() => setFilters((c) => ({ ...c, offset: Math.max(0, c.offset - c.limit) }))}>Previous</button><button type="button" disabled={currentPage >= totalPages || page.offset >= 100000} onClick={() => setFilters((c) => ({ ...c, offset: c.offset + c.limit }))}>Next</button></div></div>}
      {summary && <p className="review-operations-activity">Recent Review Activity: {summary.recent_activity.length ? summary.recent_activity.slice(0, 5).map((item) => `${item.incident_key} · ${item.event_type.replaceAll('_',' ')} · ${item.created_at.replace('T',' ')}`).join('  |  ') : 'No review activity recorded.'}</p>}
    </section>
  )
}

export default IncidentReviewOperations
