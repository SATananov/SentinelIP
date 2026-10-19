import { useEffect, useRef, useState } from 'react'
import {
  createIncidentReviewSearchRequestController,
  dateInputToSearchTimestamp,
  INCIDENT_REVIEW_SEARCH_LIMIT,
  nextIncidentReviewSearchOffset,
  loadIncidentReviewSearch,
  previousIncidentReviewSearchOffset,
  selectIncidentReviewSearchResult,
} from '../services/incidentReviewSearchApi.js'

const INITIAL_FILTERS = {
  title: '', created_from: '', created_until: '', state: '', priority: '', disposition: '',
  site_id: '', scope_id: '', device_id: '',
}

function displayTime(value) {
  return value ? value.replace('T', ' ').replace('+00:00', 'Z') : '—'
}

function prepareFilters(filters, offset = 0) {
  const { created_from, created_until, ...rest } = filters
  if (created_from && created_until && created_from > created_until) {
    throw new Error('Start date must be on or before end date.')
  }
  return {
    ...rest,
    created_from: dateInputToSearchTimestamp(created_from),
    created_until: dateInputToSearchTimestamp(created_until, { exclusiveEnd: true }),
    limit: INCIDENT_REVIEW_SEARCH_LIMIT,
    offset,
  }
}

function IncidentReviewSearch({ onSelectReview }) {
  const [filters, setFilters] = useState(INITIAL_FILTERS)
  const [results, setResults] = useState(null)
  const [submittedFilters, setSubmittedFilters] = useState(null)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const requestController = useRef(createIncidentReviewSearchRequestController())

  useEffect(() => () => requestController.current.abort(), [])

  function changeFilter(key, value) {
    requestController.current.abort()
    setLoading(false)
    setError(null)
    setFilters((current) => ({ ...current, [key]: value }))
    setOffset(0)
  }

  async function runSearch(nextOffset, sourceFilters = filters) {
    requestController.current.abort()
    setLoading(false)
    setError(null)
    let query
    try {
      query = prepareFilters(sourceFilters, nextOffset)
    } catch (err) {
      setError(err.message)
      return
    }
    const request = requestController.current.start()
    setLoading(true)
    try {
      const response = await loadIncidentReviewSearch(query, request.signal)
      if (!request.isCurrent()) return
      setResults(response)
      setSubmittedFilters(sourceFilters)
      setOffset(nextOffset)
    } catch (err) {
      if (request.isCurrent() && err.name !== 'AbortError') setError(err.message)
    } finally {
      if (request.isCurrent()) setLoading(false)
    }
  }

  function reset() {
    requestController.current.abort()
    setFilters(INITIAL_FILTERS)
    setResults(null)
    setSubmittedFilters(null)
    setOffset(0)
    setLoading(false)
    setError(null)
  }

  const criteriaChanged = submittedFilters !== null
    && Object.keys(INITIAL_FILTERS).some((key) => filters[key] !== submittedFilters[key])

  return (
    <section className="incident-review-search" aria-labelledby="incident-review-search-title">
      <div className="incident-review-search-heading">
        <div>
          <h4 id="incident-review-search-title">Find review</h4>
          <p className="security-layer-copy">Search review titles by word or word beginning. Filters combine to narrow results; date ranges use your local calendar.</p>
        </div>
      </div>
      <form className="incident-review-search-form" onSubmit={(event) => {
        event.preventDefault()
        void runSearch(0)
      }}>
        <label className="incident-review-search-title-field">Title
          <input aria-label="Review title search" type="search" maxLength={160}
            value={filters.title} onChange={(event) => changeFilter('title', event.target.value)}
            placeholder="Enter remembered title words" required />
        </label>
        <label>Created from
          <input aria-label="Created from date" type="date" value={filters.created_from}
            onChange={(event) => changeFilter('created_from', event.target.value)} />
        </label>
        <label>Created through (inclusive)
          <input aria-label="Created through date" type="date" value={filters.created_until}
            onChange={(event) => changeFilter('created_until', event.target.value)} />
        </label>
        <label>State
          <select value={filters.state} onChange={(event) => changeFilter('state', event.target.value)}>
            <option value="">Any state</option>
            {['OPEN', 'IN_REVIEW', 'CLOSED'].map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}
          </select>
        </label>
        <label>Priority
          <select value={filters.priority} onChange={(event) => changeFilter('priority', event.target.value)}>
            <option value="">Any priority</option>
            {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>
        <label>Disposition
          <select value={filters.disposition} onChange={(event) => changeFilter('disposition', event.target.value)}>
            <option value="">Any disposition</option>
            {['UNREVIEWED', 'EXPECTED_ACTIVITY', 'BENIGN', 'NEEDS_MONITORING', 'ACTION_REQUIRED', 'FALSE_POSITIVE', 'INCONCLUSIVE']
              .map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}
          </select>
        </label>
        {['site_id', 'scope_id', 'device_id'].map((key) => (
          <label key={key}>{key.replace('_id', ' ID').replace(/^./, (letter) => letter.toUpperCase())}
            <input aria-label={key.replace('_id', ' ID')} type="number" min="1" step="1"
              value={filters[key]} onChange={(event) => changeFilter(key, event.target.value)} />
          </label>
        ))}
        <div className="incident-review-search-actions">
          <button className="security-detail-close" type="submit" disabled={loading}>Search</button>
          <button className="security-detail-close" type="button" onClick={reset}>Reset</button>
        </div>
      </form>
      {error && <p className="security-detail-error" role="alert">{error}</p>}
      {loading && <p className="security-layer-copy" role="status">Searching review titles…</p>}
      {!results && !loading && !error && <p className="security-empty">Enter title words to find an existing review.</p>}
      {results && criteriaChanged && <p className="security-layer-copy" role="status">Filters changed. Search again to update these results.</p>}
      {results && !criteriaChanged && results.items.length === 0 && !loading && (
        <p className="security-empty">No reviews matched these search criteria.</p>
      )}
      {results?.items?.length > 0 && (
        <>
          <ul className="incident-review-search-results" aria-label="Review search results">
            {results.items.map((item) => (
              <li key={item.id}>
                <button type="button" className="incident-review-search-result"
                  onClick={() => selectIncidentReviewSearchResult(item.id, onSelectReview)}>
                  <strong>{item.title}</strong>
                  <span>#{item.id} · {item.incident_key} · {item.state.replaceAll('_', ' ')} · {item.priority} · {item.disposition.replaceAll('_', ' ')}</span>
                  <small>Created {displayTime(item.created_at)} · Updated {displayTime(item.updated_at)}{item.closed_at ? ` · Closed ${displayTime(item.closed_at)}` : ''}</small>
                  {(item.site_id || item.scope_id || item.device_id) && <small>
                    {item.site_id ? `Site ${item.site_id}` : ''}{item.scope_id ? ` · Scope ${item.scope_id}` : ''}{item.device_id ? ` · Device ${item.device_id}` : ''}
                  </small>}
                </button>
              </li>
            ))}
          </ul>
          <div className="incident-review-search-pagination" aria-label="Review search pagination">
            <button className="security-detail-close" type="button" disabled={loading || offset === 0 || criteriaChanged}
              onClick={() => void runSearch(previousIncidentReviewSearchOffset(offset), submittedFilters ?? filters)}>Previous</button>
            <span>Showing {offset + 1}–{offset + results.items.length}</span>
            <button className="security-detail-close" type="button" disabled={loading || !results.has_more || criteriaChanged || offset >= 100000}
              onClick={() => void runSearch(nextIncidentReviewSearchOffset(offset, results.has_more), submittedFilters ?? filters)}>Next</button>
          </div>
        </>
      )}
    </section>
  )
}

export default IncidentReviewSearch
