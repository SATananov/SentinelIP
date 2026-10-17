import { useEffect, useRef, useState } from 'react'
import {
  INVESTIGATION_EVIDENCE_TYPES,
  INVESTIGATION_QUERY_TYPES,
  lookupInvestigation,
  validateInvestigationLookup,
} from '../services/investigationApi.js'
import { INVESTIGATION_DESTINATION_KINDS } from '../services/investigationNavigation.js'
import { createInvestigationRequestGuard, investigationResultLabel } from '../services/investigationLookupState.js'

function displayTime(value) {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date.toLocaleString()
}

function ResultCard({ item, onOpen, query }) {
  const label = investigationResultLabel(item.entity_type)
  const canOpen = INVESTIGATION_DESTINATION_KINDS.has(item.destination_kind) &&
    typeof item.destination_id === 'string' && item.destination_id.length > 0
  const time = displayTime(item.occurred_at)
  return (
    <article className="investigation-result">
      <div className="investigation-result-main">
        <span className="investigation-entity-type">{label}</span>
        <strong>{item.label}</strong>
        {item.context_label && <span>{item.context_label}</span>}
        <div className="investigation-context">
          {(item.site_name || item.site_id !== null && item.site_id !== undefined) && <span>Site: {item.site_name ?? item.site_id}</span>}
          {(item.scope_name || item.scope_id !== null && item.scope_id !== undefined) && <span>Scope: {item.scope_name ?? item.scope_id}</span>}
          {item.device_id !== null && item.device_id !== undefined && <span>Device: {item.device_id}</span>}
          {item.sensor_id !== null && item.sensor_id !== undefined && <span>Sensor: {item.sensor_id}</span>}
          {time && <time dateTime={item.occurred_at}>{time}</time>}
        </div>
      </div>
      <div className="investigation-result-action">
        {canOpen
          ? <button type="button" onClick={() => onOpen?.(item, query)}>Open</button>
          : <span className="investigation-unavailable">Detail navigation unavailable</span>}
      </div>
    </article>
  )
}

function InvestigationLookup({ onOpenResult }) {
  const [queryType, setQueryType] = useState('IP_ADDRESS')
  const [value, setValue] = useState('')
  const [evidenceType, setEvidenceType] = useState(INVESTIGATION_EVIDENCE_TYPES[0])
  const [evidenceId, setEvidenceId] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const requestGuard = useRef(createInvestigationRequestGuard())

  function invalidate() {
    requestGuard.current.invalidate()
    setLoading(false)
  }

  useEffect(() => () => {
    requestGuard.current.invalidate()
  }, [])

  function changeType(nextType) {
    invalidate()
    setQueryType(nextType)
    setValue('')
    setEvidenceType(INVESTIGATION_EVIDENCE_TYPES[0])
    setEvidenceId('')
    setResult(null)
    setError('')
  }

  async function submit(event) {
    event.preventDefault()
    const query = { queryType, value, evidenceType, evidenceId }
    const validation = validateInvestigationLookup(query)
    if (validation) {
      invalidate()
      setResult(null)
      setError(validation)
      return
    }
    const request = requestGuard.current.begin()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await lookupInvestigation(query, request.controller.signal)
      if (requestGuard.current.isCurrent(request)) {
        setResult(data)
      }
    } catch (requestError) {
      if (requestGuard.current.isCurrent(request) && requestError.name !== 'AbortError') {
        setError(requestError.message || 'Investigation lookup is unavailable.')
      }
    } finally {
      if (requestGuard.current.isCurrent(request)) setLoading(false)
    }
  }

  const isEvidence = queryType === 'EVIDENCE_REFERENCE'
  const currentQuery = isEvidence
    ? { queryType, evidenceType, evidenceId }
    : { queryType, value }

  return (
    <section className="panel investigation-lookup" aria-labelledby="investigation-lookup-title">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Cross-domain investigation</p>
          <h2 id="investigation-lookup-title">Investigation Search</h2>
          <p className="security-layer-copy">Choose an exact identifier type to find bounded, typed records.</p>
        </div>
        <span className="read-only-chip">Read only</span>
      </div>

      <form className={isEvidence ? 'investigation-lookup-form investigation-evidence-form' : 'investigation-lookup-form'} onSubmit={submit}>
        <label>
          <span>Lookup type</span>
          <select value={queryType} onChange={(event) => changeType(event.target.value)}>
            {INVESTIGATION_QUERY_TYPES.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}
          </select>
        </label>
        {isEvidence ? (
          <>
            <label>
              <span>Evidence type</span>
              <select value={evidenceType} onChange={(event) => { invalidate(); setEvidenceType(event.target.value); setResult(null); setError('') }}>
                {INVESTIGATION_EVIDENCE_TYPES.map((type) => <option key={type} value={type}>{type.replaceAll('_', ' ')}</option>)}
              </select>
            </label>
            <label>
              <span>Evidence ID</span>
              <input inputMode="numeric" autoComplete="off" value={evidenceId} onChange={(event) => { invalidate(); setEvidenceId(event.target.value); setResult(null); setError('') }} />
            </label>
          </>
        ) : (
          <label className="investigation-value-field">
            <span>{INVESTIGATION_QUERY_TYPES.find((type) => type.value === queryType)?.label} value</span>
            <input autoComplete="off" spellCheck="false" value={value} onChange={(event) => { invalidate(); setValue(event.target.value); setResult(null); setError('') }} />
          </label>
        )}
        <button type="submit" disabled={loading}>{loading ? 'Looking up…' : 'Look up'}</button>
      </form>

      {error && <p className="investigation-error" role="alert">{error}</p>}
      {loading && <p className="security-empty" role="status">Searching the selected identifier type…</p>}
      {result && result.items.length === 0 && <p className="security-empty" role="status">No matching record found.</p>}
      {result?.truncated && <p className="investigation-truncated" role="status">More matching records exist. Showing the bounded investigation result set.</p>}
      {result?.items?.length > 0 && (
        <div className="investigation-results" aria-label="Investigation lookup results">
          {result.items.map((item) => (
            <ResultCard key={`${item.entity_type}:${item.entity_id}`} item={item} onOpen={onOpenResult} query={currentQuery} />
          ))}
        </div>
      )}
    </section>
  )
}

export default InvestigationLookup
