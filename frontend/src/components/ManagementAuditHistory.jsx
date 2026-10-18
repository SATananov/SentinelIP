import { useEffect, useMemo, useRef, useState } from 'react'
import { buildManagementAuditQuery, loadManagementAuditEvents } from '../services/managementAuditApi.js'
import {
  createManagementAuditRequestGuard,
  formatManagementAuditTimestamp,
  managementAuditActorLabel,
  managementAuditDetails,
  managementAuditEntityLabel,
  managementAuditEventLabel,
  managementAuditPage,
  managementAuditViewState,
  MANAGEMENT_AUDIT_ENTITY_TYPES,
  MANAGEMENT_AUDIT_EVENT_TYPES,
  updateManagementAuditFilters,
} from '../services/managementAuditState.js'

function DetailValue({ label, value }) {
  if (value === null || value === undefined || value === '') return null
  return <div><dt>{label}</dt><dd>{value}</dd></div>
}

function AuditEventDetails({ event }) {
  return (
    <dl className="management-audit-details">
      {managementAuditDetails(event).map(({ label, value }) => <DetailValue key={label} label={label} value={value} />)}
    </dl>
  )
}

function ManagementAuditHistory() {
  const [filters, setFilters] = useState({ event_type: '', entity_type: '', entity_id: '', site_id: '', limit: 50, offset: 0 })
  const [retry, setRetry] = useState(0)
  const [request, setRequest] = useState({ key: null, loading: true, error: null, result: null })
  const guard = useRef(createManagementAuditRequestGuard())
  const activeController = useRef(null)
  const key = useMemo(() => JSON.stringify(filters), [filters])
  const filterError = useMemo(() => {
    try { buildManagementAuditQuery(filters); return null } catch (error) { return error.message }
  }, [filters])

  useEffect(() => {
    const requestGuard = guard.current
    const generation = requestGuard.begin()
    const controller = new AbortController()
    activeController.current = controller
    if (!filterError) {
      loadManagementAuditEvents(filters, controller.signal)
        .then((result) => {
          if (!controller.signal.aborted && requestGuard.isCurrent(generation)) {
            setRequest({ key, loading: false, error: null, result })
          }
        })
        .catch((error) => {
          if (!controller.signal.aborted && requestGuard.isCurrent(generation) && error?.name !== 'AbortError') {
            setRequest({ key, loading: false, error: error?.message || 'Management history could not be loaded.', result: null })
          }
        })
    }
    return () => {
      controller.abort()
      if (activeController.current === controller) activeController.current = null
      requestGuard.invalidate()
    }
  }, [filters, filterError, key, retry])

  const current = filterError
    ? { loading: false, error: filterError, result: null }
    : request.key === key ? request : { loading: true, error: null, result: null }
  const viewState = managementAuditViewState(current)

  function updateFilter(field, value) {
    activeController.current?.abort()
    guard.current.invalidate()
    setFilters((state) => updateManagementAuditFilters(state, field, value))
  }

  function refresh() {
    activeController.current?.abort()
    guard.current.invalidate()
    setRequest((currentRequest) => ({ ...currentRequest, key, loading: true, error: null }))
    setRetry((value) => value + 1)
  }

  function changePage(direction, hasMore) {
    activeController.current?.abort()
    guard.current.invalidate()
    setFilters((state) => managementAuditPage(state, direction, hasMore))
  }

  return (
    <section className="management-audit-history" aria-labelledby="management-audit-history-title">
      <div className="management-audit-heading">
        <div>
          <h3 id="management-audit-history-title">Management History</h3>
          <p>Actor identifies the source class, not a specific person.</p>
        </div>
        <button type="button" onClick={refresh}>Refresh history</button>
      </div>

      <div className="management-audit-filters" aria-label="Management history filters">
        <label><span>Event type</span><select value={filters.event_type} onChange={(event) => updateFilter('event_type', event.target.value)}>
          <option value="">All event types</option>
          {MANAGEMENT_AUDIT_EVENT_TYPES.map((type) => <option value={type} key={type}>{managementAuditEventLabel(type)}</option>)}
        </select></label>
        <label><span>Entity type</span><select value={filters.entity_type} onChange={(event) => updateFilter('entity_type', event.target.value)}>
          <option value="">All entity types</option>
          {MANAGEMENT_AUDIT_ENTITY_TYPES.map((type) => <option value={type} key={type}>{managementAuditEntityLabel(type)}</option>)}
        </select></label>
        <label><span>Entity ID</span><input value={filters.entity_id} disabled={!filters.entity_type} maxLength={128}
          onChange={(event) => updateFilter('entity_id', event.target.value)} placeholder={filters.entity_type ? 'Exact ID' : 'Choose entity type'} /></label>
        <label><span>Site ID</span><input type="number" min="1" step="1" value={filters.site_id}
          onChange={(event) => updateFilter('site_id', event.target.value)} placeholder="All sites" /></label>
      </div>

      {viewState === 'loading' && <p role="status" className="management-audit-state">Loading management history…</p>}
      {viewState === 'error' && <p role="alert" className="management-audit-error">{current.error}</p>}
      {viewState === 'empty' && <p className="management-audit-state">No management history matches the current filters.</p>}
      {viewState === 'ready' && <>
        <div className="management-audit-list">
          {current.result.items.slice(0, 50).map((event) => (
            <article className="management-audit-row" key={event.id}>
              <div className="management-audit-row-main">
                <strong>{managementAuditEventLabel(event.event_type)}</strong>
                <span>{managementAuditEntityLabel(event.entity_type)} · ID {event.entity_id || 'Unavailable'}</span>
                <time dateTime={typeof event.occurred_at === 'string' ? event.occurred_at : undefined}>
                  {formatManagementAuditTimestamp(event.occurred_at)}
                </time>
                <span>{managementAuditActorLabel(event.actor_type)}</span>
              </div>
              <details>
                <summary>Details</summary>
                <AuditEventDetails event={event} />
              </details>
            </article>
          ))}
        </div>
        <div className="management-audit-pagination">
          <span>{current.result.returned} events · offset {filters.offset}</span>
          <div>
            <button type="button" disabled={filters.offset === 0 || current.loading}
              onClick={() => changePage('previous', current.result.has_more)}>Previous</button>
            <button type="button" disabled={!current.result.has_more || current.loading}
              onClick={() => changePage('next', current.result.has_more)}>Next</button>
          </div>
        </div>
      </>}
    </section>
  )
}

export default ManagementAuditHistory
