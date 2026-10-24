import { useEffect, useRef, useState } from 'react'
import { cleanupDataLifecycle, loadDataLifecyclePreview } from '../services/dataLifecycleApi.js'
import {
  createDataLifecycleRequestGuard,
  dataLifecycleClassLabel,
  dataLifecyclePolicyLabel,
  dataLifecyclePreviewState,
  safeLifecycleTimestamp,
} from '../services/dataLifecycleState.js'

function DataLifecycle() {
  const [preview, setPreview] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [cleanupInFlight, setCleanupInFlight] = useState(false)
  const [cleanupResult, setCleanupResult] = useState(null)
  const requestGuard = useRef(createDataLifecycleRequestGuard())
  const cleanupLock = useRef(false)

  useEffect(() => () => requestGuard.current.invalidate(), [])

  async function refresh() {
    const request = requestGuard.current.begin()
    setLoading(true)
    setError('')
    setPreview(null)
    try {
      const result = await loadDataLifecyclePreview(request.controller.signal)
      if (requestGuard.current.isCurrent(request)) setPreview(result)
    } catch (requestError) {
      if (requestGuard.current.isCurrent(request) && requestError.name !== 'AbortError') {
        setError(requestError.message || 'Data lifecycle preview is unavailable.')
      }
    } finally {
      if (requestGuard.current.isCurrent(request)) setLoading(false)
    }
  }

  async function cleanup(dataClass) {
    const item = preview?.items?.find((entry) => entry.data_class === dataClass)
    if (!item || item.eligible_rows <= 0 || loading || cleanupLock.current) return
    const dns = dataClass === 'DNS_OBSERVATIONS'
    const legacyEvents = dataClass === 'LEGACY_EVENTS'
    const perimeterEvidence = dataClass === 'PERIMETER_EVIDENCE'
    if (perimeterEvidence && item.cleanup_blocked) return
    const prompt = legacyEvents
      ? 'Delete up to 100 unreferenced legacy SSH events at or before the displayed 90-day cutoff? This permanently deletes raw event message and severity. Threat-referenced, malformed, and future rows are preserved. Maintain a tested database backup before cleanup; restore replaces the database with its backup state. The database file may not shrink after deletion.'
      : dns
      ? 'Delete up to 100 expired DNS observations currently eligible under the retention policy? This permanently removes only observation rows. The server revalidates eligibility.'
      : perimeterEvidence
      ? `Delete up to 25 unreferenced perimeter evidence components whose event roots have all been received at least 180 days ago? This deletes each selected component atomically. Incident-linked and ambiguous evidence is preserved. The largest eligible component has ${item.largest_eligible_component_total_rows} rows (${item.largest_eligible_component_events} events and ${item.largest_eligible_component_derived_rows} derived rows); large components may hold the database write lock longer. A recent verified backup is strongly recommended. SQLite may not shrink the database file after deletion.`
      : 'Delete up to 100 expired web observations whose dependent detection snapshots are safe to preserve? Detections and Incident Review evidence remain preserved. The server revalidates eligibility.'
    if (!window.confirm(prompt)) return
    cleanupLock.current = true
    const request = requestGuard.current.begin()
    setCleanupInFlight(true)
    setError('')
    setCleanupResult(null)
    try {
      const result = await cleanupDataLifecycle(dataClass, request.controller.signal)
      if (requestGuard.current.isCurrent(request)) {
        setCleanupResult(result)
        setCleanupInFlight(false)
        await refresh()
      }
    } catch (requestError) {
      if (requestGuard.current.isCurrent(request) && requestError.name !== 'AbortError') {
        setError(requestError.message || 'Data lifecycle cleanup is unavailable.')
      }
    } finally {
      cleanupLock.current = false
      setCleanupInFlight(false)
    }
  }

  const state = dataLifecyclePreviewState({ loading, error, preview })

  return (
    <section className="panel data-lifecycle" aria-labelledby="data-lifecycle-title">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Local operator</p>
          <h2 id="data-lifecycle-title">Data Lifecycle</h2>
          <p className="data-lifecycle-description">Cleanup is manual. Flat-row cleanup deletes at most 100 rows; perimeter cleanup deletes at most 25 complete components.</p>
        </div>
        <button type="button" className="refresh-button" onClick={refresh} disabled={loading}>
          {loading ? 'Loading…' : preview ? 'Refresh preview' : 'Load preview'}
        </button>
      </div>

      {error && <div className="error-box" role="alert">{error}</div>}
      {state === 'idle' && <p className="empty-state">Load a counts-only preview of current retention policy status.</p>}
      {state === 'loading' && <p className="empty-state" role="status">Loading lifecycle preview…</p>}
      {state === 'empty' && <p className="empty-state">No lifecycle classes are available.</p>}
      {preview && state !== 'loading' && (
        <>
          <p className="data-lifecycle-evaluated">
            Evaluated: <time dateTime={preview.evaluated_at}>{safeLifecycleTimestamp(preview.evaluated_at)}</time>
          </p>
          <div className="data-lifecycle-table-wrap">
            <table className="data-lifecycle-table">
              <thead>
                <tr>
                  <th scope="col">Data class</th>
                  <th scope="col">Policy</th>
                  <th scope="col">Total</th>
                  <th scope="col">Expired</th>
                  <th scope="col">Eligible</th>
                  <th scope="col">Protected</th>
                  <th scope="col">Policy undefined</th>
                  <th scope="col">Malformed / invalid</th>
                  <th scope="col">Future skipped</th>
                  <th scope="col">Oldest eligible time</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {preview.items.map((item) => (
                  <tr key={item.data_class}>
                    <th scope="row">{dataLifecycleClassLabel(item.data_class)}</th>
                    <td>{item.retention_days ? `${item.retention_days} days` : dataLifecyclePolicyLabel(item.policy_state)}</td>
                    <td>{item.total_rows}</td>
                    <td>{item.expired_rows}</td>
                    <td>{item.data_class === 'PERIMETER_EVIDENCE'
                      ? `${item.eligible_components} components / ${item.eligible_rows} rows`
                      : item.eligible_rows}</td>
                    <td>{item.protected_by_review + item.protected_by_dependency}</td>
                    <td>{item.policy_undefined}</td>
                    <td>{item.malformed_skipped_rows ?? item.invalid_retention_rows}</td>
                    <td>{item.future_skipped_rows ?? 0}</td>
                    <td>{safeLifecycleTimestamp(item.oldest_eligible_at)}</td>
                    <td>{['DNS_OBSERVATIONS', 'WEB_OBSERVATIONS', 'LEGACY_EVENTS', 'PERIMETER_EVIDENCE'].includes(item.data_class) && (
                      <button type="button" className="refresh-button" onClick={() => cleanup(item.data_class)}
                        disabled={loading || cleanupInFlight || item.eligible_rows <= 0 || item.cleanup_blocked}>
                        {cleanupInFlight ? 'Deleting…' : item.data_class === 'PERIMETER_EVIDENCE'
                          ? 'Delete up to 25 components' : 'Delete up to 100'}
                      </button>
                    )}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="data-lifecycle-note">
            Eligible items qualify under the displayed policy. Preview does not authorize deletion; every apply rechecks current eligibility. Flat-row cleanup applies delete at most 100 rows; perimeter cleanup applies delete at most 25 complete components.
          </p>
          {preview.items.find((item) => item.data_class === 'PERIMETER_EVIDENCE') && (() => {
            const item = preview.items.find((entry) => entry.data_class === 'PERIMETER_EVIDENCE')
            return <div className="data-lifecycle-note">
              <p>Perimeter evidence retention: 180 days from server receipt. Unreferenced perimeter evidence components are eligible only after all component events have been retained for at least 180 days. Incident-linked and ambiguous evidence is preserved.</p>
              <p>Eligible components: {item.eligible_components}; eligible rows: {item.eligible_events} events, {item.eligible_detections} detections, {item.eligible_policy_correlations} policy correlations, and {item.eligible_host_correlations} host correlations.</p>
              <p>Largest eligible component: {item.largest_eligible_component_total_rows} rows ({item.largest_eligible_component_events} events, {item.largest_eligible_component_derived_rows} derived). Largest protected component: {item.largest_protected_component_total_rows} rows. Apply deletes whole components, up to 25 per action; a large component may hold the database write lock longer. A recent verified backup is strongly recommended. SQLite may not shrink the database file after deletion.</p>
              {item.cleanup_blocked && <p role="alert">Cleanup blocked: {item.cleanup_block_reason || 'Perimeter evidence relationships need operator review.'}</p>}
            </div>
          })()}
          <p className="data-lifecycle-note">
            Legacy events are retained for 90 days. Only valid, unreferenced events at or before the cutoff are eligible; threat-referenced, malformed, and future events are preserved. Deletion removes raw event message and severity. Maintain a tested database backup before cleanup. Deleted rows free pages for SQLite reuse, but the database file may not shrink immediately.
          </p>
          {preview.items.find((item) => item.data_class === 'LEGACY_EVENTS') && (
            <p className="data-lifecycle-evaluated">
              Legacy event clock: server-local wall time. Evaluated: <time dateTime={preview.items.find((item) => item.data_class === 'LEGACY_EVENTS').evaluated_at_local}>{safeLifecycleTimestamp(preview.items.find((item) => item.data_class === 'LEGACY_EVENTS').evaluated_at_local)}</time>. Cutoff: <time dateTime={preview.items.find((item) => item.data_class === 'LEGACY_EVENTS').cutoff_at_local}>{safeLifecycleTimestamp(preview.items.find((item) => item.data_class === 'LEGACY_EVENTS').cutoff_at_local)}</time>. Oldest valid retained event: {safeLifecycleTimestamp(preview.items.find((item) => item.data_class === 'LEGACY_EVENTS').oldest_retained_at)}.
            </p>
          )}
        </>
      )}
      {cleanupResult && <div className="data-lifecycle-note" role="status">
        {cleanupResult.data_class === 'PERIMETER_EVIDENCE'
          ? cleanupResult.cleanup_blocked
            ? cleanupResult.cleanup_block_reason
            : `Deleted ${cleanupResult.components_deleted} components: ${cleanupResult.events_deleted} events, ${cleanupResult.detections_deleted} detections, ${cleanupResult.policy_correlations_deleted} policy correlations, and ${cleanupResult.host_correlations_deleted} host correlations. Largest selected component: ${cleanupResult.largest_selected_component_total_rows} rows.`
          : `Cleanup deleted ${cleanupResult.deleted_count}; ${cleanupResult.protected_count} protected; ${cleanupResult.malformed_skipped_rows ?? 0} malformed; ${cleanupResult.future_skipped_rows ?? 0} future rows skipped; ${cleanupResult.remaining_eligible} eligible rows remain. Evaluated ${safeLifecycleTimestamp(cleanupResult.evaluated_at_local ?? cleanupResult.evaluated_at)} (batch limit ${cleanupResult.batch_limit}).`}
      </div>}
    </section>
  )
}

export default DataLifecycle
