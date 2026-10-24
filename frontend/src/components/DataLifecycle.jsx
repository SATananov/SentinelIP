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
    const prompt = legacyEvents
      ? 'Delete up to 100 unreferenced legacy SSH events at or before the displayed 90-day cutoff? This permanently deletes raw event message and severity. Threat-referenced, malformed, and future rows are preserved. Maintain a tested database backup before cleanup; restore replaces the database with its backup state. The database file may not shrink after deletion.'
      : dns
      ? 'Delete up to 100 expired DNS observations currently eligible under the retention policy? This permanently removes only observation rows. The server revalidates eligibility.'
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
          <p className="data-lifecycle-description">Cleanup is manual. Each confirmed apply deletes at most 100 eligible rows.</p>
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
                    <td>{item.eligible_rows}</td>
                    <td>{item.protected_by_review + item.protected_by_dependency}</td>
                    <td>{item.policy_undefined}</td>
                    <td>{item.malformed_skipped_rows ?? item.invalid_retention_rows}</td>
                    <td>{item.future_skipped_rows ?? 0}</td>
                    <td>{safeLifecycleTimestamp(item.oldest_eligible_at)}</td>
                    <td>{['DNS_OBSERVATIONS', 'WEB_OBSERVATIONS', 'LEGACY_EVENTS'].includes(item.data_class) && (
                      <button type="button" className="refresh-button" onClick={() => cleanup(item.data_class)}
                        disabled={loading || cleanupInFlight || item.eligible_rows <= 0}>
                        {cleanupInFlight ? 'Deleting…' : 'Delete up to 100'}
                      </button>
                    )}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="data-lifecycle-note">
            Eligible rows currently qualify under the displayed policy. A preview does not authorize deletion; each apply rechecks eligibility and deletes no more than 100 rows.
          </p>
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
        Cleanup deleted {cleanupResult.deleted_count}; {cleanupResult.protected_count} protected; {cleanupResult.malformed_skipped_rows ?? 0} malformed; {cleanupResult.future_skipped_rows ?? 0} future rows skipped; {cleanupResult.remaining_eligible} eligible rows remain. Evaluated {safeLifecycleTimestamp(cleanupResult.evaluated_at_local ?? cleanupResult.evaluated_at)} (batch limit {cleanupResult.batch_limit}).
      </div>}
    </section>
  )
}

export default DataLifecycle
