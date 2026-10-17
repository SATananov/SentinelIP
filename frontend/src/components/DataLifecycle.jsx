import { useEffect, useRef, useState } from 'react'
import { loadDataLifecyclePreview } from '../services/dataLifecycleApi.js'
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
  const requestGuard = useRef(createDataLifecycleRequestGuard())

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

  const state = dataLifecyclePreviewState({ loading, error, preview })

  return (
    <section className="panel data-lifecycle" aria-labelledby="data-lifecycle-title">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Local operator</p>
          <h2 id="data-lifecycle-title">Data Lifecycle</h2>
          <p className="data-lifecycle-description">Preview only — no data is deleted.</p>
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
                  <th scope="col">Invalid retention</th>
                  <th scope="col">Oldest eligible deadline</th>
                </tr>
              </thead>
              <tbody>
                {preview.items.map((item) => (
                  <tr key={item.data_class}>
                    <th scope="row">{dataLifecycleClassLabel(item.data_class)}</th>
                    <td>{dataLifecyclePolicyLabel(item.policy_state)}</td>
                    <td>{item.total_rows}</td>
                    <td>{item.expired_rows}</td>
                    <td>{item.eligible_rows}</td>
                    <td>{item.protected_by_review + item.protected_by_dependency}</td>
                    <td>{item.policy_undefined}</td>
                    <td>{item.invalid_retention_rows}</td>
                    <td>{safeLifecycleTimestamp(item.oldest_eligible_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="data-lifecycle-note">
            Eligible rows currently qualify under an approved policy; this preview does not delete data.
          </p>
        </>
      )}
    </section>
  )
}

export default DataLifecycle
