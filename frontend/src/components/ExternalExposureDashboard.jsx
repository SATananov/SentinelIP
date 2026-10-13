import { useEffect, useMemo, useState } from 'react'

import { loadExternalExposureDashboard } from '../services/externalExposureApi.js'

function label(value) {
  return value ? value.replaceAll('_', ' ') : '—'
}

function observed(value) {
  if (!value) return '—'
  return value.replace('T', ' ').replace('+00:00', ' UTC')
}

function ExternalExposureDashboard({ refreshSignal }) {
  const [data, setData] = useState(null)
  const [scopeId, setScopeId] = useState('')
  const [timeRange, setTimeRange] = useState('7d')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const filters = useMemo(() => ({ scopeId, timeRange }), [scopeId, timeRange])

  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      setLoading(true)
      setError(null)
      try {
        setData(await loadExternalExposureDashboard(filters, controller.signal))
      } catch (err) {
        if (err.name !== 'AbortError') setError(err.message)
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    load()
    return () => controller.abort()
  }, [filters, refreshSignal])

  const summary = data?.summary || {}
  const scopes = data?.options?.scopes || []

  return (
    <section className="panel exposure-dashboard-panel">
      <div className="panel-heading exposure-dashboard-heading">
        <div>
          <p className="panel-kicker">External Attack Surface</p>
          <h2>External Exposure Review</h2>
          <p className="exposure-dashboard-note">
            Authorized public exposure evidence, expected-configuration review, service classification, and observed change history. These labels do not claim vulnerability, exploitation, or compromise.
          </p>
        </div>
        <span className="panel-count">{loading ? '…' : summary.total_exposures || 0}</span>
      </div>

      <div className="external-filters">
        <label>
          <span>Authorized scope</span>
          <select value={scopeId} onChange={(event) => setScopeId(event.target.value)}>
            <option value="">All public scopes</option>
            {scopes.map((scope) => (
              <option key={scope.id} value={scope.id}>
                {scope.name || scope.canonical_target} · {scope.scope_type}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Change window</span>
          <select value={timeRange} onChange={(event) => setTimeRange(event.target.value)}>
            <option value="24h">24 hours</option>
            <option value="72h">72 hours</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
            <option value="all">All changes</option>
          </select>
        </label>
      </div>

      {error && <div className="error-box">{error}</div>}

      <div className="exposure-summary-grid">
        <article><span>Total Exposures</span><strong>{summary.total_exposures || 0}</strong></article>
        <article><span>Present</span><strong>{summary.present || 0}</strong></article>
        <article><span>Absent</span><strong>{summary.absent || 0}</strong></article>
        <article><span>Public Targets</span><strong>{summary.public_targets || 0}</strong></article>
        <article><span>Expected</span><strong>{summary.expected || 0}</strong></article>
        <article><span>Unexpected</span><strong>{summary.unexpected || 0}</strong></article>
        <article><span>Review</span><strong>{summary.review || 0}</strong></article>
        <article><span>Recent Changes</span><strong>{summary.recent_changes || 0}</strong></article>
      </div>

      <div className="exposure-dashboard-grid">
        <article className="external-subpanel">
          <h3>Service roles</h3>
          <div className="external-list">
            {data?.service_roles?.length ? data.service_roles.map((item) => (
              <div className="external-list-row" key={item.label}>
                <span>{label(item.label)}</span><strong>{item.total}</strong>
              </div>
            )) : <p className="empty-state">No classified exposure roles.</p>}
          </div>
        </article>

        <article className="external-subpanel">
          <h3>Exposure profiles</h3>
          <div className="external-list">
            {data?.exposure_profiles?.length ? data.exposure_profiles.map((item) => (
              <div className="external-list-row" key={item.label}>
                <span>{label(item.label)}</span><strong>{item.total}</strong>
              </div>
            )) : <p className="empty-state">No exposure profiles.</p>}
          </div>
        </article>

        <article className="external-subpanel">
          <h3>Observed changes</h3>
          <div className="external-list">
            {data?.change_counts?.length ? data.change_counts.map((item) => (
              <div className="external-list-row" key={item.label}>
                <span>{label(item.label)}</span><strong>{item.total}</strong>
              </div>
            )) : <p className="empty-state">No changes in this window.</p>}
          </div>
        </article>

        <article className="external-subpanel">
          <h3>Top exposed ports</h3>
          <div className="external-list">
            {data?.top_ports?.length ? data.top_ports.map((item) => (
              <div className="external-list-row" key={`${item.transport}-${item.port_number}`}>
                <span className="mono">{item.transport.toUpperCase()} {item.port_number}</span>
                <strong>{item.total}</strong>
                <small>{item.present} currently present</small>
              </div>
            )) : <p className="empty-state">No exposed-port evidence.</p>}
          </div>
        </article>

        <article className="external-subpanel exposure-wide">
          <h3>Top public targets</h3>
          <div className="external-list">
            {data?.top_targets?.length ? data.top_targets.map((item) => (
              <div className="external-list-row exposure-target-row" key={item.target_ip}>
                <span className="mono">{item.target_ip}</span>
                <strong>{item.total} exposures</strong>
                <small>{item.present} present · {item.unexpected} unexpected</small>
              </div>
            )) : <p className="empty-state">No public target evidence.</p>}
          </div>
        </article>

        <article className="external-subpanel exposure-wide">
          <h3>Recent exposure changes</h3>
          <div className="exposure-table-wrap">
            <table className="exposure-table">
              <thead><tr><th>Time</th><th>Target</th><th>Change</th><th>Assessment</th><th>Role</th><th>Presence</th></tr></thead>
              <tbody>
                {data?.recent_changes?.map((item) => (
                  <tr key={item.id}>
                    <td>{observed(item.observed_at)}</td>
                    <td className="mono">{item.target_ip}:{item.port_number}</td>
                    <td>{label(item.change_type)}</td>
                    <td>{item.classification || 'REVIEW'}</td>
                    <td>{label(item.service_role)}</td>
                    <td>{item.presence_state || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data?.recent_changes?.length && <p className="empty-state">No recent external exposure changes.</p>}
          </div>
        </article>

        <article className="external-subpanel exposure-wide">
          <h3>Current exposure inventory</h3>
          <div className="exposure-table-wrap">
            <table className="exposure-table">
              <thead><tr><th>Last seen</th><th>Target</th><th>Service</th><th>Assessment</th><th>Profile</th><th>Presence</th></tr></thead>
              <tbody>
                {data?.recent_exposures?.map((item) => (
                  <tr key={item.id}>
                    <td>{observed(item.last_seen)}</td>
                    <td className="mono">{item.target_ip}:{item.port_number}</td>
                    <td>{item.service_name || 'Unknown'}<small>{item.product || item.version ? `${item.product || ''} ${item.version || ''}`.trim() : ''}</small></td>
                    <td>{item.classification || 'REVIEW'}</td>
                    <td>{label(item.exposure_profile)}</td>
                    <td>{item.presence_state || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data?.recent_exposures?.length && <p className="empty-state">No authorized public exposures recorded.</p>}
          </div>
        </article>
      </div>
    </section>
  )
}

export default ExternalExposureDashboard
