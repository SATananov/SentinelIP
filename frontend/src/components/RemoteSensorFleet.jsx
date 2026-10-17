import { useEffect, useMemo, useRef, useState } from 'react'
import { loadRemoteSensorFleet } from '../services/remoteSensorApi.js'
import RemoteSensorFleetManagement from './RemoteSensorFleetManagement.jsx'
import RemoteSensorTaskOperations from './RemoteSensorTaskOperations.jsx'
import RemoteSensorTaskHistory from './RemoteSensorTaskHistory.jsx'
import {
  createFleetRequestGuard,
  fleetCapabilitiesLabel,
  fleetErrorMessage,
  fleetQueryKey,
  fleetSiteState,
  fleetStatusLabel,
  formatFleetHeartbeatAge,
  formatFleetTimestamp,
  fleetResultViewState,
  PLATFORM_METADATA_LABEL,
  projectFleetDetail,
  toggleFleetSelection,
  updateFleetFilter,
  updateFleetLimit,
  updateFleetPage,
} from '../services/remoteSensorFleetState.js'

const STATUS_OPTIONS = ['REVOKED', 'DISABLED', 'PENDING', 'ONLINE', 'OFFLINE', 'UNKNOWN']

function RemoteSensorFleet() {
  const [filters, setFilters] = useState({ limit: 20, offset: 0, site_id: '', status: '', platform: '', enabled: '' })
  const [data, setData] = useState(null)
  const [request, setRequest] = useState({ key: null, loading: false, error: null })
  const [selectedId, setSelectedId] = useState(null)
  const [historyRefreshGeneration, setHistoryRefreshGeneration] = useState(0)
  const [createdTask, setCreatedTask] = useState(null)
  const [retry, setRetry] = useState(0)
  const requestGuard = useRef(createFleetRequestGuard())
  const queryKey = useMemo(() => fleetQueryKey(filters), [filters])

  useEffect(() => {
    const guard = requestGuard.current
    const generation = guard.begin()
    const controller = new AbortController()
    loadRemoteSensorFleet(filters, controller.signal)
      .then((result) => {
        if (!controller.signal.aborted && guard.isCurrent(generation)) {
          setData({ key: queryKey, result })
          setSelectedId((current) => result.items?.some((item) => item.id === current) ? current : null)
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted && guard.isCurrent(generation) && error.name !== 'AbortError') {
          setRequest({ key: queryKey, loading: false, error: fleetErrorMessage(error) })
        }
      })
      .finally(() => {
        if (!controller.signal.aborted && guard.isCurrent(generation)) {
          setRequest((current) => current.key === queryKey ? { ...current, loading: false } : current)
        }
      })
    return () => {
      controller.abort()
      guard.invalidate()
    }
  }, [filters, queryKey, retry])

  const currentResult = data?.key === queryKey ? data.result : null
  const currentRequest = request.key === queryKey ? request : null
  const loading = currentRequest?.loading ?? !currentResult
  const error = currentRequest?.error ?? null
  const selected = currentResult?.items?.find((item) => item.id === selectedId) ?? null
  const selectedDetail = projectFleetDetail(selected)
  const viewState = fleetResultViewState({ loading, error, result: currentResult })

  function changeFilter(key, value) {
    setFilters((current) => updateFleetFilter(current, key, value))
    setSelectedId(null)
    setCreatedTask(null)
  }

  function changeLimit(value) {
    setFilters((current) => updateFleetLimit(current, Number(value)))
    setSelectedId(null)
    setCreatedTask(null)
  }

  function selectSensor(sensorId) {
    setSelectedId((current) => toggleFleetSelection(current, sensorId))
    setCreatedTask(null)
  }

  function refreshFleet() {
    setRequest({ key: queryKey, loading: true, error: null })
    setRetry((value) => value + 1)
  }

  return (
    <section className="panel remote-sensor-fleet" aria-labelledby="remote-sensor-fleet-title">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Operator workspace</p>
          <h2 id="remote-sensor-fleet-title">Remote Sensor Fleet</h2>
          <p className="security-layer-copy">Sensor connectivity and declared metadata. Platform and capabilities are {PLATFORM_METADATA_LABEL.toLowerCase()}.</p>
        </div>
        <button type="button" onClick={refreshFleet} disabled={loading}>Refresh fleet</button>
      </div>

      <div className="remote-sensor-filters" aria-label="Sensor fleet filters">
        <label><span>Site ID</span><input type="number" min="1" value={filters.site_id} onChange={(event) => changeFilter('site_id', event.target.value)} placeholder="All sites" /></label>
        <label><span>Status</span><select value={filters.status} onChange={(event) => changeFilter('status', event.target.value)}><option value="">All statuses</option>{STATUS_OPTIONS.map((status) => <option key={status} value={status}>{fleetStatusLabel(status)}</option>)}</select></label>
        <label><span>Platform · declared metadata</span><input type="text" maxLength="64" value={filters.platform} onChange={(event) => changeFilter('platform', event.target.value)} placeholder="Any platform" /></label>
        <label><span>Sensor enabled</span><select value={filters.enabled} onChange={(event) => changeFilter('enabled', event.target.value === '' ? '' : event.target.value === 'true')}><option value="">All</option><option value="true">Enabled</option><option value="false">Disabled</option></select></label>
        <label><span>Rows per page</span><select value={filters.limit} onChange={(event) => changeLimit(event.target.value)}><option value="20">20</option><option value="50">50</option><option value="100">100</option></select></label>
      </div>

      {error && <div className="remote-sensor-error" role="alert">{error}</div>}
      {viewState === 'loading' && <p className="security-empty" role="status">Loading sensor fleet…</p>}
      {viewState === 'empty' && <p className="security-empty">No sensors match these filters.</p>}

      {!loading && currentResult?.items?.length > 0 && (
        <>
          <div className="remote-sensor-table-wrap">
            <table className="remote-sensor-table">
              <thead><tr><th>Sensor</th><th>Site</th><th>Platform</th><th>Registered</th><th>Last heartbeat</th><th>Status</th><th>Capabilities</th><th>Assignments</th></tr></thead>
              <tbody>{currentResult.items.map((sensor) => (
                <tr key={sensor.id} className={selectedId === sensor.id ? 'remote-sensor-selected' : ''}>
                  <td><button type="button" className="remote-sensor-select" aria-pressed={selectedId === sensor.id} onClick={() => selectSensor(sensor.id)}><strong>{sensor.name}</strong><small>ID {sensor.id} · {sensor.sensor_uuid}</small></button></td>
                  <td><strong>{sensor.site_name ?? 'Unavailable'}</strong><small>Site {sensor.site_id} · {fleetSiteState(sensor.site_enabled)}</small></td>
                  <td><span>{sensor.platform}</span><small>{PLATFORM_METADATA_LABEL} · {sensor.version}</small></td>
                  <td>{formatFleetTimestamp(sensor.registered_at)}</td>
                  <td>{sensor.last_seen_at ? <>{formatFleetTimestamp(sensor.last_seen_at)}<small>{formatFleetHeartbeatAge(sensor.heartbeat_age_seconds)}</small></> : 'Never'}</td>
                  <td><span className={`remote-sensor-status remote-sensor-status-${String(sensor.status).toLowerCase()}`}>{fleetStatusLabel(sensor.status)}</span></td>
                  <td>{fleetCapabilitiesLabel(sensor.capabilities)}</td>
                  <td>{sensor.assignment_count}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="pagination">
            <span className="pagination-summary">{currentResult.items.length} sensors · evaluated {formatFleetTimestamp(currentResult.evaluated_at)}</span>
            <div className="pagination-actions">
              <button type="button" disabled={filters.offset === 0 || loading} onClick={() => setFilters((current) => updateFleetPage(current, 'previous', currentResult.has_more))}>Previous</button>
              <button type="button" disabled={!currentResult.has_more || loading || filters.offset >= 100000} onClick={() => { setFilters((current) => updateFleetPage(current, 'next', currentResult.has_more)); setSelectedId(null); setCreatedTask(null) }}>Next</button>
            </div>
          </div>
        </>
      )}

      {selectedDetail && (
        <aside className="remote-sensor-detail" aria-label={`Sensor details: ${selectedDetail.name}`}>
          <div className="remote-sensor-detail-heading"><h3>{selectedDetail.name}</h3><button type="button" onClick={() => { setSelectedId(null); setCreatedTask(null) }}>Close details</button></div>
          <h4>Identity / Status</h4>
          <dl>
            <div><dt>Sensor ID</dt><dd>{selectedDetail.id}</dd></div>
            <div><dt>UUID</dt><dd className="mono">{selectedDetail.sensor_uuid}</dd></div>
            <div><dt>Site</dt><dd>{selectedDetail.site_name ?? 'Unavailable'} · Site {selectedDetail.site_id} · {fleetSiteState(selectedDetail.site_enabled)}</dd></div>
            <div><dt>Platform</dt><dd>{selectedDetail.platform} · {selectedDetail.version} <small>{PLATFORM_METADATA_LABEL}</small></dd></div>
            <div><dt>Registered</dt><dd>{formatFleetTimestamp(selectedDetail.registered_at)}</dd></div>
            <div><dt>Last heartbeat</dt><dd>{selectedDetail.last_seen_at ? `${formatFleetTimestamp(selectedDetail.last_seen_at)} · ${formatFleetHeartbeatAge(selectedDetail.heartbeat_age_seconds)}` : 'Never'}</dd></div>
            <div><dt>Status</dt><dd><span className={`remote-sensor-status remote-sensor-status-${String(selectedDetail.status).toLowerCase()}`}>{fleetStatusLabel(selectedDetail.status)}</span></dd></div>
          </dl>
          <section><h4>Declared Capabilities</h4><p>{fleetCapabilitiesLabel(selectedDetail.capabilities)}</p></section>
          <section><h4>Assignments</h4><p>{selectedDetail.assignment_count} assigned scopes</p></section>
        </aside>
      )}
      <RemoteSensorFleetManagement sensor={selectedDetail} onRefreshFleet={refreshFleet} />
      <RemoteSensorTaskOperations key={selectedDetail?.id ?? 'no-sensor'} sensor={selectedDetail}
        onTaskCreated={(task) => {
          if (task.sensor_id === selectedDetail?.id) {
            setCreatedTask(task)
            setHistoryRefreshGeneration((value) => value + 1)
          }
        }} />
      <RemoteSensorTaskHistory selectedSensor={selectedDetail} refreshSignal={historyRefreshGeneration}
        createdTask={createdTask} />
    </section>
  )
}

export default RemoteSensorFleet
