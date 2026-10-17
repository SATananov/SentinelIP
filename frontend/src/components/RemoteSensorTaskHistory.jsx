import { useEffect, useMemo, useRef, useState } from 'react'
import { loadRemoteSensorTaskHistory } from '../services/remoteSensorApi.js'
import {
  createTaskHistoryRequestGuard,
  formatTaskTimestamp,
  projectTaskHistoryDetail,
  taskHistoryQueryKey,
  taskHistoryViewState,
  taskStatusLabel,
  taskTimestampLabel,
  taskTypeLabel,
  updateTaskHistoryFilter,
  updateTaskHistoryPage,
} from '../services/remoteSensorTaskHistoryState.js'

const TASK_TYPES = ['DISCOVER_NETWORK', 'DISCOVER_SERVICES']
const TASK_STATES = ['PENDING', 'CLAIMED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED']

function asUtc(value) {
  return value ? new Date(value).toISOString() : ''
}

function RemoteSensorTaskHistory({ selectedSensor }) {
  const [filters, setFilters] = useState({ limit: 20, offset: 0, sensor_id: '', site_id: '', scope_id: '', device_id: '', task_type: '', status: '', created_after_local: '', created_before_local: '' })
  const [data, setData] = useState(null)
  const [request, setRequest] = useState({ key: null, loading: false, error: null })
  const [selectedTaskId, setSelectedTaskId] = useState(null)
  const [refreshGeneration, setRefreshGeneration] = useState(0)
  const requestGuard = useRef(createTaskHistoryRequestGuard())
  const queryKey = useMemo(() => taskHistoryQueryKey(filters), [filters])

  useEffect(() => {
    const guard = requestGuard.current
    const generation = guard.begin()
    const controller = new AbortController()
    const query = {
      ...filters,
      created_after: asUtc(filters.created_after_local),
      created_before: asUtc(filters.created_before_local),
    }
    loadRemoteSensorTaskHistory(query, controller.signal)
      .then((result) => {
        if (!controller.signal.aborted && guard.isCurrent(generation)) {
          setData({ key: queryKey, result })
          setSelectedTaskId((current) => result.items?.some((item) => item.id === current) ? current : null)
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted && guard.isCurrent(generation) && error.name !== 'AbortError') {
          setRequest({ key: queryKey, loading: false, error: error.message || 'Task history could not be loaded.' })
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
  }, [filters, queryKey, refreshGeneration])

  const result = data?.key === queryKey ? data.result : null
  const currentRequest = request.key === queryKey ? request : null
  const loading = currentRequest?.loading ?? !result
  const error = currentRequest?.error ?? null
  const selectedTask = projectTaskHistoryDetail(result?.items?.find((item) => item.id === selectedTaskId))
  const viewState = taskHistoryViewState({ loading, error, result })

  function changeFilter(key, value) {
    setFilters((current) => updateTaskHistoryFilter(current, key, value))
    setSelectedTaskId(null)
  }

  function refresh() {
    setRequest({ key: queryKey, loading: true, error: null })
    setRefreshGeneration((value) => value + 1)
  }

  function useSelectedSensor() {
    if (!selectedSensor) return
    changeFilter('sensor_id', String(selectedSensor.id))
  }

  return (
    <section className="remote-task-history" aria-labelledby="remote-task-history-title">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Read-only task inspection</p>
          <h3 id="remote-task-history-title">Task History</h3>
          <p className="security-layer-copy">Task lifecycle metadata and safe failure details. Results and task payloads are not shown.</p>
        </div>
        <div className="remote-task-history-actions">
          {selectedSensor && <button type="button" onClick={useSelectedSensor}>Filter to selected sensor</button>}
          <button type="button" onClick={() => changeFilter('sensor_id', '')} disabled={!filters.sensor_id}>All sensors</button>
          <button type="button" onClick={refresh} disabled={loading}>Refresh tasks</button>
        </div>
      </div>

      <div className="remote-task-history-filters" aria-label="Task history filters">
        <label><span>Sensor ID</span><input type="number" min="1" value={filters.sensor_id} onChange={(event) => changeFilter('sensor_id', event.target.value)} /></label>
        <label><span>Site ID</span><input type="number" min="1" value={filters.site_id} onChange={(event) => changeFilter('site_id', event.target.value)} /></label>
        <label><span>Scope ID</span><input type="number" min="1" value={filters.scope_id} onChange={(event) => changeFilter('scope_id', event.target.value)} /></label>
        <label><span>Device ID</span><input type="number" min="1" value={filters.device_id} onChange={(event) => changeFilter('device_id', event.target.value)} /></label>
        <label><span>Task type</span><select value={filters.task_type} onChange={(event) => changeFilter('task_type', event.target.value)}><option value="">All types</option>{TASK_TYPES.map((type) => <option key={type} value={type}>{taskTypeLabel(type)}</option>)}</select></label>
        <label><span>Stored status</span><select value={filters.status} onChange={(event) => changeFilter('status', event.target.value)}><option value="">All statuses</option>{TASK_STATES.map((status) => <option key={status} value={status}>{taskStatusLabel(status)}</option>)}</select></label>
        <label><span>Created after (local)</span><input type="datetime-local" value={filters.created_after_local} onChange={(event) => changeFilter('created_after_local', event.target.value)} /></label>
        <label><span>Created before (local)</span><input type="datetime-local" value={filters.created_before_local} onChange={(event) => changeFilter('created_before_local', event.target.value)} /></label>
        <label><span>Rows per page</span><select value={filters.limit} onChange={(event) => changeFilter('limit', Number(event.target.value))}><option value="20">20</option><option value="50">50</option><option value="100">100</option></select></label>
      </div>

      {error && <div className="remote-sensor-error" role="alert">{error}</div>}
      {viewState === 'loading' && <p className="security-empty" role="status">Loading task history…</p>}
      {viewState === 'empty' && <p className="security-empty">No tasks match these filters.</p>}
      {viewState === 'ready' && (
        <>
          <div className="remote-sensor-table-wrap">
            <table className="remote-sensor-table remote-task-table">
              <thead><tr><th>Task</th><th>Sensor / Site</th><th>Scope / Target</th><th>Type</th><th>Status</th><th>Created</th><th>Failure</th></tr></thead>
              <tbody>{result.items.map((task) => (
                <tr key={task.id} className={selectedTaskId === task.id ? 'remote-sensor-selected' : ''}>
                  <td><button type="button" className="remote-sensor-select" aria-pressed={selectedTaskId === task.id} onClick={() => setSelectedTaskId((current) => current === task.id ? null : task.id)}><strong>{task.id}</strong><small>Attempts recorded: {task.attempt_count}</small></button></td>
                  <td>{task.sensor_name ?? 'Unavailable'}<small>Sensor {task.sensor_id} · {task.site_name ?? 'Unavailable'} · Site {task.site_id}</small></td>
                  <td>{task.scope_name || 'Unavailable'}<small>{task.canonical_target ?? 'Target unavailable'}{task.target_ip ? ` · ${task.target_ip}` : ''}</small></td>
                  <td>{taskTypeLabel(task.task_type)}</td>
                  <td><span className={`remote-sensor-status remote-task-status-${String(task.status).toLowerCase()}`}>{taskStatusLabel(task.status)}</span>{task.expired && <small className="remote-task-expired">Expired (stored: {taskStatusLabel(task.status)})</small>}</td>
                  <td>{formatTaskTimestamp(task.created_at)}</td>
                  <td>{task.failure_code ? <><strong>{task.failure_code}</strong><small>{task.failure_message_safe}</small></> : '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="pagination">
            <span className="pagination-summary">{result.items.length} tasks · evaluated {formatTaskTimestamp(result.evaluated_at)}</span>
            <div className="pagination-actions">
              <button type="button" disabled={filters.offset === 0 || loading} onClick={() => setFilters((current) => updateTaskHistoryPage(current, 'previous', result.has_more))}>Previous</button>
              <button type="button" disabled={!result.has_more || loading || filters.offset >= 100000} onClick={() => { setFilters((current) => updateTaskHistoryPage(current, 'next', result.has_more)); setSelectedTaskId(null) }}>Next</button>
            </div>
          </div>
        </>
      )}

      {selectedTask && (
        <aside className="remote-sensor-detail remote-task-detail" aria-label={`Task details: ${selectedTask.id}`}>
          <div className="remote-sensor-detail-heading"><h4>Task details</h4><button type="button" onClick={() => setSelectedTaskId(null)}>Close details</button></div>
          <dl>
            <div><dt>Task ID</dt><dd className="mono">{selectedTask.id}</dd></div>
            <div><dt>Type</dt><dd>{taskTypeLabel(selectedTask.task_type)}</dd></div>
            <div><dt>Stored status</dt><dd>{taskStatusLabel(selectedTask.status)}{selectedTask.expired ? ' · Expired (derived)' : ''}</dd></div>
            <div><dt>Sensor</dt><dd>{selectedTask.sensor_name ?? 'Unavailable'} · ID {selectedTask.sensor_id}</dd></div>
            <div><dt>Site</dt><dd>{selectedTask.site_name ?? 'Unavailable'} · ID {selectedTask.site_id}</dd></div>
            <div><dt>Scope</dt><dd>{selectedTask.scope_name ?? 'Unavailable'} · ID {selectedTask.scope_id} · {selectedTask.canonical_target ?? 'Target unavailable'}</dd></div>
            <div><dt>Device</dt><dd>{selectedTask.target_device_id ?? 'Not applicable'}{selectedTask.target_ip ? ` · ${selectedTask.target_ip}` : ''}</dd></div>
            <div><dt>Created</dt><dd>{formatTaskTimestamp(selectedTask.created_at)}</dd></div>
            <div><dt>Expires</dt><dd>{formatTaskTimestamp(selectedTask.expires_at)}</dd></div>
            <div><dt>Claimed</dt><dd>{taskTimestampLabel(selectedTask, 'claimed_at')}</dd></div>
            <div><dt>Started</dt><dd>{taskTimestampLabel(selectedTask, 'started_at')}</dd></div>
            <div><dt>Completed</dt><dd>{taskTimestampLabel(selectedTask, 'completed_at')}</dd></div>
            <div><dt>Terminal failure time</dt><dd>{taskTimestampLabel(selectedTask, 'failed_at')}</dd></div>
            <div><dt>Attempts recorded</dt><dd>{selectedTask.attempt_count}</dd></div>
            {selectedTask.failure_code && <div><dt>Failure</dt><dd>{selectedTask.failure_code} · {selectedTask.failure_message_safe}</dd></div>}
          </dl>
          <p className="security-layer-copy">Scope name and target are current context. Expiry is derived from the request evaluation time; stored task state is unchanged.</p>
        </aside>
      )}
    </section>
  )
}

export default RemoteSensorTaskHistory
