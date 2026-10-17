import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import {
  addRemoteSensorAssignment,
  createRemoteSensorSite,
  issueRemoteSensorEnrollment,
  listEligibleSensorScopes,
  listRemoteSensorAssignments,
  listRemoteSensorEnrollments,
  listRemoteSensorSites,
  removeRemoteSensorAssignment,
  revokeRemoteSensorCredential,
  revokeRemoteSensorEnrollment,
  setRemoteSensorEnabled,
  setRemoteSensorSiteEnabled,
} from '../services/remoteSensorApi.js'
import { fleetStatusLabel } from '../services/remoteSensorFleetState.js'
import { canReenableSensor, canRevokeEnrollment, createManagementRequestGuard, enrollmentLifecycle } from '../services/remoteSensorManagementState.js'

function RemoteSensorFleetManagement({ sensor, onRefreshFleet }) {
  const [sites, setSites] = useState([])
  const [siteId, setSiteId] = useState('')
  const [siteError, setSiteError] = useState('')
  const [siteBusy, setSiteBusy] = useState('')
  const [siteForm, setSiteForm] = useState({ name: '', description: '', enabled: true })
  const [enrollments, setEnrollments] = useState([])
  const [enrollmentLoading, setEnrollmentLoading] = useState(false)
  const [enrollmentError, setEnrollmentError] = useState('')
  const [ttl, setTtl] = useState(900)
  const [issued, setIssued] = useState(null)
  const [copyMessage, setCopyMessage] = useState('')
  const [assignments, setAssignments] = useState([])
  const [eligible, setEligible] = useState({ items: [], offset: 0, has_more: false })
  const [scopeId, setScopeId] = useState('')
  const [sensorError, setSensorError] = useState('')
  const [sensorBusy, setSensorBusy] = useState('')
  const [assignmentLoading, setAssignmentLoading] = useState(false)
  const generation = useRef(createManagementRequestGuard())
  const eligibleGeneration = useRef(0)
  const contextRef = useRef('')
  const sensorId = sensor?.id
  const sensorSiteId = sensor?.site_id
  const contextKey = `${siteId || ''}:${sensorId ?? ''}`

  useLayoutEffect(() => { contextRef.current = contextKey }, [contextKey])

  function activeRun(scope) {
    return generation.current.isCurrent(scope) && scope.context === contextRef.current
  }

  function clearIssued() {
    setIssued(null)
    setCopyMessage('')
  }

  async function runMutation(kind, action, refresh, errorSetter, busySetter, targetContext = contextKey) {
    const current = generation.current.begin(targetContext)
    busySetter(kind)
    errorSetter('')
    try {
      const result = await action()
      if (!activeRun(current)) return
      await refresh?.(result, current)
    } catch (error) {
      if (activeRun(current)) errorSetter(error?.message || 'The management request failed.')
    } finally {
      if (activeRun(current)) busySetter('')
    }
  }

  async function refreshSites(signal) {
    try {
      const result = await listRemoteSensorSites({ limit: 100, offset: 0 }, signal)
      if (!signal?.aborted) setSites(result)
    } catch (error) {
      if (!signal?.aborted && error.name !== 'AbortError') setSiteError(error.message)
    }
  }

  useEffect(() => {
    const controller = new AbortController()
    queueMicrotask(() => { void refreshSites(controller.signal) })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    // The selected entity changed; invalidate writes and clear its transient UI state.
    generation.current.invalidate(contextKey)
    queueMicrotask(() => {
      setSiteBusy('')
      setSensorBusy('')
      setSiteError('')
      setSensorError('')
    })
    if (sensorSiteId !== undefined) queueMicrotask(() => setSiteId(String(sensorSiteId)))
  }, [sensorId, sensorSiteId, contextKey])

  useEffect(() => {
    // Hide and discard a one-time token when site context changes.
    queueMicrotask(() => {
      clearIssued()
      setEnrollmentError('')
    })
    if (!siteId) { queueMicrotask(() => setEnrollments([])); return undefined }
    const controller = new AbortController()
    queueMicrotask(() => { if (!controller.signal.aborted) setEnrollmentLoading(true) })
    listRemoteSensorEnrollments(siteId, { limit: 100, offset: 0 }, controller.signal)
      .then((result) => { if (!controller.signal.aborted) setEnrollments(result) })
      .catch((error) => { if (!controller.signal.aborted && error.name !== 'AbortError') setEnrollmentError(error.message) })
      .finally(() => { if (!controller.signal.aborted) setEnrollmentLoading(false) })
    return () => controller.abort()
  }, [siteId])

  useEffect(() => {
    // These records belong to one selected sensor; clear them before loading another.
    eligibleGeneration.current += 1
    queueMicrotask(() => {
      setAssignments([])
      setEligible({ items: [], offset: 0, has_more: false })
      setScopeId('')
      setSensorError('')
    })
    if (!sensorId) return undefined
    const controller = new AbortController()
    queueMicrotask(() => { if (!controller.signal.aborted) setAssignmentLoading(true) })
    Promise.all([
      listRemoteSensorAssignments(sensorId, { limit: 100, offset: 0 }, controller.signal),
      listEligibleSensorScopes(sensorSiteId, sensorId, { limit: 100, offset: 0 }, controller.signal),
    ]).then(([assignmentRows, eligiblePage]) => {
      if (!controller.signal.aborted) {
        setAssignments(assignmentRows)
        setEligible(eligiblePage)
      }
    }).catch((error) => {
      if (!controller.signal.aborted && error.name !== 'AbortError') setSensorError(error.message)
    }).finally(() => {
      if (!controller.signal.aborted) setAssignmentLoading(false)
    })
    return () => controller.abort()
  }, [sensorId, sensorSiteId])

  const selectedSite = useMemo(() => sites.find((site) => String(site.id) === siteId) ?? null, [sites, siteId])
  const visibleIssued = issued?.siteId === siteId ? issued : null

  function selectSite(value) {
    generation.current.invalidate(`${value || ''}:${sensorId ?? ''}`)
    setSiteId(value)
    clearIssued()
  }

  function createSite(event) {
    event.preventDefault()
    const target = contextKey
    void runMutation('create-site', () => createRemoteSensorSite(siteForm), async () => {
      const result = await listRemoteSensorSites({ limit: 100, offset: 0 })
      setSites(result)
      setSiteForm({ name: '', description: '', enabled: true })
    }, setSiteError, setSiteBusy, target)
  }

  function toggleSite() {
    if (!selectedSite) return
    const enabled = !selectedSite.enabled
    const message = enabled
      ? `Enable ${selectedSite.name}? This restores site-level eligibility only.`
      : `Disable ${selectedSite.name}? Sensors at this site cannot authenticate or work, enrollment issuance and consumption are blocked, and task creation and claiming are blocked. Existing assignments and task rows are not deleted or cancelled. Re-enabling restores site-level eligibility only.`
    if (!window.confirm(message)) return
    const target = contextKey
    void runMutation('site-state', () => setRemoteSensorSiteEnabled(selectedSite.id, enabled), async () => {
      const result = await listRemoteSensorSites({ limit: 100, offset: 0 })
      setSites(result)
      onRefreshFleet()
    }, setSiteError, setSiteBusy, target)
  }

  function issueEnrollment(event) {
    event.preventDefault()
    if (!selectedSite) return
    clearIssued()
    const target = contextKey
    void runMutation('issue-enrollment', () => issueRemoteSensorEnrollment(selectedSite.id, Number(ttl)), async (result, request) => {
      setIssued({ siteId: String(selectedSite.id), token: result.token, id: result.id, expires_at: result.expires_at })
      const rows = await listRemoteSensorEnrollments(selectedSite.id, { limit: 100, offset: 0 })
      if (activeRun(request)) setEnrollments(rows)
    }, setEnrollmentError, setSiteBusy, target)
  }

  async function refreshEnrollments(targetSiteId) {
    const rows = await listRemoteSensorEnrollments(targetSiteId, { limit: 100, offset: 0 })
    if (String(targetSiteId) === siteId) setEnrollments(rows)
  }

  function revokeEnrollment(enrollment) {
    if (!window.confirm('Revoke this enrollment? It will no longer register a sensor. This does not revoke a registered sensor credential.')) return
    const target = contextKey
    void runMutation(`revoke-enrollment-${enrollment.id}`, () => revokeRemoteSensorEnrollment(enrollment.id), () => refreshEnrollments(siteId), setEnrollmentError, setSiteBusy, target)
  }

  function toggleSensor() {
    if (!canReenableSensor(sensor)) return
    const enabled = !sensor.enabled
    const message = enabled
      ? `Enable sensor ${sensor.name}? Sensor-level eligibility is restored if its site is enabled and its credential is active.`
      : `Disable sensor ${sensor.name}? It cannot authenticate, heartbeat, or claim tasks, and task creation rejects it.`
    if (!window.confirm(message)) return
    const target = contextKey
    void runMutation('sensor-state', () => setRemoteSensorEnabled(sensor.id, enabled), onRefreshFleet, setSensorError, setSensorBusy, target)
  }

  function revokeCredential() {
    if (!canReenableSensor(sensor)) return
    if (!window.confirm(`Revoke credential for ${sensor.name}? This credential cannot be restored. The sensor must register again through a new enrollment. Assignments remain and task rows are not deleted or cancelled.`)) return
    const target = contextKey
    void runMutation('credential-revoke', () => revokeRemoteSensorCredential(sensor.id), onRefreshFleet, setSensorError, setSensorBusy, target)
  }

  async function refreshAssignments(targetSensor) {
    const rows = await listRemoteSensorAssignments(targetSensor.id, { limit: 100, offset: 0 })
    if (sensor?.id === targetSensor.id) setAssignments(rows)
    onRefreshFleet()
  }

  function refreshEligible(offset = 0) {
    if (!sensor) return
    const target = contextKey
    const attempt = ++eligibleGeneration.current
    setAssignmentLoading(true)
    listEligibleSensorScopes(sensor.site_id, sensor.id, { limit: 100, offset })
      .then((result) => { if (attempt === eligibleGeneration.current && target === contextRef.current) setEligible(result) })
      .catch((error) => { if (attempt === eligibleGeneration.current && target === contextRef.current) setSensorError(error.message) })
      .finally(() => { if (attempt === eligibleGeneration.current && target === contextRef.current) setAssignmentLoading(false) })
  }

  function addAssignment(event) {
    event.preventDefault()
    if (!sensor || !scopeId) return
    const target = contextKey
    void runMutation('add-assignment', () => addRemoteSensorAssignment(sensor.id, Number(scopeId)), async () => {
      await refreshAssignments(sensor)
      await refreshEligible(eligible.offset)
      setScopeId('')
    }, setSensorError, setSensorBusy, target)
  }

  function removeAssignment(assignment) {
    const label = `${assignment.scope_name || `Scope ${assignment.scope_id}`} (${assignment.canonical_target})`
    if (!window.confirm(`Remove ${label} from ${sensor.name}?`)) return
    const target = contextKey
    void runMutation(`remove-assignment-${assignment.scope_id}`, () => removeRemoteSensorAssignment(sensor.id, assignment.scope_id), async () => {
      await refreshAssignments(sensor)
      await refreshEligible(eligible.offset)
    }, setSensorError, setSensorBusy, target)
  }

  async function copyToken() {
    try {
      await navigator.clipboard.writeText(issued.token)
      setCopyMessage('Token copied.')
    } catch {
      setCopyMessage('Copy failed. Select and copy the token manually.')
    }
  }

  return (
    <section className="remote-sensor-management" aria-label="Site and sensor management">
      <h3>Sites / Enrollment</h3>
      {siteError && <p role="alert" className="remote-sensor-error">{siteError}</p>}
      <label>Selected site
        <select value={siteId} onChange={(event) => selectSite(event.target.value)}>
          <option value="">Choose a site</option>
          {sites.map((site) => <option key={site.id} value={site.id}>{site.name} · Site {site.id} · {site.enabled ? 'Enabled' : 'Disabled'}</option>)}
        </select>
      </label>
      {selectedSite && <div className="remote-sensor-management-actions">
        <p><strong>{selectedSite.name}</strong> · {selectedSite.enabled ? 'Enabled' : 'Disabled'}</p>
        <button type="button" disabled={Boolean(siteBusy)} onClick={toggleSite}>{selectedSite.enabled ? 'Disable site' : 'Enable site'}</button>
      </div>}
      <form onSubmit={createSite} className="remote-sensor-management-form">
        <h4>Create site</h4>
        <label>Name<input required maxLength={128} value={siteForm.name} onChange={(event) => setSiteForm((current) => ({ ...current, name: event.target.value }))} /></label>
        <label>Description (optional)<input maxLength={1000} value={siteForm.description} onChange={(event) => setSiteForm((current) => ({ ...current, description: event.target.value }))} /></label>
        <label><input type="checkbox" checked={siteForm.enabled} onChange={(event) => setSiteForm((current) => ({ ...current, enabled: event.target.checked }))} /> Enabled</label>
        <button type="submit" disabled={Boolean(siteBusy) || !siteForm.name.trim()}>{siteBusy === 'create-site' ? 'Creating…' : 'Create site'}</button>
      </form>
      {selectedSite && <>
        <form onSubmit={issueEnrollment} className="remote-sensor-management-form">
          <h4>Issue sensor enrollment</h4>
          <label>Lifetime
            <select value={ttl} onChange={(event) => { clearIssued(); setTtl(Number(event.target.value)) }}>
              <option value={300}>5 minutes</option><option value={900}>15 minutes</option><option value={1800}>30 minutes</option><option value={3600}>60 minutes</option>
            </select>
          </label>
          <button type="submit" disabled={!selectedSite.enabled || Boolean(siteBusy)}>{siteBusy === 'issue-enrollment' ? 'Issuing…' : 'Create enrollment'}</button>
        </form>
        {visibleIssued && <div className="remote-sensor-issued-token" role="status">
          <strong>This token is shown only once. Copy it now; it cannot be retrieved later.</strong>
          <code>{visibleIssued.token}</code><button type="button" onClick={copyToken}>Copy token</button>{copyMessage && <span>{copyMessage}</span>}
          <button type="button" onClick={clearIssued}>Close and clear token</button>
        </div>}
        {enrollmentError && <p role="alert" className="remote-sensor-error">{enrollmentError}</p>}
        <h4>Enrollment history</h4>
        {enrollmentLoading ? <p role="status">Loading enrollments…</p> : enrollments.length === 0 ? <p>No enrollment records.</p> : (
          <ul className="remote-sensor-enrollment-list">{enrollments.map((enrollment) => {
            const state = enrollmentLifecycle(enrollment)
            return <li key={enrollment.id}>
              <span>Enrollment {enrollment.id} · {state} · Created {enrollment.created_at} · Expires {enrollment.expires_at}{enrollment.sensor_id ? ` · Sensor ${enrollment.sensor_id}` : ''}</span>
              {enrollment.revoked_at && <small>Revoked {enrollment.revoked_at}</small>}{enrollment.consumed_at && <small>Consumed {enrollment.consumed_at}</small>}
              {canRevokeEnrollment(enrollment) && <button type="button" disabled={Boolean(siteBusy)} onClick={() => revokeEnrollment(enrollment)}>Revoke enrollment</button>}
            </li>
          })}</ul>
        )}
      </>}

      {sensor && <section className="remote-sensor-selected-management" aria-label={`Management actions for ${sensor.name}`}>
        <h3>Selected sensor management</h3>
        {sensorError && <p role="alert" className="remote-sensor-error">{sensorError}</p>}
        <section><h4>Credential / Access State</h4><p>Sensor {sensor.enabled ? 'enabled' : 'disabled'} · {fleetStatusLabel(sensor.status)}</p>
          <h4>Management Actions</h4>
          <button type="button" disabled={Boolean(sensorBusy) || sensor.status === 'REVOKED'} onClick={toggleSensor}>{sensor.enabled ? 'Disable sensor' : 'Enable sensor'}</button>
          <button type="button" disabled={Boolean(sensorBusy) || sensor.status === 'REVOKED'} onClick={revokeCredential}>{sensor.status === 'REVOKED' ? 'Credential revoked' : 'Revoke credential'}</button>
        </section>
        <section><h4>Assignments</h4>
          {assignmentLoading ? <p role="status">Loading assignments…</p> : assignments.length === 0 ? <p>No scope assignments.</p> : <ul>{assignments.map((assignment) => <li key={assignment.scope_id}>
            <span>{assignment.scope_name || `Scope ${assignment.scope_id}`} · {assignment.canonical_target} · {assignment.scope_type || 'Type unavailable'} · {assignment.scope_enabled ? 'Enabled' : 'Disabled'}{assignment.scope_authorized ? ' · Authorized' : ' · Not authorized'}</span>
            <button type="button" disabled={Boolean(sensorBusy)} onClick={() => removeAssignment(assignment)}>Remove assignment</button>
          </li>)}</ul>}
          <form onSubmit={addAssignment} className="remote-sensor-management-form">
            <label>Add eligible scope
              <select value={scopeId} onChange={(event) => setScopeId(event.target.value)} disabled={assignmentLoading || Boolean(sensorBusy)}>
                <option value="">Choose an eligible scope</option>
                {eligible.items.map((scope) => <option key={scope.id} value={scope.id}>{scope.name || `Scope ${scope.id}`} · {scope.canonical_target} · {scope.scope_type}</option>)}
              </select>
            </label>
            <button type="submit" disabled={!scopeId || Boolean(sensorBusy) || sensor.status === 'REVOKED'}>{sensorBusy === 'add-assignment' ? 'Adding…' : 'Add assignment'}</button>
          </form>
          {eligible.has_more && <button type="button" disabled={assignmentLoading} onClick={() => refreshEligible(eligible.offset + eligible.limit)}>Next eligible scopes</button>}
          {eligible.offset > 0 && <button type="button" disabled={assignmentLoading} onClick={() => refreshEligible(Math.max(0, eligible.offset - eligible.limit))}>Previous eligible scopes</button>}
        </section>
      </section>}
    </section>
  )
}

export default RemoteSensorFleetManagement
