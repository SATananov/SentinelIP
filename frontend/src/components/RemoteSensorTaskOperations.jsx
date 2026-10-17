import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import {
  createRemoteSensorNetworkTask,
  createRemoteSensorServiceTask,
  listEligibleRemoteSensorTaskDevices,
  listEligibleRemoteSensorTaskScopes,
} from '../services/remoteSensorApi.js'
import {
  availableRemoteTaskTypes,
  createTaskOperationRequestGuard,
  taskCreationConfirmation,
  taskCreationResultMessage,
} from '../services/remoteSensorTaskOperationsState.js'

const PAGE_SIZE = 100

function RemoteSensorTaskOperations({ sensor, onTaskCreated }) {
  const [operation, setOperation] = useState('')
  const [scopePage, setScopePage] = useState({ items: [], offset: 0, has_more: false })
  const [scopeId, setScopeId] = useState('')
  const [devicePage, setDevicePage] = useState({ items: [], offset: 0, has_more: false })
  const [deviceId, setDeviceId] = useState('')
  const [scopeRequest, setScopeRequest] = useState({ loading: false, error: '' })
  const [deviceRequest, setDeviceRequest] = useState({ loading: false, error: '' })
  const [submitState, setSubmitState] = useState({ submitting: false, error: '', created: null })
  const scopeGuard = useRef(createTaskOperationRequestGuard())
  const deviceGuard = useRef(createTaskOperationRequestGuard())
  const mutationGeneration = useRef(0)
  const submitLock = useRef(false)
  const mounted = useRef(false)
  const contextRef = useRef(sensor?.id ?? null)
  const sensorId = sensor?.id
  const taskTypes = availableRemoteTaskTypes(sensor)
  const selectedScope = scopePage.items.find((item) => String(item.scope_id) === scopeId)
  const selectedDevice = devicePage.items.find((item) => String(item.device_id) === deviceId)
  const scopesForOperation = scopePage.items.filter((item) => item.supported_task_types.includes(operation))

  useLayoutEffect(() => { contextRef.current = sensorId ?? null }, [sensorId])

  useEffect(() => {
    mounted.current = true
    const scopeRequestGuard = scopeGuard.current
    const deviceRequestGuard = deviceGuard.current
    return () => {
      mounted.current = false
      scopeRequestGuard.invalidate()
      deviceRequestGuard.invalidate()
      mutationGeneration.current += 1
    }
  }, [])

  const supportedTaskTypesKey = taskTypes.join(',')

  useEffect(() => {
    const guard = scopeGuard.current
    guard.invalidate()
    const current = guard.begin()
    if (!operation || !sensorId || !supportedTaskTypesKey.split(',').includes(operation)) {
      queueMicrotask(() => {
        setScopePage({ items: [], offset: 0, has_more: false })
        setScopeRequest({ loading: false, error: '' })
      })
      return undefined
    }
    const controller = new AbortController()
    queueMicrotask(() => {
      if (!controller.signal.aborted) {
        setScopeRequest({ loading: true, error: '' })
        setScopeId('')
      }
    })
    listEligibleRemoteSensorTaskScopes(sensorId, { limit: PAGE_SIZE, offset: scopePage.offset }, controller.signal)
      .then((result) => {
        if (!controller.signal.aborted && guard.isCurrent(current)
            && contextRef.current === sensorId) {
          setScopePage(result)
          setScopeRequest({ loading: false, error: '' })
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted && guard.isCurrent(current)
            && contextRef.current === sensorId && error.name !== 'AbortError') {
          setScopeRequest({ loading: false, error: error.message || 'Eligible scopes could not be loaded.' })
        }
      })
    return () => {
      controller.abort()
      guard.invalidate()
    }
  }, [operation, sensorId, supportedTaskTypesKey, scopePage.offset])

  useEffect(() => {
    const guard = deviceGuard.current
    guard.invalidate()
    const current = guard.begin()
    if (operation !== 'DISCOVER_SERVICES' || !sensorId || !scopeId
        || !supportedTaskTypesKey.split(',').includes(operation)) {
      queueMicrotask(() => {
        setDevicePage({ items: [], offset: 0, has_more: false })
        setDeviceRequest({ loading: false, error: '' })
        setDeviceId('')
      })
      return undefined
    }
    const controller = new AbortController()
    queueMicrotask(() => {
      if (!controller.signal.aborted) {
        setDeviceRequest({ loading: true, error: '' })
        setDevicePage({ items: [], offset: 0, has_more: false })
        setDeviceId('')
      }
    })
    listEligibleRemoteSensorTaskDevices(sensorId, Number(scopeId),
      { limit: PAGE_SIZE, offset: devicePage.offset }, controller.signal)
      .then((result) => {
        if (!controller.signal.aborted && guard.isCurrent(current)
            && contextRef.current === sensorId) {
          setDevicePage(result)
          setDeviceRequest({ loading: false, error: '' })
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted && guard.isCurrent(current)
            && contextRef.current === sensorId && error.name !== 'AbortError') {
          setDeviceRequest({ loading: false, error: error.message || 'Eligible devices could not be loaded.' })
        }
      })
    return () => {
      controller.abort()
      guard.invalidate()
    }
  }, [operation, sensorId, scopeId, supportedTaskTypesKey, devicePage.offset])

  function chooseOperation(nextOperation) {
    setOperation(nextOperation)
    setScopeId('')
    setDeviceId('')
    setDevicePage({ items: [], offset: 0, has_more: false })
    setSubmitState({ submitting: false, error: '', created: null })
  }

  function closeForm() {
    if (submitLock.current) return
    setOperation('')
    setScopeId('')
    setDeviceId('')
    setSubmitState({ submitting: false, error: '', created: null })
  }

  async function submitTask() {
    if (submitLock.current || !sensorId || !selectedScope) return
    if (operation === 'DISCOVER_SERVICES' && !selectedDevice) return
    const confirmation = taskCreationConfirmation(operation, selectedScope, selectedDevice, sensor)
    if (!confirmation || !window.confirm(confirmation)) return
    const context = sensorId
    const attempt = ++mutationGeneration.current
    submitLock.current = true
    setSubmitState({ submitting: true, error: '', created: null })
    try {
      const task = operation === 'DISCOVER_NETWORK'
        ? await createRemoteSensorNetworkTask(sensorId, selectedScope.scope_id)
        : await createRemoteSensorServiceTask(sensorId, selectedScope.scope_id, selectedDevice.device_id)
      if (!mounted.current || contextRef.current !== context || mutationGeneration.current !== attempt) return
      setSubmitState({ submitting: false, error: '', created: task })
      onTaskCreated?.(task)
    } catch (error) {
      if (mounted.current && contextRef.current === context && mutationGeneration.current === attempt) {
        setSubmitState({ submitting: false, error: error?.message || 'Task could not be created.', created: null })
      }
    } finally {
      if (mounted.current && contextRef.current === context && mutationGeneration.current === attempt) {
        submitLock.current = false
      }
    }
  }

  if (!sensor) return null
  const administrativelyUnavailable = sensor.enabled !== true || sensor.site_enabled !== true
    || sensor.status === 'DISABLED' || sensor.status === 'REVOKED'

  return (
    <section className="remote-sensor-task-operations" aria-labelledby="remote-task-operations-title">
      <div>
        <p className="panel-kicker">Bounded operator action</p>
        <h3 id="remote-task-operations-title">Task Operations</h3>
        <p className="security-layer-copy">Tasks use assigned private network scopes and the existing fixed sensor profiles. A queued task runs only if the sensor claims it before its 15-minute expiry.</p>
        {(sensor.status === 'OFFLINE' || sensor.status === 'PENDING') && !administrativelyUnavailable
          && <p className="security-layer-copy">Sensor is {sensor.status.toLowerCase()}; task creation is allowed, but execution is not confirmed.</p>}
      </div>

      {administrativelyUnavailable && <p role="status">Task creation is unavailable while this sensor or its site is disabled or its credential is revoked.</p>}
      {!administrativelyUnavailable && taskTypes.length === 0 && <p>No supported task capability is declared by this sensor.</p>}
      {!operation && !administrativelyUnavailable && taskTypes.includes('DISCOVER_NETWORK')
        && <button type="button" onClick={() => chooseOperation('DISCOVER_NETWORK')}>Discover Network</button>}
      {!operation && !administrativelyUnavailable && taskTypes.includes('DISCOVER_SERVICES')
        && <button type="button" onClick={() => chooseOperation('DISCOVER_SERVICES')}>Discover Services</button>}

      {operation && (
        <div className="remote-task-operation-form">
          <h4>{operation === 'DISCOVER_NETWORK' ? 'Discover Network' : 'Discover Services'}</h4>
          <label><span>Eligible assigned scope</span>
            <select value={scopeId} disabled={scopeRequest.loading || submitState.submitting}
              onChange={(event) => { setScopeId(event.target.value); setDevicePage({ items: [], offset: 0, has_more: false }); setDeviceId('') }}>
              <option value="">Select a scope</option>
              {scopesForOperation.map((scope) => <option key={scope.scope_id} value={scope.scope_id}>{scope.scope_name} · {scope.canonical_target}</option>)}
            </select>
          </label>
          {scopeRequest.loading && <p role="status">Loading eligible scopes…</p>}
          {scopeRequest.error && <p className="remote-sensor-error" role="alert">{scopeRequest.error}</p>}
          {!scopeRequest.loading && !scopeRequest.error && operation && scopesForOperation.length === 0
            && <p>No eligible assigned scopes are available on this page.</p>}
          {scopePage.items.length > 0 && <div className="pagination-actions">
            <button type="button" disabled={scopePage.offset === 0 || scopeRequest.loading || submitState.submitting}
              onClick={() => setScopePage((page) => ({ ...page, offset: Math.max(0, page.offset - PAGE_SIZE) }))}>Previous scopes</button>
            <button type="button" disabled={!scopePage.has_more || scopeRequest.loading || submitState.submitting}
              onClick={() => setScopePage((page) => ({ ...page, offset: page.offset + PAGE_SIZE }))}>More scopes</button>
          </div>}

          {operation === 'DISCOVER_SERVICES' && scopeId && <>
            <label><span>Eligible device and IP</span>
              <select value={deviceId} disabled={deviceRequest.loading || submitState.submitting}
                onChange={(event) => setDeviceId(event.target.value)}>
                <option value="">Select a device</option>
                {devicePage.items.map((device) => <option key={device.device_id} value={device.device_id}>Device {device.device_id} · {device.ip_address}</option>)}
              </select>
            </label>
            {deviceRequest.loading && <p role="status">Loading eligible devices…</p>}
            {deviceRequest.error && <p className="remote-sensor-error" role="alert">{deviceRequest.error}</p>}
            {!deviceRequest.loading && !deviceRequest.error && scopeId && devicePage.items.length === 0
              && <p>No eligible devices are available on this page.</p>}
            {devicePage.items.length > 0 && <div className="pagination-actions">
              <button type="button" disabled={devicePage.offset === 0 || deviceRequest.loading || submitState.submitting}
                onClick={() => setDevicePage((page) => ({ ...page, offset: Math.max(0, page.offset - PAGE_SIZE) }))}>Previous devices</button>
              <button type="button" disabled={!devicePage.has_more || deviceRequest.loading || submitState.submitting}
                onClick={() => setDevicePage((page) => ({ ...page, offset: page.offset + PAGE_SIZE }))}>More devices</button>
            </div>}
          </>}

          {submitState.error && <p className="remote-sensor-error" role="alert">{submitState.error}</p>}
          {submitState.created && <p role="status">{taskCreationResultMessage(submitState.created)}</p>}
          <div className="remote-sensor-management-actions">
            <button type="button" onClick={submitTask} disabled={submitState.submitting || scopeRequest.loading
              || deviceRequest.loading || administrativelyUnavailable
              || !selectedScope || (operation === 'DISCOVER_SERVICES' && !selectedDevice)}>
              {submitState.submitting ? 'Creating task…' : 'Confirm and create task'}
            </button>
            <button type="button" onClick={closeForm} disabled={submitState.submitting}>Close form</button>
          </div>
        </div>
      )}
    </section>
  )
}

export default RemoteSensorTaskOperations
