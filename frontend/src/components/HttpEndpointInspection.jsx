import { useEffect, useMemo, useRef, useState } from 'react'
import {
  HTTP_ENDPOINT_HISTORY_MAX_ROWS,
  inspectHttpEndpoint,
  loadHttpEndpointHistory,
} from '../services/httpEndpointApi.js'
import {
  appendUniqueObservations,
  httpEndpointIdentity,
  isCurrentHttpEndpointRequest,
  inspectionPresentation,
  safeResponseHeaders,
  selectableTcpPorts,
  endHttpEndpointRequest,
  tryBeginHttpEndpointRequest,
  verifiedTlsFacts,
} from '../services/httpEndpointState.js'
import '../http-endpoint-inspection.css'

function HistoryError({ error }) {
  if (!error) return null
  const messages = {
    authorization: 'History is unavailable because local operator or scope authorization was rejected.',
    missing_resource: 'This device or port is no longer available in the authorized inventory.',
    network_error: 'The local API could not be reached. History could not be loaded.',
  }
  return <p className="http-endpoint-error" role="alert">{messages[error.kind] || 'Endpoint history could not be loaded.'}</p>
}

export function CertificateDetails({ tls }) {
  const facts = verifiedTlsFacts(tls)
  if (!tls) return null
  return <section className="http-endpoint-detail-group">
    <h5>TLS</h5>
    <p>Verification: {tls.verification_status || 'Not recorded'}</p>
    {tls.hostname_verification && <p>Hostname match: {tls.hostname_verification}</p>}
    {tls.ip_address_verification && <p>IP address match: {tls.ip_address_verification}</p>}
    {tls.verification_name && <p>Verified name: {tls.verification_name}</p>}
    {facts && <>
      {facts.protocol_version && <p>Protocol: {facts.protocol_version}</p>}
      {facts.cipher && <p>Cipher: {facts.cipher.name} · {facts.cipher.bits} bits</p>}
      {facts.certificate_subject?.length > 0 && <p>Subject: {facts.certificate_subject.map((part) => `${part.name}=${part.value}`).join(', ')}</p>}
      {facts.certificate_issuer?.length > 0 && <p>Issuer: {facts.certificate_issuer.map((part) => `${part.name}=${part.value}`).join(', ')}</p>}
      {(facts.not_before || facts.not_after) && <p>Validity: {facts.not_before || 'Not recorded'} – {facts.not_after || 'Not recorded'}</p>}
      {facts.subject_alt_names?.length > 0 && <p>Subject Alternative Names: {facts.subject_alt_names.map((part) => `${part.type}: ${part.value}`).join(', ')}</p>}
      {facts.sha256_fingerprint && <p className="http-endpoint-fingerprint">SHA-256: {facts.sha256_fingerprint}</p>}
    </>}
    {!facts && <p>Certificate properties are hidden because TLS verification did not succeed.</p>}
    {tls.error_category && <p>Error category: {tls.error_category}</p>}
  </section>
}

export function ObservationDetails({ item, portNumber }) {
  const headers = safeResponseHeaders(item.response_headers)
  return <details className="http-endpoint-observation-details">
    <summary>Observation #{item.id} · {item.scheme.toUpperCase()} · {item.outcome}</summary>
    <div className="http-endpoint-detail-grid">
      <section className="http-endpoint-detail-group">
        <h5>HTTP observation</h5>
        <p>Observed: {item.observed_at}</p>
        <p>Port: {portNumber}/TCP</p>
        <p>Target: {item.target_ip}{item.approved_hostname ? ` · ${item.approved_hostname}` : ''}</p>
        <p>Source: {item.source}</p>
        <p>Outcome: {item.outcome}</p>
        {item.error_category && <p>Error category: {item.error_category}</p>}
        {item.status_code !== null && <p>HTTP status: {item.status_code}</p>}
        {item.content_type && <p>Content-Type: {item.content_type}</p>}
        {item.content_length !== null && <p>Declared Content-Length: {item.content_length}</p>}
        {headers.length > 0 && <div><strong>Selected response headers</strong><ul>{headers.map(([name, value]) => <li key={name}>{name}: {value}</li>)}</ul></div>}
        {item.redirect_location && <p>Redirect observed (not followed): {item.redirect_location}</p>}
        {item.server_identifier && <p>Server header (self-reported, low confidence): {item.server_identifier.value}</p>}
      </section>
      <CertificateDetails tls={item.tls}/>
      <section className="http-endpoint-detail-group">
        <h5>Scan provenance</h5>
        <p>Run: {item.scan?.run_id || 'Not recorded'}</p>
        <p>Target record: {item.scan?.target_id ?? 'Not recorded'}</p>
        <p>Profile: {item.scan?.profile || 'Not recorded'}</p>
        <p>Scanner: {item.scan?.scanner || 'Not recorded'}{item.scan?.scanner_version ? ` ${item.scan.scanner_version}` : ''}</p>
        <p>Run status: {item.scan?.status || 'Not recorded'}</p>
        <p>Target outcome: {item.scan?.target_outcome || 'Not recorded'}</p>
        {item.scan?.error_category && <p>Error category: {item.scan.error_category}</p>}
      </section>
    </div>
  </details>
}

function HttpEndpointHistory({ scopeId, deviceId, port, reloadToken }) {
  const endpointKey = httpEndpointIdentity(scopeId, deviceId, port?.id)
  const requestKey = `${endpointKey}:${reloadToken}`
  const [pageState, setPageState] = useState(() => ({
    key: requestKey, items: [], nextCursor: null, loading: true, loadingMore: false, error: null,
  }))
  const generation = useRef(0)
  const controllerRef = useRef(null)
  const pendingRef = useRef(false)
  const current = pageState.key === requestKey ? pageState : {
    key: requestKey, items: [], nextCursor: null, loading: true, loadingMore: false, error: null,
  }

  useEffect(() => {
    const requestGeneration = ++generation.current
    const controller = new AbortController()
    controllerRef.current?.abort()
    controllerRef.current = controller
    pendingRef.current = true
    loadHttpEndpointHistory({ scopeId, deviceId, portId: port.id, signal: controller.signal })
      .then((page) => {
        if (requestGeneration !== generation.current || controller.signal.aborted) return
        setPageState({ key: requestKey, items: appendUniqueObservations([], page.items),
          nextCursor: page.next_cursor, loading: false, loadingMore: false, error: null })
      })
      .catch((error) => {
        if (requestGeneration === generation.current && !controller.signal.aborted) {
          setPageState({ key: requestKey, items: [], nextCursor: null,
            loading: false, loadingMore: false, error })
        }
      })
      .finally(() => {
        if (requestGeneration === generation.current) {
          pendingRef.current = false
          if (controllerRef.current === controller) controllerRef.current = null
        }
      })
    return () => {
      generation.current += 1
      pendingRef.current = false
      controller.abort()
      if (controllerRef.current === controller) controllerRef.current = null
    }
  }, [deviceId, port.id, requestKey, scopeId])

  async function loadMore() {
    if (!current.nextCursor || pendingRef.current || current.items.length >= HTTP_ENDPOINT_HISTORY_MAX_ROWS) return
    const requestGeneration = generation.current
    const controller = new AbortController()
    controllerRef.current?.abort()
    controllerRef.current = controller
    pendingRef.current = true
    setPageState((state) => state.key === requestKey
      ? { ...state, loadingMore: true, error: null } : state)
    try {
      const page = await loadHttpEndpointHistory({
        scopeId, deviceId, portId: port.id, cursor: current.nextCursor, signal: controller.signal,
      })
      if (requestGeneration !== generation.current || controller.signal.aborted) return
      setPageState((state) => state.key === requestKey ? {
        ...state,
        items: appendUniqueObservations(state.items, page.items),
        nextCursor: page.next_cursor,
        loadingMore: false,
      } : state)
    } catch (error) {
      if (requestGeneration === generation.current && !controller.signal.aborted) {
        setPageState((state) => state.key === requestKey ? { ...state, loadingMore: false, error } : state)
      }
    } finally {
      if (requestGeneration === generation.current) {
        pendingRef.current = false
        if (controllerRef.current === controller) controllerRef.current = null
      }
    }
  }

  return <>
    {current.loading && <p className="recon-muted" role="status">Loading endpoint history…</p>}
    <HistoryError error={current.error}/>
    {!current.loading && !current.error && current.items.length === 0 && <p className="recon-muted">No HTTP/TLS observations are recorded for this port.</p>}
    {current.items.length > 0 && <div className="http-endpoint-history" aria-label="HTTP and TLS observation history">
      <h5>Stored observations ({current.items.length}{current.nextCursor ? '+' : ''})</h5>
      <div className="http-endpoint-history-list">
        {current.items.map((item) => <article className="http-endpoint-observation" key={item.id}>
          <div className="http-endpoint-observation-summary">
            <strong>{item.observed_at}</strong>
            <span>{item.scheme.toUpperCase()} · {port.port_number}/TCP · {item.outcome}</span>
            {item.status_code !== null && <span>HTTP {item.status_code}</span>}
            {item.tls && <span>TLS: {item.tls.verification_status}</span>}
            <small>Observation #{item.id} · run {item.scan?.run_id || 'not recorded'}</small>
          </div>
          <ObservationDetails item={item} portNumber={port.port_number}/>
        </article>)}
      </div>
      {current.items.length >= HTTP_ENDPOINT_HISTORY_MAX_ROWS && current.nextCursor && <p className="recon-muted">Showing the first {HTTP_ENDPOINT_HISTORY_MAX_ROWS} observations for this view.</p>}
      {current.nextCursor && current.items.length < HTTP_ENDPOINT_HISTORY_MAX_ROWS && <button type="button" className="recon-secondary"
        disabled={current.loadingMore || current.loading} onClick={loadMore}>
        {current.loadingMore ? 'Loading more…' : 'Load more observations'}
      </button>}
      {current.loadingMore && <p className="recon-muted" role="status">Loading more observations…</p>}
    </div>}
  </>
}

function HttpEndpointInspection({ scopeId, device, ports, authorizationConfirmed }) {
  const choices = useMemo(() => selectableTcpPorts(ports), [ports])
  const [portId, setPortId] = useState('')
  const [scheme, setScheme] = useState('http')
  const [inspectionState, setInspectionState] = useState({ key: '', pending: false, result: null, error: null })
  const [historyReload, setHistoryReload] = useState(0)
  const inspectionGeneration = useRef(0)
  const inspectionController = useRef(null)
  const inspectionPendingRef = useRef(false)
  const port = choices.find((item) => String(item.id) === portId)
  const endpointKey = httpEndpointIdentity(scopeId, device?.id, port?.id)
  const activeEndpoint = useRef(endpointKey)
  const visibleInspection = inspectionState.key === endpointKey ? inspectionState : {
    key: endpointKey, pending: false, result: null, error: null,
  }

  useEffect(() => {
    return () => {
      inspectionGeneration.current += 1
      inspectionController.current?.abort()
      inspectionPendingRef.current = false
    }
  }, [])

  function choosePort(value) {
    activeEndpoint.current = httpEndpointIdentity(scopeId, device?.id, value ? Number(value) : undefined)
    inspectionGeneration.current += 1
    inspectionController.current?.abort()
    inspectionPendingRef.current = false
    setPortId(value)
  }

  async function inspect() {
    if (!port || !authorizationConfirmed || !tryBeginHttpEndpointRequest(inspectionPendingRef)) return
    const generation = ++inspectionGeneration.current
    const requestEndpoint = endpointKey
    const controller = new AbortController()
    inspectionController.current?.abort()
    inspectionController.current = controller
    setInspectionState({ key: endpointKey, pending: true, result: null, error: null })
    try {
      const result = await inspectHttpEndpoint({
        scopeId, deviceId: device.id, portId: port.id, scheme, signal: controller.signal,
      })
      if (!isCurrentHttpEndpointRequest(requestEndpoint, activeEndpoint.current, generation, inspectionGeneration.current, controller.signal)) return
      setInspectionState({ key: endpointKey, pending: true, result, error: null })
      if (result.persistence?.status === 'PERSISTED') setHistoryReload((value) => value + 1)
    } catch (error) {
      if (generation === inspectionGeneration.current && !controller.signal.aborted) {
        setInspectionState({ key: endpointKey, pending: true, result: null, error })
      }
    } finally {
      if (generation === inspectionGeneration.current) {
        endHttpEndpointRequest(inspectionPendingRef)
        setInspectionState((current) => current.key === endpointKey ? { ...current, pending: false } : current)
        if (inspectionController.current === controller) inspectionController.current = null
      }
    }
  }

  const inspectionResult = visibleInspection.result
  const inspectionPending = visibleInspection.pending
  const presentation = inspectionPresentation(inspectionResult, visibleInspection.error)

  return <section className="http-endpoint-panel" aria-labelledby={`http-endpoint-heading-${device?.id}`}>
    <div className="http-endpoint-heading">
      <div><p className="panel-kicker">Endpoint evidence</p><h4 id={`http-endpoint-heading-${device?.id}`}>HTTP / HTTPS inspection</h4></div>
    </div>
    <p className="recon-muted">Inspect one existing open TCP port. Requests are explicit and results are stored in endpoint history when persistence succeeds.</p>
    {choices.length === 0 ? <p className="recon-muted">No open TCP ports are available for inspection.</p> : <div className="http-endpoint-controls">
      <label className="recon-field">Observed TCP port
        <select value={portId} disabled={inspectionPending} onChange={(event) => choosePort(event.target.value)}>
          <option value="">Select a port</option>
          {choices.map((item) => <option key={item.id} value={item.id}>{item.port_number}/TCP · {item.state}</option>)}
        </select>
      </label>
      <label className="recon-field">Scheme
        <select value={scheme} disabled={inspectionPending} onChange={(event) => setScheme(event.target.value)}>
          <option value="http">HTTP</option>
          <option value="https">HTTPS</option>
        </select>
      </label>
      <button type="button" disabled={!port || !authorizationConfirmed || inspectionPending}
        onClick={inspect}>{inspectionPending ? 'Inspecting…' : 'Inspect selected port'}</button>
    </div>}
    {!authorizationConfirmed && <p className="http-endpoint-hint">Confirm the authorized assessment in Step 1 before inspecting.</p>}
    {inspectionPending && <p className="recon-muted" role="status">Inspection in progress. Do not repeat this request.</p>}
    {presentation && <div className={`http-endpoint-result http-endpoint-result-${presentation.tone}`} role={presentation.tone === 'error' ? 'alert' : 'status'}>
      <strong>{presentation.title}</strong><span>{presentation.message}</span>
      {inspectionResult?.status_code !== null && inspectionResult?.status_code !== undefined && <span>HTTP status: {inspectionResult.status_code}</span>}
      {inspectionResult?.persistence?.status === 'PERSISTED' && <span>Stored observation #{inspectionResult.persistence.observation_id} · run {inspectionResult.persistence.scan_run_id}</span>}
      {inspectionResult?.persistence?.status === 'NOT_ATTEMPTED' && <span>Persistence was not attempted.</span>}
    </div>}
    {port && <HttpEndpointHistory key={`${endpointKey}:${historyReload}`} scopeId={scopeId}
      deviceId={device.id} port={port} reloadToken={historyReload}/>}
  </section>
}

export default HttpEndpointInspection
