import { useEffect, useRef, useState } from 'react'
import ReconEvidence from './ReconEvidence.jsx'
import '../recon03-evidence.css'
import {
  discoverNetwork, discoverPublicScope, discoverDeviceServices, discoverScopeDeviceServices,
  loadDeviceReview, loadNetworkDevices, loadNetworks, loadScopeDevices, loadScopes,
} from '../services/networkApi.js'
import { canScanPublicCidr } from '../services/publicCidrState.js'
import { availableAssessmentScopes, isAssessmentScopeAllowed } from '../services/reconAssessmentState.js'

const defensiveActions = [
  { title: 'Threat detections', text: 'Review established security signals and correlations.', button: 'Open Detections', destination: 'detections' },
  { title: 'Incident reviews', text: 'Investigate evidence and document analyst decisions.', button: 'Open Operations', destination: 'operations' },
  { title: 'Remote sensors', text: 'Inspect enrolled sensors and existing task workflows.', button: 'Open Sensors', destination: 'remote-sensors' },
  { title: 'Event reports', text: 'Review the event timeline and export available records.', button: 'Open Reports', destination: 'events-analytics' },
]

function ReconLab({ active, onNavigate }) {
  const [mode, setMode] = useState('offensive')
  const [stage, setStage] = useState('setup')
  const [scopes, setScopes] = useState([])
  const [networks, setNetworks] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [devices, setDevices] = useState([])
  const [deviceId, setDeviceId] = useState('')
  const [review, setReview] = useState(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const generation = useRef(0)
  const running = useRef(false)

  useEffect(() => {
    if (!active) return undefined
    const controller = new AbortController()
    const version = ++generation.current
    setLoading(true)
    setError('')
    Promise.all([loadScopes(controller.signal), loadNetworks(controller.signal)])
      .then(([scopeData, networkData]) => {
        if (version !== generation.current) return
        setScopes(Array.isArray(scopeData) ? scopeData : [])
        setNetworks(Array.isArray(networkData) ? networkData : [])
      })
      .catch((err) => { if (version === generation.current && err.name !== 'AbortError') setError(err.message) })
      .finally(() => { if (version === generation.current) setLoading(false) })
    return () => { controller.abort(); generation.current += 1 }
  }, [active])

  const choices = availableAssessmentScopes(scopes, networks, canScanPublicCidr)
  const selected = choices.find((item) => item.key === selectedId)
  const allowScan = selected && isAssessmentScopeAllowed(selected.scope, selected.network, canScanPublicCidr)

  function chooseScope(value) {
    generation.current += 1
    setSelectedId(value)
    setStage('setup')
    setConfirmed(false)
    setDevices([])
    setDeviceId('')
    setReview(null)
    setMessage('')
    setError('')
  }

  async function executeScan() {
    if (running.current || !confirmed || !selected || !allowScan) return
    const version = ++generation.current
    running.current = true
    setBusy('scan')
    setError('')
    setMessage('')
    setDevices([])
    setDeviceId('')
    setReview(null)
    try {
      const outcome = selected.scope.scope_type === 'PRIVATE_NETWORK'
        ? await discoverNetwork(selected.network.id)
        : await discoverPublicScope(selected.scope.id)
      if (version !== generation.current) return
      const rows = Array.isArray(outcome?.devices) ? outcome.devices : outcome?.device ? [outcome.device] : []
      setDevices(rows)
      setStage('results')
      setMessage(`Scan complete. ${rows.length} device${rows.length === 1 ? '' : 's'} found. Review the results before drawing conclusions.`)
    } catch (err) {
      if (version === generation.current) setError(err.message)
    } finally {
      running.current = false
      if (version === generation.current) setBusy('')
    }
  }

  async function showDevices() {
    if (running.current || !selected) return
    const version = ++generation.current
    running.current = true
    setBusy('inventory')
    setError('')
    setMessage('')
    setDeviceId('')
    setReview(null)
    try {
      const rows = selected.scope.scope_type === 'PRIVATE_NETWORK'
        ? await loadNetworkDevices(selected.network.id)
        : await loadScopeDevices(selected.scope.id)
      if (version === generation.current) {
        setDevices(Array.isArray(rows) ? rows : Array.isArray(rows?.devices) ? rows.devices : [])
        setStage('results')
        setMessage('Previous results loaded. No new scan was started.')
      }
    } catch (err) { if (version === generation.current) setError(err.message) }
    finally { running.current = false; if (version === generation.current) setBusy('') }
  }

  async function selectDevice(id) {
    if (running.current) return
    const version = ++generation.current
    running.current = true
    setBusy('review')
    setError('')
    setDeviceId(String(id))
    setReview(null)
    setStage('results')
    try {
      const result = await loadDeviceReview(id)
      if (version === generation.current) setReview(result)
    } catch (err) { if (version === generation.current) setError(err.message) }
    finally { running.current = false; if (version === generation.current) setBusy('') }
  }

  async function scanServices() {
    if (running.current || !selected || !review?.device?.id || !confirmed || !allowScan) return
    const version = ++generation.current
    running.current = true
    setBusy('services')
    setError('')
    try {
      if (selected.scope.scope_type === 'PRIVATE_NETWORK') await discoverDeviceServices(review.device.id)
      else await discoverScopeDeviceServices(selected.scope.id, review.device.id)
      if (version !== generation.current) return
      const updated = await loadDeviceReview(review.device.id)
      if (version === generation.current) {
        setReview(updated)
        setMessage('Service discovery completed. Review the recorded evidence below.')
      }
    } catch (err) { if (version === generation.current) setError(err.message) }
    finally { running.current = false; if (version === generation.current) setBusy('') }
  }

  return <div className="recon-lab recon-compact">
    <div className="recon-intro">
      <div className="recon-intro-top"><div><p className="panel-kicker">Security workspace</p><h3>Recon Lab</h3></div>
        <div className="recon-modes" role="group" aria-label="Security workflow mode">
          <button type="button" className="recon-mode" aria-pressed={mode === 'offensive'} onClick={() => setMode('offensive')}>Offensive · Security checks</button>
          <button type="button" className="recon-mode" aria-pressed={mode === 'defensive'} onClick={() => setMode('defensive')}>Defensive · Threat review</button>
        </div>
      </div>
    </div>
    {mode === 'offensive' ? <>
      <nav className="recon-tabs" aria-label="Assessment steps">
        <button type="button" aria-current={stage === 'setup' ? 'step' : undefined} className={stage === 'setup' ? 'recon-tab active' : 'recon-tab'} onClick={() => setStage('setup')}>1. Set up scan</button>
        <button type="button" aria-current={stage === 'results' ? 'step' : undefined} className={stage === 'results' ? 'recon-tab active' : 'recon-tab'} onClick={() => setStage('results')}>2. Results {devices.length ? `(${devices.length})` : ''}</button>
        <button type="button" aria-current={stage === 'report' ? 'step' : undefined} className={stage === 'report' ? 'recon-tab active' : 'recon-tab'} onClick={() => setStage('report')}>3. Reports</button>
      </nav>
      {stage !== 'setup' && error && <p className="recon-error" role="alert">{error}</p>}
      {stage !== 'setup' && busy && <p role="status" className="recon-muted">{busy === 'scan' ? 'Scanning the target…' : busy === 'inventory' ? 'Loading devices…' : busy === 'services' ? 'Checking services…' : 'Loading device details…'}</p>}
      {stage !== 'setup' && message && <p role="status" className="recon-success">{message}</p>}
      {stage === 'setup' && <>
      <section className="recon-scopes" aria-labelledby="recon-setup-heading">
        <div className="recon-section-heading"><div><p className="panel-kicker">Step 1</p><h3 id="recon-setup-heading">Choose a network or host</h3></div><button type="button" className="recon-secondary" onClick={() => onNavigate('scope-discovery')}>Add or Manage Targets</button></div>
        <p className="recon-muted">Choose a network or host you have permission to check.</p>
        {loading ? <p role="status">Loading authorized targets…</p> : null}
        {!loading && error && <p className="recon-error" role="alert">{error}</p>}
        <div className="recon-form-grid"><label className="recon-field">Network or host
          <select value={selectedId} disabled={loading || Boolean(busy)} onChange={(event) => chooseScope(event.target.value)}>
            <option value="">Select a network or host</option>
            {choices.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}
          </select>
        </label><div className="recon-target-hint"><strong>Selected address</strong><span>{selected?.scope.canonical_target || 'Nothing selected'}</span><small>{selected ? 'Authorized and enabled' : 'Choose a network or host'}</small></div></div>
        {!loading && choices.length === 0 && <p className="recon-muted">No approved targets available. Use Add or Manage Targets.</p>}
        {selected && <label className="recon-confirm"><input type="checkbox" checked={confirmed} disabled={Boolean(busy)} onChange={(event) => setConfirmed(event.target.checked)}/><span>I have permission to check this target.</span></label>}
        <div className="recon-actions"><button type="button" disabled={!selected || Boolean(busy)} onClick={showDevices}>View Previous Results</button><button type="button" disabled={!selected || !confirmed || !allowScan || Boolean(busy)} onClick={executeScan}>{busy === 'scan' ? 'Scanning…' : 'Start Scan'}</button></div>
        {busy && <p role="status" className="recon-muted">{busy === 'scan' ? 'Running authorized host discovery…' : busy === 'inventory' ? 'Loading saved devices…' : busy === 'services' ? 'Scanning selected device services…' : 'Loading device evidence…'}</p>}
        {message && <p role="status" className="recon-success">{message}</p>}
      </section>
      </>}
      {stage === 'results' && <>
      <section className="recon-scopes" aria-labelledby="recon-results-heading">
        <div className="recon-section-heading"><div><p className="panel-kicker">Step 2</p><h3 id="recon-results-heading">Devices and findings</h3></div><span className="recon-count">{devices.length} shown</span></div>
        {devices.length === 0 ? <p className="recon-muted">Select a target and start a scan or open its previous results.</p> : <div className="recon-device-list">{devices.map((item) => <button key={item.id} type="button" className={String(item.id) === deviceId ? 'recon-device selected' : 'recon-device'} disabled={Boolean(busy)} onClick={() => selectDevice(item.id)}><strong>{item.last_ip_address || `Device #${item.id}`}</strong><span>{item.hostname || item.vendor || 'Unknown device'}</span><small>{item.status || 'Observed'}</small></button>)}</div>}
        {busy === 'review' && <p role="status">Loading evidence…</p>}
        {review && <div className="recon-evidence">
          <div className="recon-section-heading"><div><h3>Device details</h3><p className="recon-muted">{review.device?.last_ip_address || 'Selected device'}</p></div><button type="button" disabled={!confirmed || !allowScan || Boolean(busy)} onClick={scanServices}>{busy === 'services' ? 'Scanning…' : 'Scan Services'}</button></div>
          <div className="recon-evidence-grid">
            <section><h4>Ports ({review.ports?.length || 0})</h4>{review.ports?.length ? review.ports.map((x) => <p key={x.id}>{x.port_number}/{x.transport} · {x.state}</p>) : <p>No recorded ports.</p>}</section>
            <section><h4>Services ({review.services?.length || 0})</h4>{review.services?.length ? review.services.map((x) => <p key={x.id}>{x.service_name || 'Unknown'} · {[x.product, x.version].filter(Boolean).join(' ') || 'Unknown version'}</p>) : <p>No recorded services.</p>}</section>
            <section><h4>Findings ({review.findings?.length || 0})</h4>{review.findings?.length ? review.findings.map((x) => <p key={x.id}><strong>{x.title}</strong> · {x.severity} · {x.status}<small>{x.reason}</small></p>) : <p>No findings recorded.</p>}</section>
            <section><h4>CVE matches ({review.cveMatches?.length || 0})</h4>{review.cveMatches?.length ? review.cveMatches.map((x) => <p key={x.id}>{x.cve_id || `Match #${x.id}`} · {x.match_status || x.status || 'Requires review'}</p>) : <p>No CVE matches recorded.</p>}</section>
          </div><ReconEvidence deviceId={review.device.id} findings={review.findings || []}/><p className="recon-muted">CVE matches need to be verified before being described as confirmed vulnerabilities.</p>
        </div>}
      </section>
      </>}
      {stage === 'report' && <>
      <section className="recon-next-steps" aria-labelledby="recon-report-heading">
        <div className="recon-section-heading"><div><p className="panel-kicker">Step 3</p><h3 id="recon-report-heading">Reports and next steps</h3></div></div>
        <p className="recon-muted">Review the findings before sharing them. You can download event reports now.</p>
        <div className="recon-grid">
          <article className="recon-card"><h3>Network exposure</h3><p>See available information about exposed services.</p><button type="button" onClick={() => onNavigate('perimeter')}>View Exposure</button></article>
          <article className="recon-card"><h3>Available reports</h3><p>Download recorded event information as PDF, CSV or JSON.</p><button type="button" onClick={() => onNavigate('events-analytics')}>Open Reports</button></article>
        </div>
      </section>
      </>}
    </> : <div className="recon-grid recon-defensive-grid">{defensiveActions.map((action) => <article className="recon-card" key={action.title}><h3>{action.title}</h3><p>{action.text}</p><button type="button" onClick={() => onNavigate(action.destination)}>{action.button}</button></article>)}</div>}
  </div>
}

export default ReconLab
