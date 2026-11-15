import { useEffect, useMemo, useRef, useState } from 'react'
import ReconEvidence from './ReconEvidence.jsx'
import '../recon03-evidence.css'
import {
  discoverNetwork, discoverPublicScope, discoverDeviceServices, discoverScopeDeviceServices,
  loadDeviceReview, loadNetworkDevices, loadNetworks, loadScopeDevices, loadScopes,
} from '../services/networkApi.js'
import { canScanPublicCidr } from '../services/publicCidrState.js'
import { availableAssessmentScopes, isAssessmentScopeAllowed } from '../services/reconAssessmentState.js'
import { downloadAssessmentReport, loadAssessmentReport, triggerAssessmentReportDownload } from '../services/reconAssessmentReportApi.js'
import { assessmentDeviceInventory, assessmentDisplayValue, assessmentFindingContext, assessmentObservationSummary, assessmentSummaryScrollBehavior, toggleExpandedAssessmentDevice } from '../services/reconAssessmentReportView.js'

const defensiveActions = [
  { title: 'Threat detections', text: 'Review established security signals and correlations.', button: 'Open Detections', destination: 'detections' },
  { title: 'Incident reviews', text: 'Investigate evidence and document analyst decisions.', button: 'Open Operations', destination: 'operations' },
  { title: 'Remote sensors', text: 'Inspect enrolled sensors and existing task workflows.', button: 'Open Sensors', destination: 'remote-sensors' },
  { title: 'Event reports', text: 'Review the event timeline and export available records.', button: 'Open Reports', destination: 'events-analytics' },
]

function ReportDownloadActions({ placement, busy, onDownload }) {
  return <div className={`recon-report-downloads recon-report-downloads-${placement}`} aria-label={`Download assessment report ${placement}`}>
    <button type="button" disabled={Boolean(busy)} onClick={() => onDownload('pdf')}>{busy === 'pdf' ? 'Preparing PDF…' : 'Download PDF'}</button>
    <button type="button" disabled={Boolean(busy)} onClick={() => onDownload('docx')}>{busy === 'docx' ? 'Preparing Word…' : 'Download Word'}</button>
    <button type="button" disabled={Boolean(busy)} onClick={() => onDownload('html')}>{busy === 'html' ? 'Preparing HTML…' : 'Download HTML'}</button>
  </div>
}

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
  const [report, setReport] = useState(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError, setReportError] = useState('')
  const [reportDownloadError, setReportDownloadError] = useState('')
  const [reportDownloadBusy, setReportDownloadBusy] = useState('')
  const [expandedDeviceIds, setExpandedDeviceIds] = useState(() => new Set())
  const [showAllObservations, setShowAllObservations] = useState(false)
  const generation = useRef(0)
  const reportGeneration = useRef(0)
  const reportSummaryRef = useRef(null)
  const running = useRef(false)

  useEffect(() => {
    if (!active) return undefined
    const controller = new AbortController()
    const version = ++generation.current
    Promise.resolve().then(async () => {
      if (controller.signal.aborted) return
      setLoading(true)
      setError('')
      try {
        const [scopeData, networkData] = await Promise.all([loadScopes(controller.signal), loadNetworks(controller.signal)])
        if (version !== generation.current) return
        setScopes(Array.isArray(scopeData) ? scopeData : [])
        setNetworks(Array.isArray(networkData) ? networkData : [])
      } catch (err) { if (version === generation.current && err.name !== 'AbortError') setError(err.message) }
      finally { if (version === generation.current) setLoading(false) }
    })
    return () => { controller.abort(); generation.current += 1 }
  }, [active])

  const choices = useMemo(() => availableAssessmentScopes(scopes, networks, canScanPublicCidr), [scopes, networks])
  const selected = choices.find((item) => item.key === selectedId)
  const allowScan = selected && isAssessmentScopeAllowed(selected.scope, selected.network, canScanPublicCidr)

  useEffect(() => {
    if (!active || stage !== 'report' || !selected || !allowScan) return undefined
    const controller = new AbortController()
    const version = ++reportGeneration.current
    const scopeId = selected.scope.id
    Promise.resolve().then(async () => {
      if (controller.signal.aborted) return
      setReportLoading(true)
      setReportError('')
      try {
        const result = await loadAssessmentReport(scopeId, controller.signal)
        if (version === reportGeneration.current && !controller.signal.aborted) setReport(result)
      } catch (err) {
        if (version === reportGeneration.current && err.name !== 'AbortError') {
          setReport(null)
          setReportError(err.message)
        }
      } finally {
        if (version === reportGeneration.current) setReportLoading(false)
      }
    })
    return () => { controller.abort(); reportGeneration.current += 1 }
  }, [active, stage, selected, allowScan])

  async function downloadReport(format) {
    if (!selected || !allowScan || reportDownloadBusy) return
    setReportDownloadError('')
    setReportDownloadBusy(format)
    try {
      const result = await downloadAssessmentReport(selected.scope.id, format)
      triggerAssessmentReportDownload(result.blob, result.filename)
    } catch (err) {
      if (err.name !== 'AbortError') setReportDownloadError(err.message)
    } finally { setReportDownloadBusy('') }
  }

  function scrollToReportSummary() {
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches === true
    reportSummaryRef.current?.scrollIntoView({ behavior: assessmentSummaryScrollBehavior(reduceMotion), block: 'start' })
  }

  function chooseScope(value) {
    generation.current += 1
    setSelectedId(value)
    setStage('setup')
    setConfirmed(false)
    setDevices([])
    setDeviceId('')
    setReview(null)
    setReport(null)
    setReportError('')
    setReportDownloadError('')
    setExpandedDeviceIds(new Set())
    setShowAllObservations(false)
    setMessage('')
    setError('')
  }

  function chooseReportScope(value) {
    if (value === selectedId) return
    generation.current += 1
    setSelectedId(value)
    setConfirmed(false)
    setDevices([])
    setDeviceId('')
    setReview(null)
    setReport(null)
    setReportError('')
    setReportDownloadError('')
    setExpandedDeviceIds(new Set())
    setShowAllObservations(false)
    setMessage('')
    setError('')
  }

  function openReports() {
    setReport(null)
    setReportError('')
    setReportDownloadError('')
    setExpandedDeviceIds(new Set())
    setShowAllObservations(false)
    setStage('report')
  }

  function toggleDeviceDetails(deviceId) {
    setExpandedDeviceIds((current) => toggleExpandedAssessmentDevice(current, deviceId))
  }

  const storedObservations = report?.scan_metadata?.observations || []
  const observationSummary = assessmentObservationSummary(storedObservations)

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
        <button type="button" aria-current={stage === 'report' ? 'step' : undefined} className={stage === 'report' ? 'recon-tab active' : 'recon-tab'} onClick={openReports}>3. Reports</button>
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
          </div><ReconEvidence key={review.device.id} deviceId={review.device.id} device={review.device} ports={review.ports || []} services={review.services || []} findings={review.findings || []}/><p className="recon-muted">CVE matches need to be verified before being described as confirmed vulnerabilities.</p>
        </div>}
      </section>
      </>}
      {stage === 'report' && <>
      <section className="recon-next-steps recon-assessment-report" aria-labelledby="recon-report-heading">
        <div className="recon-section-heading"><div><p className="panel-kicker">Step 3</p><h3 id="recon-report-heading">Assessment report</h3></div></div>
        <label className="recon-field">Authorized assessment
          <select aria-label="Authorized assessment" value={selectedId} disabled={loading || Boolean(reportDownloadBusy)} onChange={(event) => chooseReportScope(event.target.value)}>
            <option value="">Select an authorized target</option>
            {choices.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}
          </select>
        </label>
        {loading && <p role="status" className="recon-muted">Loading authorized targets…</p>}
        {!loading && choices.length === 0 && <p className="recon-muted">No authorized targets are available.</p>}
        {reportLoading && selected && <p role="status" className="recon-muted">Loading assessment report…</p>}
        {reportError && <p role="alert" className="recon-error">{reportError}</p>}
        {reportDownloadError && <p role="alert" className="recon-error">{reportDownloadError}</p>}
        {selected && !reportLoading && !reportError && report?.assessment?.scope_id === selected.scope.id && <>
          <div className="recon-report-heading" ref={reportSummaryRef}><div><h4>{report.assessment.name || 'Authorized target'}</h4><p>{report.assessment.target}</p></div><small>Generated {report.generated_at}</small></div>
          <p className="recon-report-note">This is a snapshot of stored assessment evidence. Historical observations and inventory status do not confirm current reachability or security.</p>
          <ReportDownloadActions placement="top" busy={reportDownloadBusy} onDownload={downloadReport}/>
          <div className="recon-report-metrics" aria-label="Assessment coverage">
            <div><strong>{report.coverage.discovered_assets ?? report.devices.length}</strong><span>Discovered devices</span></div>
            <div><strong>{report.coverage.assets_with_service_evidence ?? 0}</strong><span>With service evidence</span></div>
            <div><strong>{report.coverage.assets_without_service_evidence ?? 0}</strong><span>Without service evidence</span></div>
            <div><strong>{report.coverage.potential_vulnerabilities ?? 0}</strong><span>Potential vulnerabilities</span></div>
            <div><strong>{report.coverage.confirmed_findings ?? 0}</strong><span>Confirmed findings</span></div>
            <div><strong>{report.coverage.unverified_cve_matches ?? 0}</strong><span>Unverified CVE matches</span></div>
            <div><strong>{report.devices.reduce((count, item) => count + (item.evidence?.length || 0), 0)}</strong><span>Stored evidence items</span></div>
          </div>
          {report.coverage.assets_without_service_evidence > 0 && <p className="recon-report-warning">Service coverage is incomplete for {report.coverage.assets_without_service_evidence} device(s).</p>}
          {report.coverage.data_incomplete && <p className="recon-report-warning">Some stored report data is unavailable or truncated.</p>}
          <section className="recon-report-section recon-report-finding-summary"><h4>Findings</h4><p>{report.findings.length} finding{report.findings.length === 1 ? '' : 's'} recorded. Expand a device to review finding severity, status, verification and service context.</p></section>
          <div className="recon-report-devices"><div className="recon-report-inventory-heading"><h4>Discovered devices</h4><span>{report.devices.length} asset{report.devices.length === 1 ? '' : 's'}</span></div>
            {report.devices.length === 0 ? <p className="recon-muted">No devices are recorded for this assessment.</p> : report.devices.map((item) => {
              const inventory = assessmentDeviceInventory(item)
              const expanded = expandedDeviceIds.has(inventory.id)
              const panelId = `recon-report-device-details-${report.assessment.scope_id}-${inventory.id}`
              return <article className="recon-report-device" key={inventory.id}>
                <div className="recon-report-device-row">
                  <div className="recon-report-device-identity"><strong>{inventory.ipAddress}</strong><span>{inventory.identity}</span></div>
                  <div className="recon-report-device-status"><small>Recorded inventory status</small><span>{inventory.status}</span></div>
                  <div className="recon-report-device-counts"><span><strong>{inventory.portCount}</strong> ports</span><span><strong>{inventory.serviceCount}</strong> services</span><span><strong>{inventory.findingCount}</strong> findings</span><span><strong>{inventory.evidenceCount}</strong> evidence items</span></div>
                  <button type="button" className="recon-report-expand" aria-expanded={expanded} aria-controls={panelId} onClick={() => toggleDeviceDetails(inventory.id)}>{expanded ? 'Collapse' : 'Expand'}</button>
                </div>
                <div className="recon-report-device-details" id={panelId} hidden={!expanded}>
                  {expanded && <>
                  <section><h5>Ports and services</h5>
                    {item.ports.length || item.services.length ? <ul>{item.ports.map((port) => {
                      const service = item.services.find((entry) => entry.port_id === port.id)
                      const serviceText = service ? [service.service_name, service.product, service.version].filter(Boolean).join(' ') : ''
                      return <li key={`port-${port.id}`}>{port.port_number}/{port.transport}{port.state ? ` · ${assessmentDisplayValue(port.state)}` : ''}{serviceText ? ` · ${serviceText}` : ''}</li>
                    })}{item.services.filter((service) => !item.ports.some((port) => port.id === service.port_id)).map((service) => <li key={`service-${service.id}`}>{[service.service_name, service.product, service.version].filter(Boolean).join(' ')}</li>)}</ul> : <p>No port or service observations are recorded. Service coverage is incomplete.</p>}
                  </section>
                  <section><h5>Findings</h5>
                    {item.findings.length ? <div className="recon-report-device-findings">{item.findings.map((finding) => {
                      const context = assessmentFindingContext(item, finding)
                      return <article key={finding.id}><strong>{context.title}</strong><span>{context.ipAddress} · {context.severity} · {context.lifecycleStatus} · Verification: {context.verificationStatus}</span><small>{context.port || 'Port not recorded'}{context.service ? ` · ${context.service}` : ''}</small>{context.description && <p>{context.description}</p>}</article>
                    })}</div> : <p>No findings are recorded. This does not establish that the device is secure.</p>}
                  </section>
                  <section><h5>CVE matches</h5>
                    {item.cve_matches.length ? <ul>{item.cve_matches.map((match) => <li key={match.id}>{match.cve_id || `CVE match #${match.id}`} · {assessmentDisplayValue(match.match_status)} · Potential match, not verified</li>)}</ul> : <p>No CVE matches are recorded.</p>}
                  </section>
                  <section><h5>Stored evidence</h5>
                    {item.evidence.length ? <ul>{item.evidence.map((evidence) => <li key={evidence.id}>{evidence.description || evidence.filename}{evidence.finding_id ? ` · Finding #${evidence.finding_id}` : ' · Device evidence'}{evidence.created_at ? ` · Stored ${evidence.created_at}` : ''}</li>)}</ul> : <p>No stored evidence is available for this device.</p>}
                  </section>
                  </>}
                </div>
              </article>
            })}
          </div>
          <section className="recon-report-section"><h4>Recommendations</h4>{report.recommendations.length ? <ul>{report.recommendations.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul> : <p className="recon-muted">No finding-backed recommendations are recorded.</p>}</section>
          <section className="recon-report-section recon-report-observations"><h4>Stored observations</h4>
            {storedObservations.length ? <><p>{observationSummary.count} historical observation{observationSummary.count === 1 ? '' : 's'} · Latest {observationSummary.latestAt || 'timestamp not recorded'}</p><button type="button" className="recon-report-expand" aria-expanded={showAllObservations} aria-controls="recon-report-observation-history" onClick={() => setShowAllObservations((current) => !current)}>{showAllObservations ? 'Hide' : `Show all (${storedObservations.length})`}</button>
              <ul id="recon-report-observation-history" hidden={!showAllObservations}>{showAllObservations && storedObservations.map((item, index) => <li key={`${item.device_id}-${index}`}>Device #{item.device_id} · {item.latest_observed_at || 'Timestamp not recorded'} · {(item.sources || []).join(', ') || 'Source not recorded'}</li>)}</ul>
            </> : <p className="recon-muted">No historical scan observations are recorded.</p>}
          </section>
          <section className="recon-report-section"><h4>Coverage and limitations</h4><p>{report.coverage.data_incomplete ? 'Some report data is incomplete.' : 'No report truncation is recorded.'}</p>{report.coverage.limitations?.length ? <ul>{report.coverage.limitations.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul> : null}</section>
          <div className="recon-report-bottom-actions"><ReportDownloadActions placement="bottom" busy={reportDownloadBusy} onDownload={downloadReport}/><button type="button" className="recon-report-expand" onClick={scrollToReportSummary}>Back to Summary</button></div>
        </>}
        {!reportError && !selected && <p className="recon-muted">Select an authorized target to view its stored assessment report.</p>}
      </section>
      </>}
    </> : <div className="recon-grid recon-defensive-grid">{defensiveActions.map((action) => <article className="recon-card" key={action.title}><h3>{action.title}</h3><p>{action.text}</p><button type="button" onClick={() => onNavigate(action.destination)}>{action.button}</button></article>)}</div>}
  </div>
}

export default ReconLab
