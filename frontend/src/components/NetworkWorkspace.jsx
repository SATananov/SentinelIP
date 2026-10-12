import {
  useCallback,
  useEffect,
  useState,
} from 'react'

import {
  createPublicIPv4Scope,
  discoverDeviceServices,
  discoverNetworkCandidates,
  discoverNetwork,
  discoverPublicScope,
  discoverScopeDeviceServices,
  loadDeviceReview,
  loadNetworkDevices,
  loadNetworks,
  loadScopeDevices,
  loadScopes,
} from '../services/networkApi.js'

const PUBLIC_AUTHORIZATION_VERSION = 'public_ipv4_authorization_v1'

function isIPv4Address(value) {
  const parts = value.trim().split('.')
  return parts.length === 4 && parts.every((part) => (
    /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
  ))
}

function DeviceStatus({ value }) {
  const normalized = String(value ?? 'UNKNOWN').toLowerCase()

  return (
    <span className={`network-status network-status-${normalized}`}>
      {value ?? 'UNKNOWN'}
    </span>
  )
}

function NetworkWorkspace() {
  const [networks, setNetworks] = useState([])
  const [scopes, setScopes] = useState([])
  const [selectedPublicScopeId, setSelectedPublicScopeId] = useState(null)
  const [publicTarget, setPublicTarget] = useState('')
  const [publicTargetName, setPublicTargetName] = useState('')
  const [publicTargetDescription, setPublicTargetDescription] = useState('')
  const [publicAuthorizationConfirmed, setPublicAuthorizationConfirmed] = useState(false)
  const [networkCandidates, setNetworkCandidates] = useState([])
  const [selectedNetworkId, setSelectedNetworkId] = useState(null)
  const [devices, setDevices] = useState([])
  const [selectedDeviceId, setSelectedDeviceId] = useState(null)
  const [deviceReview, setDeviceReview] = useState(null)

  const [loading, setLoading] = useState(true)
  const [scanLoading, setScanLoading] = useState(false)
  const [deviceLoading, setDeviceLoading] = useState(false)
  const [serviceScanLoading, setServiceScanLoading] = useState(false)
  const [error, setError] = useState(null)
  const [deviceError, setDeviceError] = useState(null)
  const [candidateLoading, setCandidateLoading] = useState(false)
  const [candidateError, setCandidateError] = useState(null)
  const [publicScopeLoading, setPublicScopeLoading] = useState(false)
  const [publicScopeError, setPublicScopeError] = useState(null)

  const loadWorkspace = useCallback(async (signal) => {
    setLoading(true)
    setError(null)

    try {
      const [networkData, scopeData] = await Promise.all([
        loadNetworks(signal),
        loadScopes(signal),
      ])
      setNetworks(networkData)
      setScopes(scopeData)

      if (networkData.length === 0) {
        setSelectedNetworkId(null)
        setDevices([])
        return
      }

      const firstNetwork = networkData[0]
      const deviceData = await loadNetworkDevices(firstNetwork.id, signal)

      setSelectedNetworkId(firstNetwork.id)
      setDevices(deviceData)
    } catch (err) {
      if (err.name !== 'AbortError') {
        setError(err.message)
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    const timer = setTimeout(() => {
      loadWorkspace(controller.signal)
    }, 0)

    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [loadWorkspace])

  async function selectNetwork(event) {
    const networkId = Number(event.target.value)

    setSelectedPublicScopeId(null)
    setSelectedNetworkId(networkId)
    setDevices([])
    setSelectedDeviceId(null)
    setDeviceReview(null)
    setDeviceError(null)
    setLoading(true)
    setError(null)

    try {
      const deviceData = await loadNetworkDevices(networkId)
      setDevices(deviceData)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function scanNetwork() {
    if (!selectedNetworkId) {
      return
    }

    setScanLoading(true)
    setError(null)

    try {
      const result = await discoverNetwork(selectedNetworkId)
      setDevices(result.devices)

      if (
        selectedDeviceId &&
        !result.devices.some((device) => device.id === selectedDeviceId)
      ) {
        setSelectedDeviceId(null)
        setDeviceReview(null)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setScanLoading(false)
    }
  }

  async function selectDevice(deviceId) {
    setSelectedDeviceId(deviceId)
    setDeviceReview(null)
    setDeviceLoading(true)
    setDeviceError(null)

    try {
      const result = await loadDeviceReview(deviceId)
      setDeviceReview(result)
    } catch (err) {
      setDeviceError(err.message)
    } finally {
      setDeviceLoading(false)
    }
  }

  async function scanServices() {
    if (!selectedDeviceId) {
      return
    }

    setServiceScanLoading(true)
    setDeviceError(null)

    try {
      if (selectedPublicScopeId) {
        await discoverScopeDeviceServices(selectedPublicScopeId, selectedDeviceId)
      } else {
        await discoverDeviceServices(selectedDeviceId)
      }
      const result = await loadDeviceReview(selectedDeviceId)
      setDeviceReview(result)
    } catch (err) {
      setDeviceError(err.message)
    } finally {
      setServiceScanLoading(false)
    }
  }

  async function refreshNetworkCandidates() {
    setCandidateLoading(true)
    setCandidateError(null)

    try {
      const candidates = await discoverNetworkCandidates()
      setNetworkCandidates(candidates)
    } catch (err) {
      setCandidateError(err.message)
    } finally {
      setCandidateLoading(false)
    }
  }

  async function addPublicTarget(event) {
    event.preventDefault()
    if (!isIPv4Address(publicTarget) || !publicAuthorizationConfirmed) return

    setPublicScopeLoading(true)
    setPublicScopeError(null)
    try {
      const scope = await createPublicIPv4Scope({
        target: publicTarget.trim(),
        name: publicTargetName.trim(),
        description: publicTargetDescription.trim(),
        authorization_confirmed: true,
        authorization_confirmation_version: PUBLIC_AUTHORIZATION_VERSION,
      })
      setScopes((current) => [...current, scope])
      setPublicTarget('')
      setPublicTargetName('')
      setPublicTargetDescription('')
      setPublicAuthorizationConfirmed(false)
      setSelectedPublicScopeId(scope.id)
      setSelectedNetworkId(null)
      setDevices([])
      setSelectedDeviceId(null)
      setDeviceReview(null)
    } catch (err) {
      setPublicScopeError(err.message)
    } finally {
      setPublicScopeLoading(false)
    }
  }

  async function selectPublicTarget(scopeId) {
    setSelectedPublicScopeId(scopeId)
    setSelectedNetworkId(null)
    setDevices([])
    setSelectedDeviceId(null)
    setDeviceReview(null)
    setLoading(true)
    setError(null)
    try {
      setDevices(await loadScopeDevices(scopeId))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function scanPublicTarget(scopeId) {
    setSelectedPublicScopeId(scopeId)
    setSelectedNetworkId(null)
    setScanLoading(true)
    setError(null)
    setDeviceError(null)
    setSelectedDeviceId(null)
    setDeviceReview(null)
    try {
      const result = await discoverPublicScope(scopeId)
      const nextDevices = result.device ? [result.device] : []
      setDevices(nextDevices)
      if (nextDevices.length > 0) {
        const review = await loadDeviceReview(nextDevices[0].id)
        setSelectedDeviceId(nextDevices[0].id)
        setDeviceReview(review)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setScanLoading(false)
    }
  }

  const selectedNetwork = networks.find(
    (network) => network.id === selectedNetworkId,
  )
  const selectedScope = scopes.find(
    (scope) => scope.network_id === selectedNetworkId,
  )
  const publicTargets = scopes.filter((scope) => scope.scope_type === 'PUBLIC_IPV4')
  const selectedPublicScope = publicTargets.find(
    (scope) => scope.id === selectedPublicScopeId,
  )
  const scopeAllowsScan = Boolean(
    selectedNetwork?.authorized === true &&
    selectedNetwork?.enabled === true &&
    selectedScope?.scope_type === 'PRIVATE_NETWORK' &&
    selectedScope?.canonical_target === selectedNetwork?.cidr &&
    selectedScope?.authorized === true &&
    selectedScope?.enabled === true &&
    selectedScope?.authorization_confirmed_at &&
    selectedScope?.authorization_confirmation_version &&
    selectedScope?.authorization_source,
  )
  const publicScopeAllowsScan = Boolean(
    selectedPublicScope?.scope_type === 'PUBLIC_IPV4' &&
    selectedPublicScope?.authorized === true &&
    selectedPublicScope?.enabled === true &&
    selectedPublicScope?.authorization_confirmed_at &&
    selectedPublicScope?.authorization_confirmation_version &&
    selectedPublicScope?.authorization_source &&
    isIPv4Address(selectedPublicScope?.canonical_target ?? '')
  )
  const busy = loading || scanLoading || deviceLoading || serviceScanLoading

  return (
    <section className="network-workspace">
      <div className="network-workspace-heading">
        <div>
          <p className="panel-kicker">Network Visibility</p>
          <h2>Network Workspace</h2>
          <p className="network-workspace-copy">
            Discover authorized private networks and public targets, review devices, and inspect
            persisted ports, services, findings, and CVE matches.
          </p>
        </div>

        <span className="network-boundary">
          AUTHORIZED TARGETS ONLY
        </span>
      </div>

      {error && (
        <div className="network-error">
          {error}
        </div>
      )}

      <div className="network-toolbar">
        <label>
          <span>Authorized network</span>
          <select
            value={selectedNetworkId ?? ''}
            onChange={selectNetwork}
            disabled={busy || networks.length === 0}
          >
            {networks.length === 0 && (
              <option value="">No networks configured</option>
            )}

            {networks.map((network) => (
              <option key={network.id} value={network.id}>
                {network.name
                  ? `${network.name} · ${network.cidr}`
                  : network.cidr}
              </option>
            ))}
          </select>
        </label>

        <button
          className="network-primary-action"
          type="button"
          onClick={scanNetwork}
          disabled={!selectedNetworkId || !scopeAllowsScan || busy}
        >
          {scanLoading ? 'Scanning network…' : 'Scan Network'}
        </button>

        <div className="network-context">
          <span>Devices</span>
          <strong>{devices.length}</strong>
        </div>
      </div>

      {selectedNetwork && (
        <article className="panel network-scope-panel">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">Authorized Scope</p>
              <h3>{selectedScope?.name || 'Selected Network Scope'}</h3>
            </div>
            <span className={
              scopeAllowsScan
                ? 'network-candidate-state network-scope-confirmed'
                : 'network-candidate-state network-scope-unconfirmed'
            }>
              {scopeAllowsScan ? 'Confirmed' : 'Not confirmed'}
            </span>
          </div>
          <dl className="network-scope-details">
            <div>
              <dt>Type</dt>
              <dd>{selectedScope?.scope_type === 'PRIVATE_NETWORK'
                ? 'Private Network'
                : 'Unavailable'}</dd>
            </div>
            <div>
              <dt>Target</dt>
              <dd className="mono">
                {selectedScope?.canonical_target ?? selectedNetwork.cidr}
              </dd>
            </div>
            <div>
              <dt>Authorization</dt>
              <dd>{scopeAllowsScan ? 'Confirmed' : 'Not confirmed'}</dd>
            </div>
            <div>
              <dt>State</dt>
              <dd>{selectedScope?.enabled ? 'Enabled' : 'Disabled'}</dd>
            </div>
          </dl>
        </article>
      )}

      <article className="panel public-target-panel">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Explicit Authorization</p>
            <h3>Public Targets</h3>
          </div>
          <span className="network-candidate-state public-target-badge">
            Single IPv4 only
          </span>
        </div>
        <p className="network-candidate-note">
          Add only a public IPv4 address you own or are authorized to assess.
          Hostnames and ranges are not accepted.
        </p>
        <form className="public-target-form" onSubmit={addPublicTarget}>
          <label>
            <span>IPv4 address</span>
            <input
              value={publicTarget}
              onChange={(event) => setPublicTarget(event.target.value)}
              inputMode="decimal"
              autoComplete="off"
              aria-label="Public IPv4 address"
            />
          </label>
          <label>
            <span>Name (optional)</span>
            <input
              value={publicTargetName}
              onChange={(event) => setPublicTargetName(event.target.value)}
              maxLength={120}
            />
          </label>
          <label className="public-target-description">
            <span>Description (optional)</span>
            <input
              value={publicTargetDescription}
              onChange={(event) => setPublicTargetDescription(event.target.value)}
              maxLength={500}
            />
          </label>
          <label className="public-target-confirmation">
            <input
              type="checkbox"
              checked={publicAuthorizationConfirmed}
              onChange={(event) => setPublicAuthorizationConfirmed(event.target.checked)}
            />
            <span>I confirm that I own this target or have authorization to assess it.</span>
          </label>
          <button
            className="network-primary-action"
            type="submit"
            disabled={publicScopeLoading || !isIPv4Address(publicTarget) || !publicAuthorizationConfirmed}
          >
            {publicScopeLoading ? 'Saving…' : 'Add Public Target'}
          </button>
        </form>
        {publicScopeError && (
          <div className="network-error" role="alert">{publicScopeError}</div>
        )}
        {publicTargets.length === 0 ? (
          <p className="network-mini-empty">No public targets are authorized.</p>
        ) : (
          <div className="public-target-list">
            {publicTargets.map((scope) => {
              const canScan = scope.authorized && scope.enabled &&
                scope.authorization_confirmed_at &&
                scope.authorization_confirmation_version && scope.authorization_source
              const isSelected = scope.id === selectedPublicScopeId
              return (
                <div className={isSelected ? 'public-target-row is-selected' : 'public-target-row'} key={scope.id}>
                  <div>
                    <strong>{scope.name || 'Public IPv4 Target'}</strong>
                    <small>Type: Public IPv4</small>
                    <span className="mono">{scope.canonical_target}</span>
                    <small>Authorization: {canScan ? 'Confirmed' : 'Not confirmed'} · State: {scope.enabled ? 'Enabled' : 'Disabled'}</small>
                  </div>
                  <div className="public-target-actions">
                    <button
                      className="network-secondary-action"
                      type="button"
                      onClick={() => selectPublicTarget(scope.id)}
                      disabled={loading || scanLoading}
                    >
                      {isSelected ? 'Selected' : 'Review Target'}
                    </button>
                    <button
                      className="network-primary-action"
                      type="button"
                      onClick={() => scanPublicTarget(scope.id)}
                      disabled={!canScan || busy || publicScopeLoading}
                    >
                      {scanLoading && isSelected ? 'Scanning…' : 'Scan Target'}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </article>

      <article className="panel network-candidate-panel">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Local System State</p>
            <h3>Discovered Networks</h3>
          </div>

          <button
            className="network-secondary-action"
            type="button"
            onClick={refreshNetworkCandidates}
            disabled={candidateLoading}
          >
            {candidateLoading ? 'Discovering…' : 'Discover Networks'}
          </button>
        </div>

        <p className="network-candidate-note">
          Candidates come from local interface and route state. Discovery does
          not scan, save, or authorize these networks.
        </p>

        {candidateError && (
          <div className="network-error" role="alert">
            {candidateError}
          </div>
        )}

        {candidateLoading ? (
          <p className="network-mini-empty">Reading local network state…</p>
        ) : networkCandidates.length === 0 ? (
          <p className="network-mini-empty">
            No candidates discovered yet. Choose Discover Networks to read the
            local interface and route table.
          </p>
        ) : (
          <div className="network-candidate-list">
            {networkCandidates.map((candidate) => (
              <div className="network-candidate-row" key={candidate.cidr}>
                <div>
                  <strong className="mono">{candidate.cidr}</strong>
                  <span>
                    Interface: {candidate.interface || 'Unknown'} · Source:{' '}
                    {candidate.source
                      .split('+')
                      .map((source) => source.replaceAll('_', ' '))
                      .join(' + ')}
                  </span>
                  <small>{candidate.evidence.join(' · ')}</small>
                </div>
                <span className="network-candidate-state">
                  Candidate · not authorized
                </span>
              </div>
            ))}
          </div>
        )}
      </article>

      <div className="network-workspace-grid">
        <article className="panel network-device-panel">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">Inventory</p>
              <h3>Devices</h3>
            </div>

            <span className="panel-count">{devices.length}</span>
          </div>

          {loading ? (
            <p className="empty-state">Loading device inventory…</p>
          ) : devices.length === 0 ? (
            <p className="empty-state">
              {selectedPublicScope
                ? 'No device evidence is currently persisted for this target.'
                : 'No devices are currently persisted for this network.'}
            </p>
          ) : (
            <div className="network-device-list">
              {devices.map((device) => (
                <button
                  className={
                    device.id === selectedDeviceId
                      ? 'network-device-row is-selected'
                      : 'network-device-row'
                  }
                  type="button"
                  key={device.id}
                  onClick={() => selectDevice(device.id)}
                  disabled={busy}
                >
                  <div>
                    <strong className="mono">
                      {device.last_ip_address}
                    </strong>
                    <span>
                      {device.vendor ?? device.hostname ?? 'Unknown device'}
                    </span>
                  </div>

                  <DeviceStatus value={device.status} />
                </button>
              ))}
            </div>
          )}
        </article>

        <article className="panel network-detail-panel">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">Selected Device</p>
              <h3>
                {deviceReview?.device?.last_ip_address ?? 'Device Review'}
              </h3>
            </div>

            <button
              className="network-secondary-action"
              type="button"
              onClick={scanServices}
              disabled={!selectedDeviceId || !(scopeAllowsScan || publicScopeAllowsScan) || busy}
            >
              {serviceScanLoading
                ? 'Scanning services…'
                : 'Scan Services'}
            </button>
          </div>

          {deviceError && (
            <div className="network-error">
              {deviceError}
            </div>
          )}

          {!selectedDeviceId ? (
            <p className="empty-state">
              Select a discovered device to inspect its persisted security
              state.
            </p>
          ) : deviceLoading ? (
            <p className="empty-state">Loading device review…</p>
          ) : deviceReview ? (
            <>
              <div className="network-device-summary">
                <div>
                  <span>IP</span>
                  <strong className="mono">
                    {deviceReview.device.last_ip_address}
                  </strong>
                </div>

                <div>
                  <span>Vendor</span>
                  <strong>
                    {deviceReview.device.vendor ?? 'Unknown'}
                  </strong>
                </div>

                <div>
                  <span>Identity</span>
                  <strong>
                    {deviceReview.device.identity_confidence}
                  </strong>
                </div>

                <div>
                  <span>Status</span>
                  <DeviceStatus value={deviceReview.device.status} />
                </div>
              </div>

              <div className="network-review-grid">
                <section>
                  <div className="network-review-heading">
                    <h4>Ports</h4>
                    <span>{deviceReview.ports.length}</span>
                  </div>

                  {deviceReview.ports.length === 0 ? (
                    <p className="network-mini-empty">No persisted ports.</p>
                  ) : (
                    <div className="network-fact-list">
                      {deviceReview.ports.map((port) => (
                        <div key={port.id} className="network-fact-row">
                          <span className="mono">
                            {port.port_number}/{port.transport}
                          </span>
                          <strong>{port.state}</strong>
                        </div>
                      ))}
                    </div>
                  )}
                </section>

                <section>
                  <div className="network-review-heading">
                    <h4>Services</h4>
                    <span>{deviceReview.services.length}</span>
                  </div>

                  {deviceReview.services.length === 0 ? (
                    <p className="network-mini-empty">
                      No persisted services.
                    </p>
                  ) : (
                    <div className="network-service-list">
                      {deviceReview.services.map((service) => (
                        <div key={service.id} className="network-service-row">
                          <strong>
                            {service.service_name ?? 'Unknown service'}
                          </strong>
                          <span>
                            {service.product ?? 'No product evidence'}
                            {service.version
                              ? ` · ${service.version}`
                              : ''}
                          </span>
                          <small>
                            Confidence: {service.confidence}
                          </small>
                        </div>
                      ))}
                    </div>
                  )}
                </section>

                <section>
                  <div className="network-review-heading">
                    <h4>Findings</h4>
                    <span>{deviceReview.findings.length}</span>
                  </div>

                  {deviceReview.findings.length === 0 ? (
                    <p className="network-mini-empty">
                      No persisted risk findings.
                    </p>
                  ) : (
                    <div className="network-service-list">
                      {deviceReview.findings.map((finding) => (
                        <div key={finding.id} className="network-service-row">
                          <div className="network-finding-top">
                            <strong>{finding.title}</strong>
                            <span className={`security-badge security-badge-${String(finding.severity).toLowerCase()}`}>
                              {finding.severity}
                            </span>
                          </div>
                          <span>{finding.reason}</span>
                          <small>
                            {finding.status} · confidence {finding.confidence}
                          </small>
                        </div>
                      ))}
                    </div>
                  )}
                </section>

                <section>
                  <div className="network-review-heading">
                    <h4>CVE Matches</h4>
                    <span>{deviceReview.cveMatches.length}</span>
                  </div>

                  {deviceReview.cveMatches.length === 0 ? (
                    <p className="network-mini-empty">
                      No persisted CVE matches.
                    </p>
                  ) : (
                    <div className="network-service-list">
                      {deviceReview.cveMatches.map((match) => (
                        <div key={match.id} className="network-service-row">
                          <strong>{match.cve_id ?? `Match #${match.id}`}</strong>
                          <span>
                            {match.match_status ?? match.status ?? 'Review'}
                          </span>
                          <small>
                            Confidence: {match.confidence ?? 'Unknown'}
                          </small>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              </div>
            </>
          ) : (
            <p className="empty-state">
              Device review is unavailable.
            </p>
          )}
        </article>
      </div>
    </section>
  )
}

export default NetworkWorkspace
