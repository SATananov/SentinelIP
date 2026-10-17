import { canScanPublicCidr } from '../services/publicCidrState.js'
import PublicCidrTargets from './PublicCidrTargets.jsx'
import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react'

import {
  createPublicIPv4Scope,
  createHostnameScope,
  discoverDeviceServices,
  discoverNetworkCandidates,
  discoverNetwork,
  discoverPublicScope,
  discoverScopeDeviceServices,
  loadDeviceReview,
  loadDevice,
  loadNetworkDevices,
  loadNetworks,
  loadScopeDevices,
  loadScopes,
  previewHostname,
  reauthorizeHostnameScope,
} from '../services/networkApi.js'

const PUBLIC_AUTHORIZATION_VERSION = 'public_ipv4_authorization_v1'
const HOSTNAME_AUTHORIZATION_VERSION = 'hostname_authorization_v1'

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

function ScopeState({ confirmed, enabled, type, reauthorizationRequired = false }) {
  return (
    <div className="workspace-scope-badges">
      <span className={confirmed ? 'scope-badge scope-badge-confirmed' : 'scope-badge scope-badge-unconfirmed'}>
        {confirmed ? 'Confirmed' : 'Not confirmed'}
      </span>
      <span className={enabled ? 'scope-badge scope-badge-enabled' : 'scope-badge scope-badge-disabled'}>
        {enabled ? 'Enabled' : 'Disabled'}
      </span>
      <span className="scope-badge scope-badge-type">{type}</span>
      {reauthorizationRequired && <span className="scope-badge scope-badge-unconfirmed">Re-authorization required</span>}
    </div>
  )
}

function NetworkWorkspace({ investigationRequest = null }) {
  const [cidrBusy, setCidrBusy] = useState(false)
  const [networks, setNetworks] = useState([])
  const [scopes, setScopes] = useState([])
  const [networkCandidates, setNetworkCandidates] = useState([])
  const [selectedScope, setSelectedScope] = useState(null)
  const [devices, setDevices] = useState([])
  const [selectedDeviceId, setSelectedDeviceId] = useState(null)
  const [deviceReview, setDeviceReview] = useState(null)

  const [publicTarget, setPublicTarget] = useState('')
  const [publicTargetName, setPublicTargetName] = useState('')
  const [publicTargetDescription, setPublicTargetDescription] = useState('')
  const [publicAuthorizationConfirmed, setPublicAuthorizationConfirmed] = useState(false)
  const [hostnameInput, setHostnameInput] = useState('')
  const [hostnameName, setHostnameName] = useState('')
  const [hostnameDescription, setHostnameDescription] = useState('')
  const [hostnamePreview, setHostnamePreview] = useState(null)
  const [hostnameAuthorizationConfirmed, setHostnameAuthorizationConfirmed] = useState(false)
  const [hostnamePreviewLoading, setHostnamePreviewLoading] = useState(false)
  const [hostnameScopeLoading, setHostnameScopeLoading] = useState(false)
  const [hostnameError, setHostnameError] = useState(null)
  const [reauthorizeScopeId, setReauthorizeScopeId] = useState(null)
  const [reauthorizationRequiredIds, setReauthorizationRequiredIds] = useState([])

  const [workspaceLoading, setWorkspaceLoading] = useState(true)
  const [selectionLoading, setSelectionLoading] = useState(false)
  const [scanLoading, setScanLoading] = useState(false)
  const [deviceLoading, setDeviceLoading] = useState(false)
  const [serviceScanLoading, setServiceScanLoading] = useState(false)
  const [candidateLoading, setCandidateLoading] = useState(false)
  const [publicScopeLoading, setPublicScopeLoading] = useState(false)

  const [workspaceError, setWorkspaceError] = useState(null)
  const [privateError, setPrivateError] = useState(null)
  const [publicError, setPublicError] = useState(null)
  const [candidateError, setCandidateError] = useState(null)
  const [deviceError, setDeviceError] = useState(null)
  const [investigationNavigationError, setInvestigationNavigationError] = useState(null)

  const selectionRequest = useRef(0)
  const handledInvestigationRequest = useRef(null)
  const latestInvestigationRequest = useRef(null)

  const loadWorkspace = useCallback(async (signal) => {
    setWorkspaceLoading(true)
    setWorkspaceError(null)

    try {
      const [networkData, scopeData] = await Promise.all([
        loadNetworks(signal),
        loadScopes(signal),
      ])
      setNetworks(networkData)
      setScopes(scopeData)
    } catch (err) {
      if (err.name !== 'AbortError') setWorkspaceError(err.message)
    } finally {
      setWorkspaceLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    const timer = setTimeout(() => loadWorkspace(controller.signal), 0)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [loadWorkspace])

  const selectPrivateNetwork = useCallback(async (network) => {
    const requestId = selectionRequest.current + 1
    selectionRequest.current = requestId
    setSelectedScope({ kind: 'PRIVATE_NETWORK', id: network.id })
    setDevices([])
    setSelectedDeviceId(null)
    setDeviceReview(null)
    setDeviceError(null)
    setPrivateError(null)
    setSelectionLoading(true)

    try {
      const data = await loadNetworkDevices(network.id)
      if (selectionRequest.current === requestId) setDevices(data)
    } catch (err) {
      if (selectionRequest.current === requestId) setPrivateError(err.message)
    } finally {
      if (selectionRequest.current === requestId) setSelectionLoading(false)
    }
  }, [])

  const selectPublicTarget = useCallback(async (scope) => {
    const requestId = selectionRequest.current + 1
    selectionRequest.current = requestId
    setSelectedScope({ kind: scope.scope_type, id: scope.id })
    setDevices([])
    setSelectedDeviceId(null)
    setDeviceReview(null)
    setDeviceError(null)
    setPublicError(null)
    setSelectionLoading(true)

    try {
      const data = await loadScopeDevices(scope.id)
      if (selectionRequest.current === requestId) setDevices(data)
    } catch (err) {
      if (selectionRequest.current === requestId) setPublicError(err.message)
    } finally {
      if (selectionRequest.current === requestId) setSelectionLoading(false)
    }
  }, [])

  async function scanPrivateNetwork(network) {
    const scope = scopes.find((item) => item.network_id === network.id)
    const canScan = network.authorized === true && network.enabled === true &&
      scope?.scope_type === 'PRIVATE_NETWORK' && scope.authorized === true &&
      scope.enabled === true && scope.canonical_target === network.cidr &&
      Boolean(scope.authorization_confirmed_at) &&
      Boolean(scope.authorization_confirmation_version) && Boolean(scope.authorization_source)
    if (!canScan) return

    const requestId = selectionRequest.current + 1
    selectionRequest.current = requestId
    setSelectedScope({ kind: 'PRIVATE_NETWORK', id: network.id })
    setDevices([])
    setSelectedDeviceId(null)
    setDeviceReview(null)
    setDeviceError(null)
    setPrivateError(null)
    setScanLoading(true)

    try {
      const result = await discoverNetwork(network.id)
      if (selectionRequest.current === requestId) setDevices(result.devices)
    } catch (err) {
      if (selectionRequest.current === requestId) setPrivateError(err.message)
    } finally {
      if (selectionRequest.current === requestId) setScanLoading(false)
    }
  }

  async function scanPublicTarget(scope) {
    const canScan = ['PUBLIC_IPV4', 'HOSTNAME', 'PUBLIC_CIDR'].includes(scope.scope_type) && scope.authorized === true &&
      scope.enabled === true && Boolean(scope.authorization_confirmed_at) &&
      Boolean(scope.authorization_confirmation_version) && Boolean(scope.authorization_source) &&
      (scope.scope_type === 'PUBLIC_IPV4'
        ? isIPv4Address(scope.canonical_target ?? '')
        : scope.scope_type === 'PUBLIC_CIDR'
          ? canScanPublicCidr(scope)
          : scope.resolution_status === 'CURRENT' && scope.approved_addresses?.length > 0)
    if (!canScan) return

    const requestId = selectionRequest.current + 1
    selectionRequest.current = requestId
    setSelectedScope({ kind: scope.scope_type, id: scope.id })
    setDevices([])
    setSelectedDeviceId(null)
    setDeviceReview(null)
    setDeviceError(null)
    setPublicError(null)
    setScanLoading(true)

    try {
      const result = await discoverPublicScope(scope.id)
      const nextDevices = Array.isArray(result.devices)
        ? result.devices
        : result.device ? [result.device] : []
      if (selectionRequest.current !== requestId) return
      setDevices(nextDevices)
      if (nextDevices.length > 0) {
        const review = await loadDeviceReview(nextDevices[0].id)
        if (selectionRequest.current === requestId) {
          setSelectedDeviceId(nextDevices[0].id)
          setDeviceReview(review)
        }
      }
    } catch (err) {
      if (selectionRequest.current === requestId) {
        setPublicError(err.message)
        if (scope.scope_type === 'HOSTNAME' && err.status === 409) {
          setScopes((current) => current.map((item) => (
            item.id === scope.id ? { ...item, resolution_status: 'REAUTH_REQUIRED' } : item
          )))
          setReauthorizationRequiredIds((current) => current.includes(scope.id) ? current : [...current, scope.id])
        }
      }
    } finally {
      if (selectionRequest.current === requestId) setScanLoading(false)
    }
  }

  const selectDevice = useCallback(async (deviceId) => {
    const requestId = selectionRequest.current + 1
    selectionRequest.current = requestId
    setSelectedDeviceId(deviceId)
    setDeviceReview(null)
    setDeviceLoading(true)
    setDeviceError(null)

    try {
      const result = await loadDeviceReview(deviceId)
      if (selectionRequest.current === requestId) setDeviceReview(result)
    } catch (err) {
      if (selectionRequest.current === requestId) setDeviceError(err.message)
    } finally {
      if (selectionRequest.current === requestId) setDeviceLoading(false)
    }
  }, [])

  useEffect(() => {
    const request = investigationRequest
    if (!request) return
    latestInvestigationRequest.current = request.nonce
    if (!['DEVICE', 'SCOPE'].includes(request.kind) || workspaceLoading ||
        handledInvestigationRequest.current === request.nonce) return
    handledInvestigationRequest.current = request.nonce
    const id = Number(request.id)
    if (!Number.isSafeInteger(id) || id <= 0) {
      queueMicrotask(() => {
        if (latestInvestigationRequest.current === request.nonce) {
          setInvestigationNavigationError({ nonce: request.nonce, message: 'This Network Workspace destination is unavailable.' })
        }
      })
      return
    }
    async function openRequestedContext() {
      try {
        let scope = scopes.find((item) => item.id === Number(request.item?.scope_id))
        if (request.kind === 'SCOPE') scope = scopes.find((item) => item.id === id)
        if (!scope && request.kind === 'DEVICE') {
          const device = await loadDevice(id)
          if (latestInvestigationRequest.current !== request.nonce) return
          scope = scopes.find((item) => item.id === Number(device.scope_id))
          if (!scope && device.network_id) scope = scopes.find((item) => item.network_id === device.network_id)
        }
        if (scope?.scope_type === 'PRIVATE_NETWORK') {
          const network = networks.find((item) => item.id === scope.network_id)
          if (!network) throw new Error('The device or scope is not present in the current network inventory.')
          await selectPrivateNetwork(network)
          if (latestInvestigationRequest.current !== request.nonce) return
          if (request.kind === 'DEVICE') await selectDevice(id)
          return
        }
        if (scope && ['PUBLIC_IPV4', 'PUBLIC_CIDR', 'HOSTNAME'].includes(scope.scope_type)) {
          await selectPublicTarget(scope)
          if (latestInvestigationRequest.current !== request.nonce) return
          if (request.kind === 'DEVICE') await selectDevice(id)
          return
        }
        if (request.kind === 'DEVICE') {
          const review = await loadDeviceReview(id)
          if (handledInvestigationRequest.current !== request.nonce) return
          setDevices([review.device])
          setSelectedDeviceId(id)
          setDeviceReview(review)
          return
        }
        throw new Error('The requested scope is unavailable in the current network inventory.')
      } catch (error) {
        if (latestInvestigationRequest.current === request.nonce) {
          setInvestigationNavigationError({ nonce: request.nonce, message: error?.message || 'The requested network record is unavailable.' })
        }
      }
    }
    void openRequestedContext()
  }, [investigationRequest, networks, scopes, workspaceLoading,
    selectPrivateNetwork, selectPublicTarget, selectDevice])

  async function scanServices() {
    if (!selectedDeviceId || !selectedScope) return

    setServiceScanLoading(true)
    setDeviceError(null)
    try {
      if (selectedScope.kind !== 'PRIVATE_NETWORK') {
        await discoverScopeDeviceServices(selectedScope.id, selectedDeviceId)
      } else {
        await discoverDeviceServices(selectedDeviceId)
      }
      setDeviceReview(await loadDeviceReview(selectedDeviceId))
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
      setNetworkCandidates(await discoverNetworkCandidates())
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
    setPublicError(null)
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
      selectionRequest.current += 1
      setSelectedScope({ kind: 'PUBLIC_IPV4', id: scope.id })
      setDevices([])
      setSelectedDeviceId(null)
      setDeviceReview(null)
      setDeviceError(null)
    } catch (err) {
      setPublicError(err.message)
    } finally {
      setPublicScopeLoading(false)
    }
  }

  async function previewHostnameTarget() {
    setHostnamePreviewLoading(true)
    setHostnameError(null)
    setHostnamePreview(null)
    setHostnameAuthorizationConfirmed(false)
    try {
      const result = await previewHostname({ hostname: hostnameInput })
      setHostnameInput(result.canonical_hostname)
      setHostnamePreview(result)
    } catch (err) {
      setHostnameError(err.message)
    } finally {
      setHostnamePreviewLoading(false)
    }
  }

  async function saveHostnameTarget(event) {
    event.preventDefault()
    if (!hostnamePreview?.eligible || !hostnameAuthorizationConfirmed) return
    setHostnameScopeLoading(true)
    setHostnameError(null)
    const payload = {
      canonical_hostname: hostnamePreview.canonical_hostname,
      approved_resolved_ipv4: hostnamePreview.resolved_ipv4,
      name: hostnameName.trim(),
      description: hostnameDescription.trim(),
      authorization_confirmed: true,
      authorization_confirmation_version: HOSTNAME_AUTHORIZATION_VERSION,
    }
    try {
      const scope = reauthorizeScopeId
        ? await reauthorizeHostnameScope(reauthorizeScopeId, payload)
        : await createHostnameScope(payload)
      setScopes((current) => reauthorizeScopeId
        ? current.map((item) => item.id === scope.id ? scope : item)
        : [...current, scope])
      setReauthorizationRequiredIds((current) => current.filter((id) => id !== scope.id))
      setReauthorizeScopeId(null)
      setHostnameInput('')
      setHostnameName('')
      setHostnameDescription('')
      setHostnamePreview(null)
      setHostnameAuthorizationConfirmed(false)
      selectionRequest.current += 1
      setSelectedScope({ kind: 'HOSTNAME', id: scope.id })
      setDevices([])
      setSelectedDeviceId(null)
      setDeviceReview(null)
      setDeviceError(null)
    } catch (err) {
      setHostnameError(err.message)
      setHostnamePreview(null)
      setHostnameAuthorizationConfirmed(false)
    } finally {
      setHostnameScopeLoading(false)
    }
  }

  function beginHostnameReauthorization(scope) {
    setReauthorizeScopeId(scope.id)
    setHostnameInput(scope.canonical_target)
    setHostnameName(scope.name ?? '')
    setHostnameDescription(scope.description ?? '')
    setHostnamePreview(null)
    setHostnameAuthorizationConfirmed(false)
    setHostnameError(null)
  }

  const selectedNetwork = selectedScope?.kind === 'PRIVATE_NETWORK'
    ? networks.find((item) => item.id === selectedScope.id)
    : null
  const selectedPrivateScope = selectedNetwork
    ? scopes.find((item) => item.network_id === selectedNetwork.id)
    : null
  const publicTargets = scopes.filter((scope) => ['PUBLIC_IPV4', 'HOSTNAME', 'PUBLIC_CIDR'].includes(scope.scope_type))
  const ipv4Targets = publicTargets.filter((scope) => scope.scope_type === 'PUBLIC_IPV4')
  const hostnameTargets = publicTargets.filter((scope) => scope.scope_type === 'HOSTNAME')
  const activePublicScope = ['PUBLIC_IPV4', 'HOSTNAME', 'PUBLIC_CIDR'].includes(selectedScope?.kind)
    ? publicTargets.find((scope) => scope.id === selectedScope.id)
    : null

  const privateScopeConfirmed = Boolean(
    selectedNetwork?.authorized === true && selectedPrivateScope?.authorized === true &&
    selectedPrivateScope?.scope_type === 'PRIVATE_NETWORK' &&
    selectedPrivateScope?.canonical_target === selectedNetwork?.cidr &&
    selectedPrivateScope?.authorization_confirmed_at &&
    selectedPrivateScope?.authorization_confirmation_version && selectedPrivateScope?.authorization_source,
  )
  const privateScanAllowed = Boolean(
    privateScopeConfirmed && selectedNetwork?.enabled === true && selectedPrivateScope?.enabled === true,
  )
  const publicScopeConfirmed = Boolean(
    ['PUBLIC_IPV4', 'HOSTNAME', 'PUBLIC_CIDR'].includes(activePublicScope?.scope_type) && activePublicScope.authorized === true &&
    activePublicScope.authorization_confirmed_at &&
    activePublicScope.authorization_confirmation_version && activePublicScope.authorization_source &&
    (activePublicScope.scope_type === 'PUBLIC_IPV4'
      ? isIPv4Address(activePublicScope.canonical_target ?? '')
      : activePublicScope.scope_type === 'PUBLIC_CIDR'
        ? canScanPublicCidr(activePublicScope)
        : activePublicScope.resolution_status === 'CURRENT' && activePublicScope.approved_addresses?.length > 0),
  )
  const publicScanAllowed = Boolean(publicScopeConfirmed && activePublicScope.enabled === true)
  const anyActionBusy = cidrBusy || workspaceLoading || selectionLoading || scanLoading ||
    deviceLoading || serviceScanLoading || publicScopeLoading || hostnamePreviewLoading || hostnameScopeLoading

  return (
    <section className="network-workspace" id="network-workspace">
      <div className="network-workspace-heading">
        <div>
          <p className="panel-kicker">Network Visibility</p>
          <h2>Network Workspace</h2>
          <p className="network-workspace-copy">
            Discover local network candidates, select an authorized scope, and review its persisted device evidence.
          </p>
        </div>
        <span className="network-boundary">AUTHORIZED TARGETS ONLY</span>
      </div>
      {investigationNavigationError?.nonce === investigationRequest?.nonce && <p className="network-error" role="status">{investigationNavigationError.message}</p>}

      {workspaceError && <div className="network-error" role="alert">{workspaceError}</div>}

      <article className="panel workspace-section discovered-network-section">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Passive Local Discovery</p>
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
          Candidates are read from local interface and route state. Discovery does not scan, save, or authorize them.
        </p>
        {candidateError && <div className="network-error" role="alert">{candidateError}</div>}
        {candidateLoading ? (
          <p className="network-mini-empty">Reading local network state…</p>
        ) : networkCandidates.length === 0 ? (
          <p className="network-mini-empty">No candidates loaded. Choose Discover Networks to inspect local network state.</p>
        ) : (
          <div className="network-candidate-list">
            {networkCandidates.map((candidate) => (
              <div className="network-candidate-row" key={candidate.cidr}>
                <div>
                  <strong className="mono">{candidate.cidr}</strong>
                  <span>Interface: {candidate.interface || 'Unknown'} · Source: {candidate.source.replaceAll('_', ' ')}</span>
                  <small>{candidate.evidence.join(' · ')}</small>
                </div>
                <span className="network-candidate-state">Candidate · not authorized</span>
              </div>
            ))}
          </div>
        )}
      </article>

      <article className="panel workspace-section private-network-section">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Saved Private Scope</p>
            <h3>Authorized Private Networks</h3>
          </div>
          <span className="panel-count">{networks.length}</span>
        </div>
        {privateError && <div className="network-error" role="alert">{privateError}</div>}
        {workspaceLoading ? (
          <p className="network-mini-empty">Loading authorized networks…</p>
        ) : networks.length === 0 ? (
          <p className="network-mini-empty">No private networks are saved.</p>
        ) : (
          <div className="authorized-scope-list">
            {networks.map((network) => {
              const scope = scopes.find((item) => item.network_id === network.id)
              const confirmed = network.authorized === true && scope?.authorized === true &&
                scope?.scope_type === 'PRIVATE_NETWORK' && Boolean(scope?.authorization_confirmed_at) &&
                Boolean(scope?.authorization_confirmation_version) && Boolean(scope?.authorization_source)
              const enabled = network.enabled === true && scope?.enabled === true
              const isSelected = selectedScope?.kind === 'PRIVATE_NETWORK' && selectedScope.id === network.id
              return (
                <div className={isSelected ? 'authorized-scope-row is-selected' : 'authorized-scope-row'} key={network.id}>
                  <div className="authorized-scope-main">
                    <strong>{network.name || 'Private Network'}</strong>
                    <span className="mono">{network.cidr}</span>
                    <ScopeState confirmed={confirmed} enabled={enabled} type="Private Network" />
                    {isSelected && <small>{devices.length} devices in current inventory view</small>}
                  </div>
                  <div className="authorized-scope-actions">
                    <button
                      className="network-secondary-action"
                      type="button"
                      onClick={() => selectPrivateNetwork(network)}
                      disabled={anyActionBusy}
                    >
                      {isSelected ? 'Selected' : 'Select'}
                    </button>
                    <button
                      className="network-primary-action"
                      type="button"
                      onClick={() => scanPrivateNetwork(network)}
                      disabled={!confirmed || !enabled || anyActionBusy}
                    >
                      {scanLoading && isSelected ? 'Scanning…' : 'Scan Network'}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </article>

      <article className="panel workspace-section public-target-panel">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Explicit Authorization</p>
            <h3>Public Targets</h3>
          </div>
          <span className="network-candidate-state public-target-badge">Explicit scope only</span>
        </div>
        <p className="network-candidate-note">
          Add an authorized public IPv4 address, small CIDR range, or hostname. Hostname scans remain bound to the exact approved IPv4 set.
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
            <input value={publicTargetName} onChange={(event) => setPublicTargetName(event.target.value)} maxLength={120} />
          </label>
          <label className="public-target-description">
            <span>Description (optional)</span>
            <input value={publicTargetDescription} onChange={(event) => setPublicTargetDescription(event.target.value)} maxLength={500} />
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
            disabled={publicScopeLoading || anyActionBusy || !isIPv4Address(publicTarget) || !publicAuthorizationConfirmed}
          >
            {publicScopeLoading ? 'Saving…' : 'Add Public Target'}
          </button>
        </form>
        {publicError && <div className="network-error" role="alert">{publicError}</div>}
        <PublicCidrTargets
          scopes={publicTargets.filter((scope) => scope.scope_type === 'PUBLIC_CIDR')}
          selectedScope={selectedScope}
          busy={anyActionBusy}
          scanning={scanLoading}
          onBusyChange={setCidrBusy}
          onSelect={selectPublicTarget}
          onScan={scanPublicTarget}
          onCreated={(scope) => {
            setScopes((current) => [...current, scope])
            selectionRequest.current += 1
            setSelectedScope({ kind: 'PUBLIC_CIDR', id: scope.id })
            setDevices([])
            setSelectedDeviceId(null)
            setDeviceReview(null)
            setDeviceError(null)
            setPublicError(null)
          }}
        />
        <div className="hostname-target-form-section">
          <h4>Hostname</h4>
          <p className="network-candidate-note">Preview resolves A records only. Review and authorize the exact eligible public IPv4 addresses shown.</p>
          <form className="public-target-form" onSubmit={saveHostnameTarget}>
            <label>
              <span>Hostname</span>
              <input
                value={hostnameInput}
                disabled={hostnamePreviewLoading || hostnameScopeLoading}
                onChange={(event) => {
                  setHostnameInput(event.target.value)
                  setHostnamePreview(null)
                  setHostnameAuthorizationConfirmed(false)
                }}
                autoComplete="off"
                aria-label="Hostname target"
              />
            </label>
            <label>
              <span>Name (optional)</span>
              <input value={hostnameName} onChange={(event) => setHostnameName(event.target.value)} maxLength={120} />
            </label>
            <label className="public-target-description">
              <span>Description (optional)</span>
              <input value={hostnameDescription} onChange={(event) => setHostnameDescription(event.target.value)} maxLength={500} />
            </label>
            <div className="hostname-form-actions">
              <button
                className="network-secondary-action"
                type="button"
                onClick={previewHostnameTarget}
                disabled={!hostnameInput.trim() || anyActionBusy}
              >
                {hostnamePreviewLoading ? 'Resolving…' : 'Resolve / Preview'}
              </button>
              {hostnamePreview?.eligible && (
                <>
                  <div className="hostname-preview-addresses" aria-live="polite">
                    <strong>Resolved public IPv4 addresses</strong>
                    <ul>{hostnamePreview.resolved_ipv4.map((address) => <li className="mono" key={address}>{address}</li>)}</ul>
                  </div>
                  <label className="public-target-confirmation">
                    <input
                      type="checkbox"
                      checked={hostnameAuthorizationConfirmed}
                      onChange={(event) => setHostnameAuthorizationConfirmed(event.target.checked)}
                    />
                    <span>I confirm that I own this hostname or have authorization to assess the resolved targets shown above.</span>
                  </label>
                  <button
                    className="network-primary-action"
                    type="submit"
                    disabled={!hostnameAuthorizationConfirmed || anyActionBusy}
                  >
                    {hostnameScopeLoading ? 'Saving…' : reauthorizeScopeId ? 'Renew Authorization' : 'Add Hostname'}
                  </button>
                </>
              )}
            </div>
          </form>
          {hostnameError && <div className="network-error" role="alert">{hostnameError}</div>}
          {hostnamePreview && !hostnamePreview.eligible && (
            <div className="network-error" role="alert">{hostnamePreview.errors.join(' ')}</div>
          )}
        </div>

        <div className="hostname-target-list-section">
          <h4>Authorized Public IPv4</h4>
          {ipv4Targets.length === 0 ? <p className="network-mini-empty">No public IPv4 targets are authorized.</p> : (
            <div className="authorized-scope-list">
              {ipv4Targets.map((scope) => {
                const confirmed = scope.authorized === true && Boolean(scope.authorization_confirmed_at) &&
                  Boolean(scope.authorization_confirmation_version) && Boolean(scope.authorization_source)
                const isSelected = selectedScope?.kind === 'PUBLIC_IPV4' && selectedScope.id === scope.id
                return (
                  <div className={isSelected ? 'authorized-scope-row is-selected public-scope-row' : 'authorized-scope-row public-scope-row'} key={scope.id}>
                    <div className="authorized-scope-main">
                      <strong>{scope.name || 'Public IPv4 Target'}</strong>
                      <span className="mono">{scope.canonical_target}</span>
                      <ScopeState confirmed={confirmed} enabled={scope.enabled === true} type="Public IPv4" />
                    </div>
                    <div className="authorized-scope-actions">
                      <button className="network-secondary-action" type="button" onClick={() => selectPublicTarget(scope)} disabled={anyActionBusy}>{isSelected ? 'Selected' : 'Select'}</button>
                      <button className="network-primary-action" type="button" onClick={() => scanPublicTarget(scope)} disabled={!confirmed || !scope.enabled || !isIPv4Address(scope.canonical_target ?? '') || anyActionBusy}>{scanLoading && isSelected ? 'Scanning…' : 'Scan Target'}</button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="hostname-target-list-section">
          <h4>Authorized Hostnames</h4>
          {hostnameTargets.length === 0 ? <p className="network-mini-empty">No hostnames are authorized.</p> : (
            <div className="authorized-scope-list">
              {hostnameTargets.map((scope) => {
                const confirmed = scope.authorized === true && Boolean(scope.authorization_confirmed_at) &&
                  Boolean(scope.authorization_confirmation_version) && Boolean(scope.authorization_source)
                const reauthorizationRequired = reauthorizationRequiredIds.includes(scope.id) || scope.resolution_status !== 'CURRENT'
                const isSelected = selectedScope?.kind === 'HOSTNAME' && selectedScope.id === scope.id
                return (
                  <div className={isSelected ? 'authorized-scope-row is-selected public-scope-row' : 'authorized-scope-row public-scope-row'} key={scope.id}>
                    <div className="authorized-scope-main">
                      <strong>{scope.name || 'Hostname Target'}</strong>
                      <span className="mono">{scope.canonical_target}</span>
                      <ScopeState confirmed={confirmed} enabled={scope.enabled === true} type="Hostname" reauthorizationRequired={reauthorizationRequired} />
                      <small>Approved addresses: {scope.approved_addresses?.length ? scope.approved_addresses.join(', ') : 'none'}</small>
                    </div>
                    <div className="authorized-scope-actions">
                      <button className="network-secondary-action" type="button" onClick={() => selectPublicTarget(scope)} disabled={anyActionBusy}>{isSelected ? 'Selected' : 'Select'}</button>
                      {reauthorizationRequired && <button className="network-secondary-action" type="button" onClick={() => beginHostnameReauthorization(scope)} disabled={anyActionBusy}>Renew Authorization</button>}
                      <button className="network-primary-action" type="button" onClick={() => scanPublicTarget(scope)} disabled={!confirmed || !scope.enabled || reauthorizationRequired || !scope.approved_addresses?.length || anyActionBusy}>{scanLoading && isSelected ? 'Scanning…' : 'Scan Target'}</button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </article>

      <article className="panel workspace-section selected-asset-section">
        <div className="panel-heading">
          <div>
            <p className="panel-kicker">Selected Scope</p>
            <h3>Selected Asset / Review</h3>
          </div>
          {selectedScope && (
            <span className="selected-scope-label">
              {selectedScope.kind === 'PRIVATE_NETWORK'
                ? selectedNetwork?.cidr
                : activePublicScope?.canonical_target}
            </span>
          )}
        </div>

        {!selectedScope ? (
          <p className="empty-state">Select an authorized private network or public target to view its devices and persisted review evidence.</p>
        ) : selectionLoading ? (
          <p className="empty-state">Loading devices for the selected scope…</p>
        ) : (
          <div className="network-workspace-grid">
            <section className="network-device-panel">
              <div className="network-review-heading">
                <h4>Devices</h4>
                <span>{devices.length}</span>
              </div>
              {devices.length === 0 ? (
                <p className="empty-state">
                  {scanLoading ? 'Scanning the selected authorized scope…' : 'No device evidence is currently persisted for this scope.'}
                </p>
              ) : (
                <div className="network-device-list">
                  {devices.map((device) => (
                    <button
                      className={device.id === selectedDeviceId ? 'network-device-row is-selected' : 'network-device-row'}
                      type="button"
                      key={device.id}
                      onClick={() => selectDevice(device.id)}
                      disabled={anyActionBusy}
                    >
                      <div>
                        <strong className="mono">{device.last_ip_address}</strong>
                        <span>{device.vendor ?? device.hostname ?? 'Unknown device'}</span>
                      </div>
                      <DeviceStatus value={device.status} />
                    </button>
                  ))}
                </div>
              )}
            </section>

            <section className="network-detail-panel">
              <div className="panel-heading">
                <div>
                  <p className="panel-kicker">Device Evidence</p>
                  <h4>{deviceReview?.device?.last_ip_address ?? 'Review a device'}</h4>
                </div>
                <button
                  className="network-secondary-action"
                  type="button"
                  onClick={scanServices}
                  disabled={!selectedDeviceId || !(privateScanAllowed || publicScanAllowed) || anyActionBusy}
                >
                  {serviceScanLoading ? 'Scanning services…' : 'Scan Services'}
                </button>
              </div>
              {deviceError && <div className="network-error" role="alert">{deviceError}</div>}
              {!selectedDeviceId ? (
                <p className="empty-state">Select a device to review its persisted ports, services, findings, and CVE matches.</p>
              ) : deviceLoading ? (
                <p className="empty-state">Loading device review…</p>
              ) : deviceReview ? (
                <DeviceReview review={deviceReview} />
              ) : (
                <p className="empty-state">Device review is unavailable.</p>
              )}
            </section>
          </div>
        )}
      </article>
    </section>
  )
}

function DeviceReview({ review }) {
  const { device, ports, services, findings, cveMatches } = review
  const groups = [
    { title: 'Ports', items: ports },
    { title: 'Services', items: services },
    { title: 'Findings', items: findings },
    { title: 'CVE Matches', items: cveMatches },
  ]

  return (
    <>
      <div className="network-device-summary">
        <div><span>IP</span><strong className="mono">{device.last_ip_address}</strong></div>
        <div><span>Hostname</span><strong>{device.hostname ?? 'Unknown'}</strong></div>
        <div><span>Vendor</span><strong>{device.vendor ?? 'Unknown'}</strong></div>
        <div><span>Identity confidence</span><strong>{device.identity_confidence ?? 'Unknown'}</strong></div>
        <div><span>Status</span><DeviceStatus value={device.status} /></div>
      </div>
      <div className="network-review-grid">
        {groups.map(({ title, items }) => (
          <section key={title}>
            <div className="network-review-heading"><h4>{title}</h4><span>{items.length}</span></div>
            {items.length === 0 ? (
              <p className="network-mini-empty">No persisted {title.toLowerCase()}.</p>
            ) : title === 'Ports' ? (
              <div className="network-fact-list">
                {items.map((port) => (
                  <div key={port.id} className="network-fact-row">
                    <span className="mono">{port.port_number}/{port.transport}</span><strong>{port.state}</strong>
                  </div>
                ))}
              </div>
            ) : title === 'Services' ? (
              <div className="network-service-list">
                {items.map((service) => (
                  <div key={service.id} className="network-service-row">
                    <strong>{service.service_name ?? 'Unknown service'}</strong>
                    <span>{service.product ?? 'No product evidence'}{service.version ? ` · ${service.version}` : ''}</span>
                    <small>Confidence: {service.confidence}</small>
                  </div>
                ))}
              </div>
            ) : title === 'Findings' ? (
              <div className="network-service-list">
                {items.map((finding) => (
                  <div key={finding.id} className="network-service-row">
                    <div className="network-finding-top">
                      <strong>{finding.title}</strong>
                      <span className={`security-badge security-badge-${String(finding.severity).toLowerCase()}`}>{finding.severity}</span>
                    </div>
                    <span>{finding.reason}</span>
                    <small>{finding.status} · confidence {finding.confidence}</small>
                  </div>
                ))}
              </div>
            ) : (
              <div className="network-service-list">
                {items.map((match) => (
                  <div key={match.id} className="network-service-row">
                    <strong>{match.cve_id ?? `Match #${match.id}`}</strong>
                    <span>{match.match_status ?? match.status ?? 'Review'}</span>
                    <small>Confidence: {match.confidence ?? 'Unknown'}</small>
                  </div>
                ))}
              </div>
            )}
          </section>
        ))}
      </div>
    </>
  )
}

export default NetworkWorkspace
