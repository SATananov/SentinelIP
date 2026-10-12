import { canScanPublicCidr, canSavePublicCidr, PUBLIC_CIDR_CONFIRMATION_VERSION } from '../services/publicCidrState.js'
import { useState } from 'react'
import { createPublicCidrScope, previewPublicCidr } from '../services/networkApi.js'

export default function PublicCidrTargets({ scopes, selectedScope, busy, scanning, onBusyChange, onCreated, onSelect, onScan }) {
  const [target, setTarget] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [preview, setPreview] = useState(null)
  const [confirmed, setConfirmed] = useState(false)
  const [action, setAction] = useState(null)
  const [error, setError] = useState(null)

  async function validateRange() {
    setPreview(null)
    setConfirmed(false)
    setError(null)
    setAction('preview')
    onBusyChange(true)
    try {
      setPreview(await previewPublicCidr({ target }))
    } catch (err) {
      setError(err.message)
    } finally {
      setAction(null)
      onBusyChange(false)
    }
  }

  async function save(event) {
    event.preventDefault()
    if (!canSavePublicCidr(preview, confirmed, busy)) return
    setAction('save')
    onBusyChange(true)
    setError(null)
    try {
      const scope = await createPublicCidrScope({
        target: preview.canonical_target, name, description,
        authorization_confirmed: true,
        authorization_confirmation_version: PUBLIC_CIDR_CONFIRMATION_VERSION,
      })
      onCreated(scope)
      setTarget('')
      setName('')
      setDescription('')
      setPreview(null)
      setConfirmed(false)
    } catch (err) {
      setError(err.message)
      setConfirmed(false)
    } finally {
      setAction(null)
      onBusyChange(false)
    }
  }

  return (
    <div className="hostname-target-list-section">
      <h4>Authorized Public CIDR</h4>
      <p className="network-candidate-note">
        Maximum allowed: 8 addresses (/29). /29–/32 only. Every address, including the first and last, is included. Scans run sequentially and may take several minutes.
      </p>
      <form className="public-target-form" onSubmit={save}>
        <label>
          <span>CIDR</span>
          <input value={target} disabled={busy} autoComplete="off" maxLength={64} onChange={(event) => {
            setTarget(event.target.value)
            setPreview(null)
            setConfirmed(false)
            setError(null)
          }} />
        </label>
        <label>
          <span>Name (optional)</span>
          <input value={name} disabled={busy} maxLength={120} onChange={(event) => setName(event.target.value)} />
        </label>
        <label className="public-target-description">
          <span>Description (optional)</span>
          <input value={description} disabled={busy} maxLength={500} onChange={(event) => setDescription(event.target.value)} />
        </label>
        <div className="hostname-form-actions">
          <button className="network-secondary-action" type="button" onClick={validateRange} disabled={busy || !target.trim()}>
            {action === 'preview' ? 'Validating…' : 'Validate Range'}
          </button>
          {preview && <div className="hostname-preview-addresses" aria-live="polite">
            <strong className="mono">{preview.canonical_target}</strong>
            <p>{preview.address_count} addresses · Maximum allowed: {preview.maximum_addresses}</p>
          </div>}
          <label className="public-target-confirmation">
            <input type="checkbox" checked={confirmed} disabled={busy || !preview} onChange={(event) => setConfirmed(event.target.checked)} />
            <span>I confirm that I own this range or have authorization to assess every address in it.</span>
          </label>
          <button className="network-primary-action" type="submit" disabled={!canSavePublicCidr(preview, confirmed, busy)}>
            {action === 'save' ? 'Saving…' : 'Add Public CIDR'}
          </button>
        </div>
      </form>
      {error && <div className="network-error" role="alert">{error}</div>}
      {scopes.length === 0 ? <p className="network-mini-empty">No public CIDR targets are authorized.</p> : (
        <div className="authorized-scope-list">
          {scopes.map((scope) => {
            const authorized = scope.authorized === true && Boolean(scope.authorization_confirmed_at) &&
              scope.authorization_confirmation_version === PUBLIC_CIDR_CONFIRMATION_VERSION && Boolean(scope.authorization_source)
            const isSelected = selectedScope?.kind === 'PUBLIC_CIDR' && selectedScope.id === scope.id
            const eligible = canScanPublicCidr(scope)
            return (
              <div className={isSelected ? 'authorized-scope-row is-selected public-scope-row' : 'authorized-scope-row public-scope-row'} key={scope.id}>
                <div className="authorized-scope-main">
                  <strong>{scope.name || 'Public CIDR Target'}</strong>
                  <span className="mono">{scope.canonical_target}</span>
                  <small>{scope.address_count ?? 'Invalid'} addresses · Maximum allowed: 8</small>
                  <div className="workspace-scope-badges">
                    <span className={`scope-badge scope-badge-${authorized ? 'confirmed' : 'unconfirmed'}`}>{authorized ? 'Confirmed' : 'Not confirmed'}</span>
                    <span className={`scope-badge scope-badge-${scope.enabled ? 'enabled' : 'disabled'}`}>{scope.enabled ? 'Enabled' : 'Disabled'}</span>
                    <span className="scope-badge scope-badge-type">Public CIDR</span>
                  </div>
                </div>
                <div className="authorized-scope-actions">
                  <button className="network-secondary-action" type="button" disabled={busy} onClick={() => onSelect(scope)}>{isSelected ? 'Selected' : 'Select'}</button>
                  <button className="network-primary-action" type="button" disabled={busy || !eligible} onClick={() => onScan(scope)}>{scanning && isSelected ? 'Scanning…' : 'Scan Target'}</button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
