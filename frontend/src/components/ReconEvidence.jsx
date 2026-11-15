import { useEffect, useState } from 'react'
import { addReconEvidence, listReconEvidence, loadReconEvidenceImage, removeReconEvidence } from '../services/reconEvidenceApi.js'
import { buildEvidenceCaptureCard, createEvidenceCaptureBlob, fileToBase64, MAX_CAPTURE_BYTES } from '../services/reconEvidenceCapture.js'

function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('Could not read the screenshot.'))
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '')
    reader.readAsDataURL(file)
  })
}

export default function ReconEvidence({ deviceId, device, ports = [], services = [], findings = [] }) {
  const [items, setItems] = useState([])
  const [file, setFile] = useState(null)
  const [description, setDescription] = useState('')
  const [findingId, setFindingId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [preview, setPreview] = useState(null)
  const [captureFindingId, setCaptureFindingId] = useState('')
  const [captureBusy, setCaptureBusy] = useState(false)
  const [captureError, setCaptureError] = useState('')
  const [capture, setCapture] = useState(null)
  const [captureDescription, setCaptureDescription] = useState('')

  useEffect(() => {
    let active = true
    listReconEvidence(deviceId).then((rows) => { if (active) setItems(rows) })
      .catch((err) => { if (active) setError(err.message) })
    return () => { active = false }
  }, [deviceId])

  useEffect(() => () => {
    if (capture?.previewUrl) URL.revokeObjectURL(capture.previewUrl)
  }, [capture])

  async function upload(event) {
    event.preventDefault()
    if (!file || !description.trim() || busy) return
    setBusy(true); setError('')
    try {
      const image_base64 = await readFile(file)
      const item = await addReconEvidence(deviceId, {
        filename: file.name, description: description.trim(), image_base64,
        finding_id: findingId ? Number(findingId) : null,
      })
      setItems((current) => [item, ...current]); setFile(null); setDescription(''); setFindingId('')
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  async function openImage(id) {
    setBusy(true); setError('')
    try { setPreview(await loadReconEvidenceImage(deviceId, id)) }
    catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  async function removeImage(id) {
    if (!window.confirm('Delete this screenshot?')) return
    setBusy(true); setError('')
    try {
      await removeReconEvidence(deviceId, id)
      setItems((current) => current.filter((item) => item.id !== id))
      if (preview?.id === id) setPreview(null)
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  async function captureEvidence() {
    if (!device || captureBusy || busy) return
    setCaptureBusy(true)
    setCaptureError('')
    try {
      const finding = findings.find((item) => String(item.id) === captureFindingId) || null
      const card = buildEvidenceCaptureCard({ device, ports, services, finding })
      const blob = await createEvidenceCaptureBlob(card)
      const previewUrl = URL.createObjectURL(blob)
      setCapture({ blob, previewUrl, card, finding })
      setCaptureDescription(`SentinelIP application view for ${device.last_ip_address || `device ${device.id}`}${finding ? ` — ${finding.title || `finding ${finding.id}`}` : ''}`.slice(0, 500))
    } catch (err) { setCaptureError(err.message) }
    finally { setCaptureBusy(false) }
  }

  function cancelCapture() {
    setCapture(null)
    setCaptureDescription('')
    setCaptureError('')
  }

  async function saveCapture() {
    if (!capture || !captureDescription.trim() || captureBusy) return
    if (capture.blob.size > MAX_CAPTURE_BYTES) {
      setCaptureError('Screenshot must be 1 MB or smaller.')
      return
    }
    setCaptureBusy(true)
    setCaptureError('')
    try {
      const item = await addReconEvidence(deviceId, {
        filename: `sentinelip-device-${deviceId}-${capture.card.finding_id || 'device'}.png`,
        description: captureDescription.trim(),
        image_base64: await fileToBase64(capture.blob),
        finding_id: capture.card.finding_id,
      })
      setItems((current) => [item, ...current])
      cancelCapture()
    } catch (err) { setCaptureError(err.message) }
    finally { setCaptureBusy(false) }
  }

  return <section className="recon-screenshots" aria-label="Screenshots and evidence">
    <h4>Screenshots and evidence</h4>
    <p className="recon-muted">Attach screenshots of actual findings. Remove sensitive details before uploading.</p>
    <div className="recon-capture-panel" aria-label="Evidence panel to capture">
      <div className="recon-section-heading"><div><h4>Evidence panel</h4><p className="recon-muted">Device #{device?.id} · {device?.last_ip_address || 'IP address not recorded'}</p></div></div>
      <label className="recon-field">Evidence relates to
        <select value={captureFindingId} disabled={captureBusy || Boolean(capture)} onChange={(event) => setCaptureFindingId(event.target.value)}>
          <option value="">Device evidence</option>
          {findings.map((finding) => <option key={finding.id} value={String(finding.id)}>{finding.title || `Finding ${finding.id}`}</option>)}
        </select>
      </label>
      <div className="recon-capture-card">
        {buildEvidenceCaptureCard({ device, ports, services, finding: findings.find((item) => String(item.id) === captureFindingId) || null }).lines.map((line, index) => <p key={`${line.label}-${index}`}><strong>{line.label}</strong><span>{line.value}</span></p>)}
      </div>
      <p className="recon-muted">The image is a capture of this SentinelIP application view. It is not independent proof that a remote service is currently reachable.</p>
      <button type="button" disabled={!device || busy || captureBusy || Boolean(capture)} onClick={captureEvidence}>{captureBusy ? 'Preparing preview…' : 'Capture Evidence'}</button>
    </div>
    {captureError && <p role="alert" className="recon-error">{captureError}</p>}
    {capture && <div className="recon-capture-preview" aria-label="Captured evidence preview">
      <h4>Review captured evidence</h4>
      <p><strong>Device:</strong> #{capture.card.device_id} · {device?.last_ip_address || 'IP address not recorded'}</p>
      <p><strong>Finding:</strong> {capture.finding ? `#${capture.finding.id} · ${capture.finding.title || 'Title not recorded'}` : 'Device evidence'}</p>
      <img src={capture.previewUrl} alt={`Captured SentinelIP evidence panel for device ${capture.card.device_id}`} />
      <label>Evidence description
        <input value={captureDescription} maxLength={500} disabled={captureBusy} onChange={(event) => setCaptureDescription(event.target.value)} />
      </label>
      <p className="recon-muted">Confirm to save this PNG to the selected device's existing evidence record.</p>
      <div className="recon-capture-actions"><button type="button" disabled={captureBusy || !captureDescription.trim()} onClick={saveCapture}>{captureBusy ? 'Saving…' : 'Confirm and Save'}</button><button type="button" disabled={captureBusy} onClick={cancelCapture}>Cancel</button></div>
      {captureError && <p role="alert" className="recon-error">{captureError}</p>}
    </div>}
    <form onSubmit={upload} className="recon-screenshot-form">
      <label>Screenshot (PNG or JPG, up to 1 MB)
        <input type="file" accept="image/png,image/jpeg" required disabled={busy || captureBusy || Boolean(capture)} onChange={(e) => setFile(e.target.files?.[0] || null)}/>
      </label>
      <label>What does this show?
        <input value={description} maxLength={500} required disabled={busy || captureBusy || Boolean(capture)} onChange={(e) => setDescription(e.target.value)} placeholder="Describe the evidence"/>
      </label>
      <label>Related finding
        <select value={findingId} disabled={busy || captureBusy || Boolean(capture)} onChange={(e) => setFindingId(e.target.value)}>
          <option value="">General device evidence</option>
          {findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.title || `Finding ${finding.id}`}</option>)}
        </select>
      </label>
      <button type="submit" disabled={busy || captureBusy || Boolean(capture) || !file || !description.trim() || file.size > 1048576}>{busy ? 'Saving…' : 'Add Screenshot'}</button>
    </form>
    {file?.size > 1048576 && <p className="recon-error">Screenshot must be 1 MB or smaller.</p>}
    {error && <p role="alert" className="recon-error">{error}</p>}
    {items.length ? <div className="recon-image-list">{items.map((item) => <div key={item.id} className="recon-image-row">
      <div><strong>{item.description}</strong><small>{item.filename} · {item.created_at}</small><small>{item.finding_id ? `Finding #${item.finding_id}` : 'Device evidence'}</small></div>
      <div className="recon-image-actions"><button type="button" disabled={busy} onClick={() => openImage(item.id)}>View</button><button type="button" disabled={busy} onClick={() => removeImage(item.id)}>Delete</button></div>
    </div>)}</div> : <p className="recon-muted">No screenshots attached yet.</p>}
    {preview && <div className="recon-image-preview"><div className="recon-section-heading"><strong>{preview.description}</strong><button type="button" onClick={() => setPreview(null)}>Close</button></div><img src={`data:${preview.media_type};base64,${preview.image_base64}`} alt={preview.description}/></div>}
  </section>
}
