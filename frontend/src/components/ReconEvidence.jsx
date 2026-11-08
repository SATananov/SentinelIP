import { useEffect, useState } from 'react'
import { addReconEvidence, listReconEvidence, loadReconEvidenceImage, removeReconEvidence } from '../services/reconEvidenceApi.js'

function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('Could not read the screenshot.'))
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '')
    reader.readAsDataURL(file)
  })
}

export default function ReconEvidence({ deviceId, findings = [] }) {
  const [items, setItems] = useState([])
  const [file, setFile] = useState(null)
  const [description, setDescription] = useState('')
  const [findingId, setFindingId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [preview, setPreview] = useState(null)

  useEffect(() => {
    let active = true
    setItems([]); setPreview(null); setError(''); setFile(null); setDescription(''); setFindingId('')
    listReconEvidence(deviceId).then((rows) => { if (active) setItems(rows) })
      .catch((err) => { if (active) setError(err.message) })
    return () => { active = false }
  }, [deviceId])

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

  return <section className="recon-screenshots" aria-label="Screenshots and evidence">
    <h4>Screenshots and evidence</h4>
    <p className="recon-muted">Attach screenshots of actual findings. Remove sensitive details before uploading.</p>
    <form onSubmit={upload} className="recon-screenshot-form">
      <label>Screenshot (PNG or JPG, up to 1 MB)
        <input type="file" accept="image/png,image/jpeg" required disabled={busy} onChange={(e) => setFile(e.target.files?.[0] || null)}/>
      </label>
      <label>What does this show?
        <input value={description} maxLength={500} required disabled={busy} onChange={(e) => setDescription(e.target.value)} placeholder="Describe the evidence"/>
      </label>
      <label>Related finding
        <select value={findingId} disabled={busy} onChange={(e) => setFindingId(e.target.value)}>
          <option value="">General device evidence</option>
          {findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.title || `Finding ${finding.id}`}</option>)}
        </select>
      </label>
      <button type="submit" disabled={busy || !file || !description.trim() || file.size > 1048576}>{busy ? 'Saving…' : 'Add Screenshot'}</button>
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
