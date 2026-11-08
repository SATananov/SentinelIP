import { API_BASE } from './apiBase.js'

async function evidenceRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, { cache: 'no-store', ...options })
  if (!response.ok) {
    let detail = ''
    try { const body = await response.json(); detail = body.detail || '' } catch { detail = '' }
    throw new Error(detail || `Evidence request failed (${response.status})`)
  }
  return response.status === 204 ? null : response.json()
}

export function listReconEvidence(deviceId) {
  return evidenceRequest(`/recon/devices/${deviceId}/evidence`)
}

export function addReconEvidence(deviceId, data) {
  return evidenceRequest(`/recon/devices/${deviceId}/evidence`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  })
}

export function loadReconEvidenceImage(deviceId, evidenceId) {
  return evidenceRequest(`/recon/devices/${deviceId}/evidence/${evidenceId}`)
}

export function removeReconEvidence(deviceId, evidenceId) {
  return evidenceRequest(`/recon/devices/${deviceId}/evidence/${evidenceId}`, { method: 'DELETE' })
}
