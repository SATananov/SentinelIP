import { API_BASE } from './apiBase.js'

export async function loadDataLifecyclePreview(signal) {
  const response = await fetch(API_BASE + '/data-lifecycle/preview', {
    method: 'GET',
    cache: 'no-store',
    signal,
  })
  if (!response.ok) {
    throw new Error('Data lifecycle preview is unavailable (' + response.status + ').')
  }
  return response.json()
}

const CLEANUP_CLASSES = new Set(['DNS_OBSERVATIONS', 'WEB_OBSERVATIONS'])

export async function cleanupDataLifecycle(dataClass, signal) {
  if (!CLEANUP_CLASSES.has(dataClass)) {
    throw new Error('Unsupported lifecycle cleanup data class.')
  }
  const response = await fetch(API_BASE + '/data-lifecycle/cleanup', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data_class: dataClass }),
    signal,
  })
  if (!response.ok) {
    throw new Error('Data lifecycle cleanup is unavailable (' + response.status + ').')
  }
  return response.json()
}
