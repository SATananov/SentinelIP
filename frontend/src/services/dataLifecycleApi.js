const API_BASE = 'http://127.0.0.1:8000'

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
