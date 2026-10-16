const AGE_LABELS = { LT_1H: '< 1h', H1_24: '1h–24h', D1_3: '1d–3d', D3_7: '3d–7d', GT_7D: '> 7d' }

export function formatReviewAge(seconds, bucket) {
  if (seconds === null || seconds === undefined || !bucket) return '—'
  return AGE_LABELS[bucket] || '—'
}

export function formatSiteWorkloadAge(seconds) {
  if (seconds === null || seconds === undefined) return '—'
  const days = Math.floor(seconds / 86400)
  if (days > 0) return `${days}d`
  const hours = Math.floor(seconds / 3600)
  if (hours > 0) return `${hours}h`
  return `${Math.floor(seconds / 60)}m`
}
