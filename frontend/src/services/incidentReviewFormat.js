const AGE_LABELS = { LT_1H: '< 1h', H1_24: '1h–24h', D1_3: '1d–3d', D3_7: '3d–7d', GT_7D: '> 7d' }

export function formatReviewAge(seconds, bucket) {
  if (seconds === null || seconds === undefined || !bucket) return '—'
  return AGE_LABELS[bucket] || '—'
}
