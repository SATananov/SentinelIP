const MAX_EXPORT_RANGE_MS = 31 * 24 * 60 * 60 * 1000

export function localDateTimeToRfc3339(value) {
  if (!value) return null
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value)
  if (!match) return null

  const [, year, month, day, hour, minute] = match
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return null
  const localParts = [
    String(date.getFullYear()).padStart(4, '0'),
    String(date.getMonth() + 1).padStart(2, '0'),
    String(date.getDate()).padStart(2, '0'),
    String(date.getHours()).padStart(2, '0'),
    String(date.getMinutes()).padStart(2, '0'),
  ]
  const actualDate = localParts.slice(0, 3).join('-')
  if (actualDate !== `${year}-${month}-${day}`
      || localParts[3] !== hour || localParts[4] !== minute) return null

  return date.toISOString()
}

export function isCustomExportRangeValid(fromLocal, untilLocal) {
  const from = localDateTimeToRfc3339(fromLocal)
  const until = localDateTimeToRfc3339(untilLocal)
  if (!from || !until) return false
  const elapsed = Date.parse(until) - Date.parse(from)
  return elapsed > 0 && elapsed <= MAX_EXPORT_RANGE_MS
}

export function buildExportQuery({
  rangeMode = 'preset',
  timeRange = 'all',
  fromLocal = '',
  untilLocal = '',
  severity = 'ALL',
  sourceIp = 'ALL',
} = {}) {
  const params = new URLSearchParams()
  if (rangeMode === 'custom') {
    if (!isCustomExportRangeValid(fromLocal, untilLocal)) return null
    params.set('from', localDateTimeToRfc3339(fromLocal))
    params.set('until', localDateTimeToRfc3339(untilLocal))
  } else {
    if (!['15m', '1h', '24h', 'all'].includes(timeRange)) return null
    params.set('time_range', timeRange)
  }

  if (severity !== 'ALL') params.set('severity', severity)
  if (sourceIp !== 'ALL') params.set('source_ip', sourceIp)
  return params
}

export function exportErrorMessage(status) {
  if (status === 413) return 'Export is too large. Narrow the date range or filters and try again.'
  if (status === 422) return 'The export filters are invalid. Check the selected range and filters.'
  return 'The export could not be generated. Try again or narrow the filters.'
}
