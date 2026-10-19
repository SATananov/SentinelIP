import { API_BASE } from './apiBase.js'

export const INCIDENT_REVIEW_SEARCH_LIMIT = 20
export const INCIDENT_REVIEW_SEARCH_MAX_OFFSET = 100000

export function nextIncidentReviewSearchOffset(offset, hasMore) {
  if (!hasMore || offset >= INCIDENT_REVIEW_SEARCH_MAX_OFFSET) return offset
  return Math.min(offset + INCIDENT_REVIEW_SEARCH_LIMIT, INCIDENT_REVIEW_SEARCH_MAX_OFFSET)
}

export function previousIncidentReviewSearchOffset(offset) {
  return Math.max(0, offset - INCIDENT_REVIEW_SEARCH_LIMIT)
}

const STATES = ['OPEN', 'IN_REVIEW', 'CLOSED']
const PRIORITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const DISPOSITIONS = ['UNREVIEWED', 'EXPECTED_ACTIVITY', 'BENIGN', 'NEEDS_MONITORING',
  'ACTION_REQUIRED', 'FALSE_POSITIVE', 'INCONCLUSIVE']

function positiveId(value, name) {
  if (value === undefined || value === null || value === '') return undefined
  const id = typeof value === 'number' ? value : Number(value)
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error(`${name} must be a positive integer.`)
  return id
}

function explicitTimestamp(value, name) {
  if (value === undefined || value === null || value === '') return undefined
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/i.test(value)
      || Number.isNaN(Date.parse(value))) {
    throw new Error(`${name} must include an explicit timezone.`)
  }
  return value
}

export function buildIncidentReviewSearchQuery(filters = {}) {
  const title = typeof filters.title === 'string' ? filters.title.trim() : ''
  const searchableCount = title.match(/[\p{L}\p{N}\p{M}]/gu)?.length ?? 0
  if (searchableCount < 3) throw new Error('Enter at least three searchable title characters.')
  if (title.length > 160) throw new Error('Title search must be 160 characters or fewer.')

  const params = new URLSearchParams()
  params.set('title', title)
  for (const key of ['state', 'priority', 'disposition']) {
    const value = filters[key]
    if (value === undefined || value === null || value === '') continue
    const allowed = key === 'state' ? STATES : key === 'priority' ? PRIORITIES : DISPOSITIONS
    if (!allowed.includes(value)) throw new Error(`${key} is unsupported.`)
    params.set(key, value)
  }
  for (const key of ['site_id', 'scope_id', 'device_id']) {
    const value = positiveId(filters[key], key)
    if (value !== undefined) params.set(key, String(value))
  }
  for (const key of ['created_from', 'created_until', 'closed_from', 'closed_until']) {
    const value = explicitTimestamp(filters[key], key)
    if (value !== undefined) params.set(key, value)
  }

  const limit = filters.limit ?? INCIDENT_REVIEW_SEARCH_LIMIT
  const offset = filters.offset ?? 0
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('Search limit is out of range.')
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 100000) throw new Error('Search offset is out of range.')
  params.set('limit', String(limit))
  params.set('offset', String(offset))
  return params.toString()
}

export function loadIncidentReviewSearch(filters, signal) {
  const query = buildIncidentReviewSearchQuery(filters)
  return fetch(`${API_BASE}/incident-reviews/search?${query}`, {
    method: 'GET', cache: 'no-store', signal,
  }).catch((error) => {
    if (error?.name === 'AbortError') throw error
    throw new Error('Incident Review search is unavailable.')
  }).then(async (response) => {
    if (!response.ok) {
      const message = response.status === 422
        ? 'Check the review title and filters, then try again.'
        : 'Incident Review search failed. Try again.'
      const error = new Error(message)
      error.status = response.status
      throw error
    }
    return response.json()
  })
}

export function dateInputToSearchTimestamp(value, { exclusiveEnd = false } = {}) {
  if (!value) return ''
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value)
  if (!match) throw new Error('Enter a valid calendar date.')
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const date = new Date(year, month - 1, day)
  if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) {
    throw new Error('Enter a valid calendar date.')
  }
  if (exclusiveEnd) date.setDate(date.getDate() + 1)
  return date.toISOString()
}

export function createIncidentReviewSearchRequestController() {
  let generation = 0
  let activeController = null
  return {
    start() {
      activeController?.abort()
      activeController = new AbortController()
      const currentGeneration = ++generation
      return {
        signal: activeController.signal,
        isCurrent: () => generation === currentGeneration && !activeController.signal.aborted,
      }
    },
    abort() {
      generation += 1
      activeController?.abort()
      activeController = null
    },
  }
}

export function selectIncidentReviewSearchResult(reviewId, onSelectReview) {
  if (!Number.isSafeInteger(reviewId) || reviewId <= 0) return false
  onSelectReview?.(reviewId)
  return true
}
