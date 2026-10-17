export const TASK_STATUS_LABELS = Object.freeze({
  PENDING: 'Pending', CLAIMED: 'Claimed', RUNNING: 'Running', COMPLETED: 'Completed',
  FAILED: 'Failed', CANCELLED: 'Cancelled', UNKNOWN: 'Unknown',
})

export const TASK_TYPE_LABELS = Object.freeze({
  DISCOVER_NETWORK: 'Discover network', DISCOVER_SERVICES: 'Discover services', UNKNOWN: 'Unknown',
})

export function createTaskHistoryRequestGuard() {
  let generation = 0
  return {
    begin() { generation += 1; return generation },
    invalidate() { generation += 1 },
    isCurrent(candidate) { return candidate === generation },
  }
}

export function taskHistoryQueryKey(filters) {
  return JSON.stringify(filters)
}

export function updateTaskHistoryFilter(current, key, value) {
  return { ...current, [key]: value, offset: 0 }
}

export function updateTaskHistoryPage(current, direction, hasMore) {
  if (direction === 'next' && hasMore) return { ...current, offset: Math.min(100000, current.offset + current.limit) }
  if (direction === 'previous') return { ...current, offset: Math.max(0, current.offset - current.limit) }
  return current
}

export function taskStatusLabel(status) {
  return TASK_STATUS_LABELS[status] ?? 'Unknown'
}

export function taskTypeLabel(type) {
  return TASK_TYPE_LABELS[type] ?? 'Unknown'
}

export function formatTaskTimestamp(value, missing = 'Unavailable') {
  if (value === null || value === undefined || value === '') return missing
  const time = Date.parse(value)
  if (!Number.isFinite(time)) return 'Unavailable'
  return new Date(time).toLocaleString()
}

export function taskTimestampLabel(task, field) {
  const missing = {
    claimed_at: 'Not claimed', started_at: 'Not started', completed_at: 'Not completed',
    failed_at: 'No terminal failure time',
  }[field] ?? 'Unavailable'
  return formatTaskTimestamp(task?.[field], missing)
}

export function taskHistoryViewState({ loading, error, result }) {
  if (loading) return 'loading'
  if (error) return 'error'
  if (!result || !Array.isArray(result.items) || result.items.length === 0) return 'empty'
  return 'ready'
}

export function projectTaskHistoryDetail(task) {
  if (!task || typeof task !== 'object') return null
  const fields = ['id', 'sensor_id', 'sensor_name', 'site_id', 'site_name', 'scope_id',
    'scope_name', 'canonical_target', 'target_device_id', 'target_ip', 'task_type',
    'status', 'created_at', 'expires_at', 'claimed_at', 'started_at', 'completed_at',
    'failed_at', 'attempt_count', 'failure_code', 'failure_message_safe', 'expired']
  return Object.fromEntries(fields.map((field) => [field, task[field]]))
}
