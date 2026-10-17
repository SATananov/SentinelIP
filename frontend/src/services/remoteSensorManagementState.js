export function enrollmentLifecycle(enrollment, now = Date.now()) {
  if (enrollment?.revoked_at) return 'Revoked'
  if (enrollment?.consumed_at) return 'Consumed'
  const expires = Date.parse(enrollment?.expires_at ?? '')
  if (Number.isFinite(expires) && expires <= now) return 'Expired'
  return 'Pending'
}

export function canRevokeEnrollment(enrollment, now = Date.now()) {
  return enrollmentLifecycle(enrollment, now) === 'Pending'
}

export function canReenableSensor(sensor) {
  return Boolean(sensor) && sensor.status !== 'REVOKED'
}

export function createManagementRequestGuard() {
  let generation = 0
  let context = ''
  return {
    begin(nextContext) { generation += 1; context = nextContext; return { generation, context } },
    invalidate(nextContext = context) { generation += 1; context = nextContext },
    isCurrent(request) { return request?.generation === generation && request?.context === context },
  }
}
