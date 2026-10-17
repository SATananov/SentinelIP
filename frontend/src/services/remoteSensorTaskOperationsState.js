const CAPABILITY_TASKS = Object.freeze({
  HOST_DISCOVERY: 'DISCOVER_NETWORK',
  SERVICE_DISCOVERY: 'DISCOVER_SERVICES',
})

export function availableRemoteTaskTypes(sensor) {
  if (!sensor || !sensor.id || sensor.enabled !== true || sensor.site_enabled !== true
      || sensor.status === 'DISABLED' || sensor.status === 'REVOKED') return []
  const declared = new Set(Array.isArray(sensor.capabilities) ? sensor.capabilities : [])
  return Object.entries(CAPABILITY_TASKS)
    .filter(([capability]) => declared.has(capability))
    .map(([, taskType]) => taskType)
}

export function taskCreationConfirmation(operation, scope, device, sensor) {
  if (operation === 'DISCOVER_NETWORK') {
    return `Create a network discovery task for ${scope?.scope_name ?? 'selected scope'} on ${sensor?.name ?? 'selected sensor'}? It will run only if the sensor claims it before the 15-minute expiry.`
  }
  if (operation === 'DISCOVER_SERVICES') {
    return `Create a service discovery task for ${device?.ip_address ?? 'selected device'} on ${sensor?.name ?? 'selected sensor'}? It will run only if the sensor claims it before the 15-minute expiry.`
  }
  return ''
}

export function createTaskOperationRequestGuard() {
  let generation = 0
  return {
    begin() { generation += 1; return generation },
    invalidate() { generation += 1 },
    isCurrent(candidate) { return candidate === generation },
  }
}

export function taskCreationResultMessage(task) {
  if (!task || task.status !== 'PENDING') return 'Task creation was not confirmed.'
  return `Task queued · ${task.id} · Pending. It will run only if the sensor claims it before expiry.`
}
