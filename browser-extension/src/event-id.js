export function createEventId(randomUUID = globalThis.crypto?.randomUUID) {
  if (typeof randomUUID === 'function') {
    return randomUUID.call(globalThis.crypto)
  }

  const randomPart = Math.random().toString(36).slice(2)
  return `sentinelip-${Date.now().toString(36)}-${randomPart}`
}