export function isAssessmentScopeAllowed(scope, network, canScanPublicCidr) {
  if (!scope || scope.authorized !== true || scope.enabled !== true ||
      !scope.authorization_confirmed_at || !scope.authorization_confirmation_version ||
      !scope.authorization_source) return false
  if (scope.scope_type === 'PRIVATE_NETWORK') return Boolean(network &&
    network.id === scope.network_id && network.authorized === true && network.enabled === true &&
    network.cidr === scope.canonical_target)
  if (scope.scope_type === 'PUBLIC_IPV4') return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(scope.canonical_target || '') &&
    scope.canonical_target.split('.').every((part) => Number(part) <= 255)
  if (scope.scope_type === 'HOSTNAME') return scope.resolution_status === 'CURRENT' &&
    Array.isArray(scope.approved_addresses) && scope.approved_addresses.length > 0
  if (scope.scope_type === 'PUBLIC_CIDR') return canScanPublicCidr(scope)
  return false
}

export function availableAssessmentScopes(scopes, networks, canScanPublicCidr) {
  if (!Array.isArray(scopes) || !Array.isArray(networks)) return []
  return scopes.flatMap((scope) => {
    const network = scope.scope_type === 'PRIVATE_NETWORK'
      ? networks.find((item) => item.id === scope.network_id) : null
    if (!isAssessmentScopeAllowed(scope, network, canScanPublicCidr)) return []
    return [{ key: `${scope.scope_type}:${scope.id}`, scope, network,
      label: `${scope.name || scope.canonical_target} · ${scope.canonical_target} (${scope.scope_type.replaceAll('_', ' ').toLowerCase()})` }]
  })
}
