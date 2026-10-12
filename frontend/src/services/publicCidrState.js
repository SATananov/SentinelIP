export const PUBLIC_CIDR_CONFIRMATION_VERSION = 'public_cidr_authorization_v1'

const validCount = (value) => [1, 2, 4, 8].includes(value)

export function canScanPublicCidr(scope) {
  return scope?.scope_type === 'PUBLIC_CIDR' && scope.authorized === true && scope.enabled === true &&
    Boolean(scope.authorization_confirmed_at) && Boolean(scope.authorization_source) &&
    scope.authorization_confirmation_version === PUBLIC_CIDR_CONFIRMATION_VERSION && validCount(scope.address_count)
}

export function canSavePublicCidr(preview, confirmed, busy) {
  return !busy && confirmed === true && Boolean(preview?.canonical_target) &&
    preview?.maximum_addresses === 8 && preview?.enumeration === 'ALL_ADDRESSES' && validCount(preview?.address_count)
}
