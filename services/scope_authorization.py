from collections.abc import Mapping

from services.scope_models import ScopeType
from services.target_policy import TargetPolicyError, validate_cidr


class ScopeAuthorizationError(ValueError):
    """Raised when a stored network lacks an enabled confirmed scope."""


def require_private_network_scope(network, scope) -> None:
    if not isinstance(network, Mapping) or not isinstance(scope, Mapping):
        raise ScopeAuthorizationError(
            "A persisted network and associated scope are required."
        )

    if network.get("authorized") is not True:
        raise ScopeAuthorizationError("The network is not authorized.")
    if network.get("enabled") is not True:
        raise ScopeAuthorizationError("The network is disabled.")

    if scope.get("scope_type") != ScopeType.PRIVATE_NETWORK.value:
        raise ScopeAuthorizationError("The associated scope is not private.")
    if scope.get("authorized") is not True:
        raise ScopeAuthorizationError("The scope is not authorized.")
    if scope.get("enabled") is not True:
        raise ScopeAuthorizationError("The scope is disabled.")
    if not all(
        isinstance(scope.get(field), str) and scope[field].strip()
        for field in (
            "authorization_confirmed_at",
            "authorization_confirmation_version",
            "authorization_source",
        )
    ):
        raise ScopeAuthorizationError(
            "The scope has no persisted authorization confirmation."
        )

    network_id = network.get("id")
    if (
        not isinstance(network_id, int)
        or isinstance(network_id, bool)
        or scope.get("network_id") != network_id
    ):
        raise ScopeAuthorizationError(
            "The scope is not associated with this network."
        )

    cidr = network.get("cidr")
    if not isinstance(cidr, str):
        raise ScopeAuthorizationError("The network CIDR is invalid.")
    try:
        canonical_cidr = validate_cidr(cidr).cidr
    except TargetPolicyError as exc:
        raise ScopeAuthorizationError("The network CIDR is invalid.") from exc
    if scope.get("canonical_target") != canonical_cidr:
        raise ScopeAuthorizationError(
            "The scope target does not match the network CIDR."
        )
