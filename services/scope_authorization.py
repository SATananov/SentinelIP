from collections.abc import Mapping

from services.scope_models import ScopeType
from services.public_target_policy import (
    PublicTargetPolicyError,
    normalize_public_ipv4,
)
from services.hostname_policy import HostnamePolicyError, normalize_hostname
from services.target_policy import TargetPolicyError, validate_cidr


class ScopeAuthorizationError(ValueError):
    """Raised when a stored network lacks an enabled confirmed scope."""


HOSTNAME_CONFIRMATION_VERSION = "hostname_authorization_v1"


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


def require_public_ipv4_scope(scope) -> str:
    if not isinstance(scope, Mapping):
        raise ScopeAuthorizationError("A persisted public scope is required.")
    if scope.get("scope_type") != ScopeType.PUBLIC_IPV4.value:
        raise ScopeAuthorizationError("The scope is not a public IPv4 target.")
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
    try:
        canonical_target = normalize_public_ipv4(scope.get("canonical_target"))
    except PublicTargetPolicyError as exc:
        raise ScopeAuthorizationError("The stored public target is invalid.") from exc
    if canonical_target != scope.get("canonical_target"):
        raise ScopeAuthorizationError(
            "The stored public target is not canonical."
        )
    if type(scope.get("id")) is not int or scope["id"] <= 0:
        raise ScopeAuthorizationError("The public scope ID is invalid.")
    return canonical_target


def require_hostname_scope(scope, *, require_current=True, require_enabled=True) -> str:
    if not isinstance(scope, Mapping):
        raise ScopeAuthorizationError("A persisted hostname scope is required.")
    if scope.get("scope_type") != ScopeType.HOSTNAME.value:
        raise ScopeAuthorizationError("The scope is not a hostname target.")
    if scope.get("authorized") is not True:
        raise ScopeAuthorizationError("The hostname scope is not authorized.")
    if require_enabled and scope.get("enabled") is not True:
        raise ScopeAuthorizationError("The hostname scope is disabled.")
    if not all(
        isinstance(scope.get(field), str) and scope[field].strip()
        for field in (
            "authorization_confirmed_at",
            "authorization_confirmation_version",
            "authorization_source",
        )
    ):
        raise ScopeAuthorizationError(
            "The hostname scope has no persisted authorization confirmation."
        )
    if scope.get("authorization_confirmation_version") != HOSTNAME_CONFIRMATION_VERSION:
        raise ScopeAuthorizationError("The hostname scope uses an unsupported authorization confirmation.")
    try:
        hostname = normalize_hostname(scope.get("canonical_target"))
    except HostnamePolicyError as exc:
        raise ScopeAuthorizationError("The stored hostname is invalid.") from exc
    if hostname != scope.get("canonical_target"):
        raise ScopeAuthorizationError("The stored hostname is not canonical.")
    if type(scope.get("id")) is not int or scope["id"] <= 0:
        raise ScopeAuthorizationError("The hostname scope ID is invalid.")
    if require_current and (
        scope.get("resolution_status") != "CURRENT"
        or not isinstance(scope.get("resolution_verified_at"), str)
        or not scope["resolution_verified_at"].strip()
        or not isinstance(scope.get("resolution_version"), str)
        or not scope["resolution_version"].strip()
    ):
        raise ScopeAuthorizationError("Hostname re-authorization is required.")
    return hostname
