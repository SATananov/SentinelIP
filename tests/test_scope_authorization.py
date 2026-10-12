import pytest

from services.scope_authorization import (
    ScopeAuthorizationError,
    require_private_network_scope,
)


@pytest.fixture
def authorized_records():
    network = {
        "id": 7,
        "cidr": "192.168.20.0/24",
        "authorized": True,
        "enabled": True,
    }
    scope = {
        "id": 12,
        "network_id": 7,
        "scope_type": "PRIVATE_NETWORK",
        "canonical_target": "192.168.20.0/24",
        "authorized": True,
        "enabled": True,
        "authorization_confirmed_at": "2026-10-12T10:00:00",
        "authorization_confirmation_version": "test-v1",
        "authorization_source": "test-fixture",
    }
    return network, scope


def test_confirmed_enabled_private_scope_is_accepted(authorized_records):
    require_private_network_scope(*authorized_records)


@pytest.mark.parametrize(
    ("network_field", "scope_field", "value"),
    [
        ("authorized", None, False),
        ("enabled", None, False),
        (None, "scope_type", "HOSTNAME"),
        (None, "authorized", False),
        (None, "enabled", False),
        (None, "authorization_confirmed_at", None),
        (None, "authorization_confirmation_version", None),
        (None, "authorization_source", None),
        (None, "network_id", 8),
        (None, "canonical_target", "192.168.21.0/24"),
    ],
)
def test_invalid_network_or_scope_is_rejected(
    authorized_records, network_field, scope_field, value
):
    network, scope = authorized_records
    if network_field:
        network[network_field] = value
    if scope_field:
        scope[scope_field] = value

    with pytest.raises(ScopeAuthorizationError):
        require_private_network_scope(network, scope)


def test_invalid_private_network_policy_is_rejected(authorized_records):
    network, scope = authorized_records
    network["cidr"] = "8.8.8.0/24"
    scope["canonical_target"] = "8.8.8.0/24"

    with pytest.raises(ScopeAuthorizationError):
        require_private_network_scope(network, scope)
