import pytest

from services.target_policy import (
    TargetPolicyError,
    normalize_cidr,
    validate_cidr,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.0.0/24", "192.168.0.0/24"),
        ("192.168.1.1/25", "192.168.1.0/25"),
        ("10.10.10.0/24", "10.10.10.0/24"),
        ("172.16.5.0/24", "172.16.5.0/24"),
    ],
)
def test_validate_private_ipv4_network(value, expected):
    assert validate_cidr(value).cidr == expected


def test_normalize_cidr_returns_canonical_network():
    assert normalize_cidr(" 192.168.1.9/26 ") == "192.168.1.0/26"


@pytest.mark.parametrize(
    "value",
    [
        "not-a-cidr",
        "2001:db8::/64",
        "8.8.8.0/24",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "0.0.0.0/0",
        "10.0.0.0/8",
        "192.168.0.0/23",
    ],
)
def test_validate_rejects_unsupported_network(value):
    with pytest.raises(TargetPolicyError):
        validate_cidr(value)