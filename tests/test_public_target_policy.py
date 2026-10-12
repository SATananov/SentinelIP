import pytest

from services.public_target_policy import (
    PublicTargetPolicyError,
    normalize_public_ipv4,
)


@pytest.mark.parametrize("target", ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
def test_accepts_global_unicast_ipv4(target):
    assert normalize_public_ipv4(target) == target


def test_canonicalizes_whitespace_and_decimal_ipv4():
    assert normalize_public_ipv4(" 1.1.1.1 ") == "1.1.1.1"


@pytest.mark.parametrize(
    "target",
    [
        "10.1.2.3",
        "172.16.1.1",
        "192.168.1.1",
        "192.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "240.0.0.1",
        "100.64.0.1",
        "192.0.2.1",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.175.48.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "255.255.255.255",
        "2001:4860:4860::8888",
        "example.test",
        "8.8.8.8/32",
        "not-an-address",
        "",
    ],
)
def test_rejects_private_or_special_target_classes(target):
    with pytest.raises(PublicTargetPolicyError):
        normalize_public_ipv4(target)
