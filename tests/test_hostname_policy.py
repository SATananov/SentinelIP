import pytest

from services.hostname_policy import HostnamePolicyError, normalize_hostname


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ],
)
def test_hostname_normalization(value, expected):
    assert normalize_hostname(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "example..com",
        ".example.com",
        "example.com..",
        "-bad.example",
        "bad-.example",
        "a" * 64 + ".example",
        ".".join(["a" * 63] * 4),
        "https://example.com",
        "example.com/path",
        "example.com?query",
        "example.com#fragment",
        "user@example.com",
        "example.com:443",
        "192.0.2.1",
        "999.999.999.999",
        "example .com",
    ],
)
def test_invalid_hostname_shapes_are_rejected(value):
    with pytest.raises(HostnamePolicyError):
        normalize_hostname(value)
