import pytest

from services.hostname_resolution import (
    HostnameResolutionError,
    HostnameResolver,
    IneligibleHostnameResolution,
)


def test_resolver_sorts_deduplicates_and_canonicalizes_results():
    resolver = HostnameResolver(
        lookup=lambda hostname: ["8.8.4.4", "8.8.8.8", "8.8.4.4"],
    )
    result = resolver.resolve("Example.com.")
    assert result.canonical_hostname == "example.com"
    assert result.resolved_ipv4 == ("8.8.4.4", "8.8.8.8")


@pytest.mark.parametrize(
    "addresses",
    [
        [],
        ["10.0.0.1"],
        ["127.0.0.1"],
        ["169.254.1.1"],
        ["100.64.0.1"],
        ["192.0.2.1"],
        ["224.0.0.1"],
        ["8.8.8.8", "10.0.0.1"],
        ["2001:4860:4860::8888"],
    ],
)
def test_ineligible_resolution_fails_closed(addresses):
    resolver = HostnameResolver(lookup=lambda hostname: addresses)
    with pytest.raises(IneligibleHostnameResolution):
        resolver.resolve("example.com")


def test_resolver_failure_and_timeout_are_bounded():
    def fail(_hostname):
        raise OSError("private resolver detail")

    with pytest.raises(HostnameResolutionError, match="DNS resolution failed"):
        HostnameResolver(lookup=fail).resolve("example.com")

    with pytest.raises(HostnameResolutionError, match="timed out"):
        HostnameResolver(lookup=lambda _hostname: __import__("time").sleep(0.1), timeout_seconds=0.01).resolve("example.com")


def test_resolver_enforces_address_count_limit():
    addresses = [f"8.8.8.{number}" for number in range(1, 18)]
    with pytest.raises(IneligibleHostnameResolution, match="too many"):
        HostnameResolver(lookup=lambda _hostname: addresses, max_addresses=2).resolve("example.com")
