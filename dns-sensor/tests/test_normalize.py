import pytest
from sentinelip_dns.normalize import domain, address, ttl, EvidenceError


@pytest.mark.parametrize("raw,expected", [(" Login.Example.TEST. ", "login.example.test"),
    ("BÜCHER.test.", "xn--bcher-kva.test"), ("XN--BCHER-KVA.test", "xn--bcher-kva.test")])
def test_domain(raw, expected):
    assert domain(raw) == expected


@pytest.mark.parametrize("raw", ["", ".", "a..", "a..b", "https://example.test", "a/b", "-a.test", "a_.test", "a"*64, "xn--.test", None])
def test_invalid_domain(raw):
    with pytest.raises(EvidenceError):
        domain(raw)


@pytest.mark.parametrize("raw", [-1, True, 1.5, "1", 2147483648])
def test_invalid_ttl(raw):
    with pytest.raises(EvidenceError):
        ttl(raw)


def test_addresses_and_ttl():
    assert address("2001:0db8::1") == "2001:db8::1"
    assert ttl(0) == 0
    assert ttl(None) is None
    with pytest.raises(EvidenceError):
        address("fe80::1%eth0")
