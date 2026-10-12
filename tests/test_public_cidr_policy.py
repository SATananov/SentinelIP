import pytest

from services.public_cidr_policy import normalize_public_cidr, public_cidr_addresses, PublicCIDRPolicyError


@pytest.mark.parametrize('prefix,count', [(32, 1), (31, 2), (30, 4), (29, 8)])
def test_exact_enumeration_includes_both_endpoints(prefix, count):
    target = f'8.8.8.0/{prefix}'
    assert normalize_public_cidr(target) == target
    assert public_cidr_addresses(target) == tuple(f'8.8.8.{i}' for i in range(count))


def test_host_bits_are_canonicalized_without_widening_prefix():
    assert normalize_public_cidr(' 8.8.8.7/29 ') == '8.8.8.0/29'


@pytest.mark.parametrize('target', [
    '8.8.8.0/28', '8.8.8.0/27', '8.8.8.0/24', '8.8.0.0/16', '8.0.0.0/8', '0.0.0.0/0',
    '10.0.0.0/29', '172.16.0.0/29', '192.168.0.0/29', '127.0.0.0/29',
    '169.254.0.0/29', '224.0.0.0/29', '0.0.0.0/32', '240.0.0.0/29',
    '100.64.0.0/29', '192.0.2.0/29', '198.51.100.0/29', '203.0.113.0/29',
    '198.18.0.0/29', '192.0.0.8/29', '192.31.196.0/29', '255.255.255.255/32',
    '2001:4860::/32', '::/128', '', 'example.com/29', '8.8.8.8', '8.8.8.8/33',
    '8.8.8.8/-1', '8.8.8.8/255.255.255.248', 'https://8.8.8.8/29',
])
def test_rejects_nonpublic_oversized_and_malformed(target):
    with pytest.raises(PublicCIDRPolicyError):
        normalize_public_cidr(target)


def test_every_address_is_validated(monkeypatch):
    import services.public_cidr_policy as policy
    seen = []
    def validate(address):
        seen.append(address)
        if address == '8.8.8.5':
            raise ValueError('synthetic special-purpose member')
        return address
    monkeypatch.setattr(policy, 'normalize_public_ipv4', validate)
    with pytest.raises(PublicCIDRPolicyError):
        public_cidr_addresses('8.8.8.0/29')
    assert seen == [f'8.8.8.{i}' for i in range(6)]
