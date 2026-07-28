"""Tests for the adoption plan builder (``modules/core/cert_adopt.py``), #472."""

import types

import pytest

from modules.core.cert_adopt import build_adoption_plan

pytestmark = [pytest.mark.unit]


class _FakeDNS:
    def __init__(self, provider='cloudflare', configured=True, settings=None):
        self._provider = provider
        self._configured = configured
        self.settings_manager = types.SimpleNamespace(
            load_settings=lambda: (settings or {})
        )

    def suggest_dns_provider_for_domain(self, domain, settings=None):
        return (self._provider, 90) if self._provider else (None, 0)

    def get_available_providers(self):
        if not self._provider:
            return []
        return [{'name': self._provider, 'configured': self._configured}]


def _rec(**kw):
    base = {
        'fingerprint': 'fp', 'subject_cn': 'example.com',
        'san_dns': ['example.com', 'www.example.com'],
        'key': {'type': 'RSA', 'size': 2048, 'curve': None},
        'managed': False,
    }
    base.update(kw)
    return base


# --- feasibility ----------------------------------------------------------- #

def test_available_when_dns_and_email_present():
    plan = build_adoption_plan(_rec(), _FakeDNS(), settings={'email': 'a@b.com'})
    assert plan['available'] is True
    assert plan['domain'] == 'example.com'
    assert plan['san_domains'] == ['www.example.com']
    assert plan['dns_provider'] == 'cloudflare'
    assert plan['dns_provider_configured'] is True


def test_unavailable_when_already_managed():
    plan = build_adoption_plan(_rec(managed=True), _FakeDNS(), settings={'email': 'a@b.com'})
    assert plan['available'] is False
    assert 'already managed' in plan['reason'].lower()


def test_unavailable_when_no_dns_configured():
    plan = build_adoption_plan(_rec(), _FakeDNS(configured=False), settings={'email': 'a@b.com'})
    assert plan['available'] is False
    assert 'dns' in plan['reason'].lower()


def test_unavailable_when_no_provider_suggested():
    plan = build_adoption_plan(_rec(), _FakeDNS(provider=None), settings={'email': 'a@b.com'})
    assert plan['available'] is False
    assert plan['dns_provider'] is None


def test_unavailable_when_no_email():
    plan = build_adoption_plan(_rec(), _FakeDNS(), settings={})
    assert plan['available'] is False
    assert 'email' in plan['reason'].lower()


def test_unavailable_when_no_domain():
    plan = build_adoption_plan(
        _rec(subject_cn=None, san_dns=[]), _FakeDNS(), settings={'email': 'a@b.com'})
    assert plan['available'] is False
    assert plan['domain'] is None


def test_none_record():
    plan = build_adoption_plan(None, _FakeDNS(), settings={'email': 'a@b.com'})
    assert plan['available'] is False
    assert 'not found' in plan['reason'].lower()


# --- derivation ------------------------------------------------------------ #

def test_derive_names_from_san_only():
    rec = _rec(subject_cn=None, san_dns=['a.example.com', 'b.example.com'])
    plan = build_adoption_plan(rec, _FakeDNS(), settings={'email': 'a@b.com'})
    assert plan['domain'] == 'a.example.com'
    assert plan['san_domains'] == ['b.example.com']


def test_key_options_rsa():
    plan = build_adoption_plan(
        _rec(key={'type': 'RSA', 'size': 4096}), _FakeDNS(), settings={'email': 'a@b.com'})
    assert plan['key_type'] == 'rsa'
    assert plan['key_size'] == 4096
    assert plan['elliptic_curve'] is None


def test_key_options_ecdsa():
    plan = build_adoption_plan(
        _rec(key={'type': 'ECDSA', 'curve': 'secp384r1'}), _FakeDNS(),
        settings={'email': 'a@b.com'})
    assert plan['key_type'] == 'ecdsa'
    assert plan['elliptic_curve'] == 'secp384r1'
    assert plan['key_size'] is None


def test_key_options_ecdsa_openssl_curve_alias():
    # An observed OpenSSL-style 'prime256v1' must map to the create form's
    # canonical 'secp256r1' rather than being dropped.
    plan = build_adoption_plan(
        _rec(key={'type': 'ECDSA', 'curve': 'prime256v1'}), _FakeDNS(),
        settings={'email': 'a@b.com'})
    assert plan['elliptic_curve'] == 'secp256r1'


def test_key_options_unusual_size_falls_back():
    # A 1024-bit RSA key isn't offered by the create form -> size dropped.
    plan = build_adoption_plan(
        _rec(key={'type': 'RSA', 'size': 1024}), _FakeDNS(), settings={'email': 'a@b.com'})
    assert plan['key_type'] == 'rsa'
    assert plan['key_size'] is None


def test_key_options_ed25519_uses_defaults():
    plan = build_adoption_plan(
        _rec(key={'type': 'Ed25519', 'size': 256}), _FakeDNS(),
        settings={'email': 'a@b.com'})
    assert plan['key_type'] is None
    assert plan['key_size'] is None
    assert plan['elliptic_curve'] is None
