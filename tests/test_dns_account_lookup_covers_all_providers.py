"""Account lookup must recognise every provider's real credential fields.

get_dns_provider_account_config fell back to a hardcoded 6-key allowlist
(api_token / access_key_id / api_key / api_url / username / token) when
default_accounts had no entry for the provider. That list did not cover
rfc2136 (nameserver/tsig_key/tsig_secret), scaleway (application_token), and
several others, so a fully configured account for one of those resolved to
(None, None) and issuance died with "account not configured" — naming
credentials that were already stored. Lookup and the `configured` flag now use
the provider's own required fields (_DNS_PROVIDER_CREDENTIALS).
"""
from unittest.mock import MagicMock

import pytest

from modules.core.dns_providers import DNSManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def dm():
    sm = MagicMock()
    sm.migrate_dns_providers_to_multi_account = lambda s: s
    return DNSManager(sm)


def _resolve(dm, settings, provider):
    dm.settings_manager.load_settings = lambda: settings
    return dm.get_dns_provider_account_config(provider, settings=settings)


@pytest.mark.parametrize('provider,creds', [
    ('rfc2136', {'nameserver': '1.2.3.4', 'tsig_key': 'k', 'tsig_secret': 's'}),
    ('scaleway', {'application_token': 'tok'}),
    ('azure', {'subscription_id': 'x', 'tenant_id': 't', 'client_id': 'c',
               'client_secret': 'sec', 'resource_group': 'g'}),
    ('edgedns', {'client_token': 'ct', 'client_secret': 'cs',
                 'access_token': 'at', 'host': 'h'}),
    ('cloudflare', {'api_token': 't'}),   # control: was already covered
])
def test_a_configured_account_resolves_with_no_default_set(dm, provider, creds):
    settings = {'dns_providers': {provider: {'accounts': {'default': creds}}}}
    cfg, used = _resolve(dm, settings, provider)
    assert cfg is not None, f"{provider} resolved to None despite being configured"
    assert used == 'default'


def test_an_empty_account_does_not_resolve(dm):
    """CONTROL: an account whose credential fields are blank must still be
    treated as unconfigured."""
    settings = {'dns_providers': {'cloudflare': {'accounts': {
        'default': {'api_token': ''}}}}}
    assert _resolve(dm, settings, 'cloudflare') == (None, None)


def test_the_configured_flag_covers_rfc2136(dm):
    settings = {'dns_providers': {'rfc2136': {'accounts': {'default': {
        'nameserver': '1.2.3.4', 'tsig_key': 'k', 'tsig_secret': 's'}}}}}
    dm.settings_manager.load_settings = lambda: settings
    accounts = dm.list_dns_provider_accounts('rfc2136', settings=settings)
    assert accounts and accounts[0]['configured'] is True


def test_an_unknown_provider_accepts_any_non_empty_value(dm):
    """A provider not in the credential registry must not be silently rejected
    — any non-empty field counts (the old allowlist would have dropped it)."""
    settings = {'dns_providers': {'weirdns': {'accounts': {'default': {
        'some_field': 'value'}}}}}
    cfg, _ = _resolve(dm, settings, 'weirdns')
    assert cfg is not None
