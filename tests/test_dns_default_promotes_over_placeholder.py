"""Adding a real DNS account claims the default slot over an empty placeholder.

The first-run migration pre-seeds default_accounts[provider] = 'default'
pointing at the empty scaffolded placeholder account. create_dns_account only
claimed the default when `provider not in default_accounts`, which was never
true after that, so a real account added later never became the default —
issuance then resolved the empty placeholder and handed certbot a blank
credential (#13). The new account now claims the slot when the current default
is unconfigured.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.dns_providers import DNSManager

pytestmark = [pytest.mark.unit]


def _dm(state):
    sm = MagicMock()
    sm.migrate_dns_providers_to_multi_account = lambda s: s
    sm.update = lambda mut, reason: (mut(state), True)[1]
    return DNSManager(sm)


def test_a_real_account_promotes_over_the_empty_placeholder():
    state = {
        'dns_providers': {'cloudflare': {'accounts': {
            'default': {'api_token': ''}}}},
        'default_accounts': {'cloudflare': 'default'},
    }
    _dm(state).create_dns_account(
        'cloudflare', 'production', {'api_token': 'REAL', 'name': 'Production'})
    assert state['default_accounts']['cloudflare'] == 'production'


def test_a_valid_default_is_not_overridden():
    """CONTROL: a second real account must not steal the default from a
    configured one."""
    state = {
        'dns_providers': {'cloudflare': {'accounts': {
            'production': {'api_token': 'REAL'}}}},
        'default_accounts': {'cloudflare': 'production'},
    }
    _dm(state).create_dns_account(
        'cloudflare', 'staging', {'api_token': 'REAL2', 'name': 'Staging'})
    assert state['default_accounts']['cloudflare'] == 'production'


def test_the_first_account_still_becomes_default():
    """CONTROL: with no default set yet, the first account claims the slot."""
    state = {'dns_providers': {'cloudflare': {'accounts': {}}}}
    _dm(state).create_dns_account(
        'cloudflare', 'production', {'api_token': 'REAL'})
    assert state['default_accounts']['cloudflare'] == 'production'
