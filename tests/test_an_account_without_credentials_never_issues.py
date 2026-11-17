"""A DNS account with no credential is never handed to issuance (#1469).

A fresh instance's first-run settings carry sixteen providers in the
single-account format with every credential empty, and the migration to
multi-account wraps each one in an account named "default" and makes it the
provider's default. Such an account was resolved like any other:

* asked for by name, it came back, and issuance wrote its blank token into
  certbot's credentials file, so the failure came from the DNS provider;
* as the provider's default, it came back even when another account of the
  same provider had credentials.

`_account_has_credentials` already answers whether an account can issue (the
provider's own required fields, as the settings page and the provider test
use). The lookup issuance goes through now asks it too.
"""
import copy

import pytest

from modules.core.dns_providers import DNSManager

pytestmark = [pytest.mark.unit]


class _Settings:
    def __init__(self, data):
        self.data = data

    def load_settings(self):
        return copy.deepcopy(self.data)

    def migrate_dns_providers_to_multi_account(self, settings):
        return settings


# What the migration makes of the first-run template's Cloudflare entry.
SCAFFOLD = {'name': 'Default Cloudflare Account',
            'description': 'Migrated from single-account configuration', 'api_token': ''}
REAL = {'name': 'Production', 'api_token': 'a' * 40}


def _manager(accounts, default='default'):
    data = {'dns_providers': {'cloudflare': {'accounts': accounts}}}
    if default:
        data['default_accounts'] = {'cloudflare': default}
    return DNSManager(_Settings(data))


def test_a_fresh_instance_has_no_cloudflare_account_to_issue_with():
    config, account_id = _manager({'default': SCAFFOLD}).get_dns_provider_account_config('cloudflare')
    assert (config, account_id) == (None, None)


def test_the_empty_account_asked_for_by_name_is_not_handed_out():
    manager = _manager({'default': SCAFFOLD, 'prod': REAL})
    assert manager.get_dns_provider_account_config('cloudflare', 'default') == (None, None)


def test_an_empty_default_gives_way_to_an_account_with_credentials():
    config, account_id = _manager({'default': SCAFFOLD, 'prod': REAL}).get_dns_provider_account_config('cloudflare')
    assert account_id == 'prod'
    assert config['api_token'] == 'a' * 40


def test_an_account_with_credentials_is_resolved_as_before():
    manager = _manager({'default': SCAFFOLD, 'prod': REAL}, default='prod')
    assert manager.get_dns_provider_account_config('cloudflare')[1] == 'prod'
    assert manager.get_dns_provider_account_config('cloudflare', 'prod')[1] == 'prod'


def test_the_listing_and_the_lookup_agree():
    """What the settings page and the create form are told matches what
    issuance would do with the account."""
    manager = _manager({'default': SCAFFOLD, 'prod': REAL})
    listed = {a['account_id']: a['configured'] for a in manager.list_dns_provider_accounts('cloudflare')}
    assert listed == {'default': False, 'prod': True}
    for account_id, configured in listed.items():
        resolved = manager.get_dns_provider_account_config('cloudflare', account_id)[1]
        assert (resolved == account_id) is configured
