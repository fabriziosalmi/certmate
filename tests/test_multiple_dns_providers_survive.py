"""Configuring a second DNS provider must not delete the first (#641).

Reported by a user: "Only one DNS provider can be set and used. After adding a
new DNS provider configuration, the previous one is forgotten." The certificate
form still offered the forgotten provider, so issuance failed later for missing
credentials rather than at the point the configuration was lost.

`atomic_update` merges the top level and deep-merges a named set of subtrees.
`dns_providers` was not in that set, so a settings POST carrying one provider
replaced the whole subtree. Reproduced before fixing: save Cloudflare, save
Route53, Cloudflare's token is gone.

The risk in the fix is the opposite one — a deep merge means keys are never
dropped, so something that removed a provider by omitting it from a POST would
stop working. Nothing does: the UI deletes an account with
`DELETE /api/dns/<provider>/accounts/<id>`. That path is exercised here too,
because a fix that quietly disabled deletion would trade one report for another.
"""
import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import _DEEP_MERGE_SETTINGS_KEYS, SettingsManager

pytestmark = [pytest.mark.unit]

CF_TOKEN = 'cloudflare-token-value'
AWS_KEY = 'AKIAEXAMPLEEXAMPLE'


@pytest.fixture
def settings(tmp_path):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    manager = SettingsManager(FileOperations(*dirs), dirs[1] / 'settings.json')
    manager.load_settings()
    return manager


def _providers(settings):
    return settings.load_settings(use_cache=False).get('dns_providers', {})


def test_configuring_a_second_provider_keeps_the_first(settings):
    """The reported bug, as the user described it."""
    settings.atomic_update({'dns_providers': {'cloudflare': {'api_token': CF_TOKEN}}})
    settings.atomic_update({'dns_providers': {'route53': {'access_key_id': AWS_KEY}}})

    providers = _providers(settings)

    assert providers.get('cloudflare', {}).get('api_token') == CF_TOKEN, (
        'configuring Route53 deleted the Cloudflare credential; the provider '
        'stays selectable on the certificate form and issuance fails later'
    )
    assert providers.get('route53', {}).get('access_key_id') == AWS_KEY


def test_a_third_provider_keeps_both(settings):
    """Two is the reported case; the property is that none of them is lost."""
    settings.atomic_update({'dns_providers': {'cloudflare': {'api_token': CF_TOKEN}}})
    settings.atomic_update({'dns_providers': {'route53': {'access_key_id': AWS_KEY}}})
    settings.atomic_update({'dns_providers': {'azure': {'client_id': 'azure-id'}}})

    providers = _providers(settings)
    assert providers['cloudflare']['api_token'] == CF_TOKEN
    assert providers['route53']['access_key_id'] == AWS_KEY
    assert providers['azure']['client_id'] == 'azure-id'


def test_updating_a_provider_still_overwrites_its_own_fields(settings):
    """CONTROL: merging must not make a credential impossible to CHANGE.

    A deep merge that only ever added would leave an operator unable to rotate
    a token, which is worse than the bug being fixed.
    """
    settings.atomic_update({'dns_providers': {'cloudflare': {'api_token': 'old'}}})
    settings.atomic_update({'dns_providers': {'cloudflare': {'api_token': 'new'}}})

    assert _providers(settings)['cloudflare']['api_token'] == 'new'


def test_dns_providers_is_in_the_deep_merge_set():
    """Names the mechanism, so a failure says what to fix rather than only that
    a credential vanished."""
    assert 'dns_providers' in _DEEP_MERGE_SETTINGS_KEYS


# ---------------------------------------------------------------------------
# The risk the fix introduces: removal must still work
# ---------------------------------------------------------------------------

def test_an_account_can_still_be_deleted(tmp_path):
    """A deep merge never drops keys, so deletion has to come from elsewhere.

    It does — the UI calls DELETE /api/dns/<provider>/accounts/<id>, which goes
    through DNSManager rather than through a settings POST. If that ever
    changed, this fix would turn a data-loss bug into a cannot-remove-anything
    bug, so it is exercised rather than assumed.
    """
    from modules.core.dns_providers import DNSManager

    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    settings = SettingsManager(FileOperations(*dirs), dirs[1] / 'settings.json')
    settings.load_settings()

    dns = DNSManager(settings)
    assert dns.add_account('primary', 'cloudflare', {'api_token': CF_TOKEN})
    assert dns.add_account('secondary', 'cloudflare', {'api_token': 'other'})

    accounts = _providers(settings)['cloudflare']['accounts']
    assert set(accounts) >= {'primary', 'secondary'}

    assert dns.delete_account('cloudflare', 'secondary')

    remaining = _providers(settings)['cloudflare']['accounts']
    assert 'secondary' not in remaining, 'the account was not removed'
    assert 'primary' in remaining, 'removing one account took the other with it'


def test_two_accounts_on_the_same_provider_both_persist(tmp_path):
    """The multi-account shape the report's second half is about: choosing a
    non-default provider on the certificate form has to find its credentials.
    """
    from modules.core.dns_providers import DNSManager

    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    settings = SettingsManager(FileOperations(*dirs), dirs[1] / 'settings.json')
    settings.load_settings()

    dns = DNSManager(settings)
    dns.add_account('public', 'cloudflare', {'api_token': CF_TOKEN})
    dns.add_account('internal', 'cloudflare', {'api_token': 'internal-token'})

    config, _err = dns.get_dns_provider_account_config(
        'cloudflare', 'internal', settings.load_settings(use_cache=False))

    assert config, 'the non-default account could not be resolved'
    assert config.get('api_token') == 'internal-token'
