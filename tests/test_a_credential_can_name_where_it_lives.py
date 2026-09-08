"""A DNS token or the OIDC secret can live outside settings.json.

Every DNS provider API token and the OIDC client secret rested in
`settings.json` as cleartext JSON. 0600 is the right permission and is not the
point: that file is what gets backed up, copied between hosts, mounted into a
container and attached to a bug report. A deployment already keeping its
secrets in a Docker or Kubernetes secret had no way to keep them out of it.

`API_BEARER_TOKEN_FILE` already solved this for one secret. `secret_refs`
generalises it: any field may be supplied as `<field>_file` or `<field>_env`
instead of as a value.

Two properties carry the whole feature, and both have controls here:

**The resolved value must never be written back.** Resolving where the config
is *loaded* rather than where it is *used* would mean the next settings save
persists the secret into the file the mechanism exists to keep it out of —
silently, and permanently. `test_editing_the_oidc_config_does_not_persist_the
_resolved_secret` and its DNS counterpart fail on exactly that.

**A reference must never resolve to nothing.** An empty credential produces a
certbot or IdP failure that reads like a provider outage. A missing file or an
unset variable is refused, and the log names the reference — never the value.
"""
import logging

import pytest

from modules.core.dns_providers import DNSManager
from modules.core.secret_refs import (
    SecretReferenceError, has_value, referenced_fields, resolve, resolve_field,
)
from modules.core.utils import (
    _DNS_PROVIDER_CREDENTIALS, validate_dns_provider_account,
)

pytestmark = [pytest.mark.unit]


# --- resolution ----------------------------------------------------------

def test_a_field_can_name_a_file(tmp_path):
    secret = tmp_path / 'cf_token'
    secret.write_text('the-real-token')

    config = {'api_token_file': str(secret)}

    assert resolve(config)['api_token'] == 'the-real-token'


def test_a_field_can_name_an_environment_variable(monkeypatch):
    monkeypatch.setenv('CF_API_TOKEN', 'from-the-environment')

    assert resolve({'api_token_env': 'CF_API_TOKEN'})['api_token'] == (
        'from-the-environment')


def test_the_trailing_newline_a_secret_manager_adds_is_stripped(tmp_path):
    """`docker secret` and `kubectl create secret --from-file` both leave a
    trailing newline. A token with one reaches the DNS API as a wrong token,
    and the authentication error that comes back names nothing useful."""
    secret = tmp_path / 'cf_token'
    secret.write_text('the-real-token\n')

    assert resolve({'api_token_file': str(secret)})['api_token'] == (
        'the-real-token')


def test_a_reference_beats_a_stale_literal(tmp_path):
    """The migration case. Someone adds `api_token_file` and leaves the old
    `api_token` in place; if the literal won, issuance would keep using the
    credential they believe they replaced and nothing would say so."""
    secret = tmp_path / 'cf_token'
    secret.write_text('the-new-token')

    resolved = resolve({'api_token': 'the-old-token',
                        'api_token_file': str(secret)})

    assert resolved['api_token'] == 'the-new-token'


def test_a_file_beats_an_environment_variable(tmp_path, monkeypatch):
    """Both set is a configuration a person can arrive at; the order is stated
    rather than whichever the dict happened to yield."""
    secret = tmp_path / 'cf_token'
    secret.write_text('from-the-file')
    monkeypatch.setenv('CF_API_TOKEN', 'from-the-environment')

    resolved = resolve({'api_token_file': str(secret),
                        'api_token_env': 'CF_API_TOKEN'})

    assert resolved['api_token'] == 'from-the-file'


def test_a_config_with_no_references_is_returned_unchanged():
    config = {'api_token': 'literal', 'name': 'prod'}
    assert resolve(config) == config


def test_the_original_is_not_mutated(tmp_path):
    """resolve() returns a copy. If it edited in place, the caller's dict —
    which for the DNS path is a slice of the loaded settings — would carry the
    secret into whatever writes settings next."""
    secret = tmp_path / 'cf_token'
    secret.write_text('the-real-token')
    config = {'api_token_file': str(secret)}

    resolve(config)

    assert 'api_token' not in config


# --- what must NOT resolve to nothing ------------------------------------

def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(SecretReferenceError) as caught:
        resolve({'api_token_file': str(tmp_path / 'not-mounted')})
    assert 'could not be read' in str(caught.value)


def test_an_empty_file_is_refused(tmp_path):
    """A mounted-but-empty secret is the shape a half-finished deployment has.
    Resolving it to '' would issue with a blank token."""
    secret = tmp_path / 'cf_token'
    secret.write_text('   \n')

    with pytest.raises(SecretReferenceError) as caught:
        resolve({'api_token_file': str(secret)})
    assert 'is empty' in str(caught.value)


def test_an_unset_environment_variable_is_refused(monkeypatch):
    monkeypatch.delenv('CF_API_TOKEN', raising=False)

    with pytest.raises(SecretReferenceError) as caught:
        resolve({'api_token_env': 'CF_API_TOKEN'})
    assert 'unset' in str(caught.value)


def test_the_error_never_carries_the_value(tmp_path):
    """CONTROL: this exception is logged. A message that interpolated the
    secret would put it in the log for every failed resolution."""
    secret = tmp_path / 'cf_token'
    secret.write_text('SUPER-SECRET-TOKEN')

    error = SecretReferenceError('api_token', str(secret), 'is empty')

    assert 'SUPER-SECRET-TOKEN' not in str(error)
    assert error.field == 'api_token'


@pytest.mark.parametrize('config', [
    {'api_token_file': ''}, {'api_token_file': '   '},
    {'api_token_env': ''}, {'api_token_file': None},
    {'api_token_file': 12}, {'_file': '/x'},
])
def test_a_blank_or_malformed_reference_is_not_a_reference(config):
    """It falls through to the literal — which is absent — rather than raising.
    An empty string in a settings field is what an untouched UI input leaves
    behind, and it must not stop the account from loading."""
    assert referenced_fields(config) == set()
    assert resolve(config) == config


def test_an_absent_field_is_none_not_an_error():
    assert resolve_field({'other': 'x'}, 'api_token') is None


@pytest.mark.parametrize('config', ['a string', None, 42, ['a', 'list']])
def test_a_config_that_is_not_a_dict_does_not_raise(config):
    """settings.json is hand-editable, and a provider entry written as a string
    reaches all three of these. Raising would turn a typo in a config file into
    a 500 on the settings page rather than an account that reads as
    unconfigured."""
    assert referenced_fields(config) == set()
    assert has_value(config, 'api_token') is False
    assert resolve(config) == config


def test_a_non_string_literal_still_counts_as_configured():
    """`rfc2136` stores a port; `custom-script` a boolean flag. The whitespace
    rule applies to strings only — a truthy non-string is a value."""
    assert has_value({'port': 53}, 'port')
    assert not has_value({'port': 0}, 'port')


# --- "is this configured" must not read secrets --------------------------

def test_a_referenced_field_counts_as_configured(tmp_path):
    """Without this, a file-backed account renders as unconfigured in the UI
    and `get_available_providers` reports the provider as unset."""
    assert has_value({'api_token_file': '/run/secrets/cf'}, 'api_token')
    assert has_value({'api_token_env': 'CF_API_TOKEN'}, 'api_token')


def test_asking_whether_it_is_configured_does_not_read_the_file(tmp_path):
    """The reference names a path that does not exist. If has_value followed
    it, rendering the settings page would raise on any host where the secret
    is not mounted — and would read every credential to draw a green tick."""
    assert has_value({'api_token_file': str(tmp_path / 'absent')}, 'api_token')


def test_a_whitespace_only_literal_is_still_not_configured():
    """REGRESSION CONTROL. The check this replaced did `str(...).strip()`; a
    plain truthiness test would count '   ' as a token and move the failure to
    certbot."""
    assert not has_value({'api_token': '   '}, 'api_token')
    assert not has_value({'api_token': ''}, 'api_token')
    assert not has_value({}, 'api_token')


def test_no_credential_field_could_be_mistaken_for_a_reference():
    """The suffix rule is only safe while no real field ends in `_file` or
    `_env`. If one is ever added, this fails instead of that field being
    silently read as a pointer to another one."""
    offenders = sorted(
        field
        for fields in _DNS_PROVIDER_CREDENTIALS.values()
        for field in fields
        if field.endswith('_file') or field.endswith('_env')
    )
    assert not offenders, (
        f'{offenders} would be read as a reference to another field rather '
        f'than as itself')


# --- the DNS path end to end ---------------------------------------------

class _Settings:
    def __init__(self, data):
        self.data = data
        self.saved = []

    def load_settings(self):
        import copy
        return copy.deepcopy(self.data)

    def migrate_dns_providers_to_multi_account(self, settings):
        return settings

    def save_settings(self, settings):
        self.saved.append(settings)
        return True


@pytest.fixture
def file_backed(tmp_path):
    secret = tmp_path / 'cf_token'
    secret.write_text('the-real-token\n')
    settings = _Settings({'dns_providers': {'cloudflare': {'accounts': {
        'prod': {'api_token_file': str(secret), 'name': 'Production'}}}}})
    return DNSManager(settings), settings, secret


def test_issuance_gets_the_resolved_token(file_backed):
    manager, _, _ = file_backed

    config, account_id = manager.get_dns_provider_account_config('cloudflare')

    assert account_id == 'prod'
    assert config['api_token'] == 'the-real-token'


def test_the_account_shows_as_configured(file_backed):
    manager, _, _ = file_backed

    accounts = manager.list_dns_provider_accounts('cloudflare')

    assert [a['configured'] for a in accounts] == [True]


def test_listing_accounts_does_not_return_the_secret(file_backed):
    """CONTROL: the listing feeds API responses. Resolving there would put the
    token in a response that previously only carried names."""
    manager, _, _ = file_backed

    listed = manager.list_accounts()

    assert 'the-real-token' not in repr(listed)


def test_an_unreadable_reference_does_not_look_like_a_missing_account(
        file_backed, caplog):
    """The account resolves to (None, None) — the existing contract — but the
    log has to name the mount, or the operator debugs a credential that is
    correct."""
    manager, settings, secret = file_backed
    secret.unlink()

    logger = logging.getLogger('modules.core.dns_providers')
    with caplog.at_level(logging.ERROR, logger=logger.name):
        config, account_id = manager.get_dns_provider_account_config(
            'cloudflare')

    assert (config, account_id) == (None, None)
    message = '\n'.join(r.getMessage() for r in caplog.records)
    assert 'api_token' in message
    assert str(secret) in message
    assert 'prod' in message


def test_a_saved_config_still_holds_the_reference_not_the_value(file_backed):
    """THE control for this feature. If anything resolved on the load path,
    the settings dict the manager hands around would carry the token, and the
    next save would write it into settings.json permanently."""
    manager, settings, _ = file_backed

    manager.get_dns_provider_account_config('cloudflare')

    stored = settings.data['dns_providers']['cloudflare']['accounts']['prod']
    assert 'api_token' not in stored
    assert 'the-real-token' not in repr(settings.data)


def test_a_literal_account_still_works(tmp_path):
    """CONTROL: the overwhelmingly common configuration must be untouched."""
    settings = _Settings({'dns_providers': {'cloudflare': {'accounts': {
        'prod': {'api_token': 'plain-old-token'}}}}})

    config, account_id = DNSManager(
        settings).get_dns_provider_account_config('cloudflare')

    assert config['api_token'] == 'plain-old-token'
    assert account_id == 'prod'


# --- the save path accepts it --------------------------------------------

def test_a_file_backed_account_can_be_saved():
    """Without this the feature exists only for settings.json edited by hand:
    the validator rejected the account as missing the field it supplies."""
    ok, message = validate_dns_provider_account(
        'cloudflare', 'prod', {'api_token_file': '/run/secrets/cf'})
    assert ok, message


def test_an_account_with_neither_is_still_rejected():
    """CONTROL: the validator must not have become a rubber stamp."""
    ok, message = validate_dns_provider_account('cloudflare', 'prod', {})
    assert not ok
    assert 'api_token' in message


def test_a_partially_referenced_account_is_still_rejected():
    """route53 needs two fields. Supplying one by reference does not excuse
    the other."""
    ok, message = validate_dns_provider_account(
        'route53', 'prod', {'access_key_id_file': '/run/secrets/id'})
    assert not ok
    assert 'secret_access_key' in message


def test_the_test_provider_button_accepts_a_reference():
    manager = DNSManager(_Settings({}))
    ok, _ = manager.test_provider(
        'cloudflare', {'api_token_env': 'CF_API_TOKEN'})
    assert ok


# --- OIDC ----------------------------------------------------------------

def test_the_oidc_secret_can_name_a_file(tmp_path):
    from modules.core.oidc import OIDCManager

    secret = tmp_path / 'oidc'
    secret.write_text('the-client-secret\n')

    assert OIDCManager._client_secret(
        {'client_secret_file': str(secret)}) == 'the-client-secret'


def test_an_unresolvable_oidc_secret_is_blank_rather_than_a_500(
        tmp_path, caplog):
    """Raising here would take down the login page for everyone, including the
    local admin who is the only person able to fix the mount."""
    from modules.core.oidc import OIDCManager

    with caplog.at_level(logging.ERROR, logger='modules.core.oidc'):
        value = OIDCManager._client_secret(
            {'client_secret_file': str(tmp_path / 'absent')})

    assert value == ''
    assert 'client_secret' in '\n'.join(
        r.getMessage() for r in caplog.records)


def test_editing_the_oidc_config_does_not_persist_the_resolved_secret(
        tmp_path):
    """THE control on the OIDC side. `update_config` loads the config, merges
    the payload onto it and writes the result back — so resolving on the load
    path would write the secret into settings.json the first time anyone
    toggled a checkbox in the SSO settings page."""
    from modules.core.oidc import _normalize_oidc_config

    secret = tmp_path / 'oidc'
    secret.write_text('the-client-secret')

    loaded = _normalize_oidc_config({'client_secret_file': str(secret),
                                     'issuer_url': 'https://idp.invalid',
                                     'client_id': 'certmate'})

    assert loaded['client_secret'] == ''
    assert 'the-client-secret' not in repr(loaded)
