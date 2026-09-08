"""A credential must not escape masking because of how it happens to be named.

What counts as a secret is decided by a regular expression over the field's
NAME — seven words — plus a declared list for the fields whose names the regex
misses. A credential named something else is neither masked on `GET
/api/web/settings` nor kept out of the share-safe backup, which is the archive
explicitly meant to be shareable.

**Measured before writing anything: today, nothing is missed.** All 29 DNS
providers' credential fields are covered. The eleven that the regex does not
match are identifiers and endpoints, and each is named below with the reason —
including `custom-script.auth_hook`, which reads like a place to hide a token
and is in fact a *script path* (`_validated_hook_path`), and
`acme-dns.username`, which IS treated as a secret because there it is half of a
generated credential rather than an account name a person chose.

So the risk is entirely about the **next** provider. This file makes that
condition impossible to introduce silently: a credential field that is neither
matched nor declared fails, naming the provider and the field.

The classification of "not a secret" lives here rather than in production code
on purpose. It changes no behaviour — it is a review artefact, the record of a
decision someone made, in the place where the next person is asked to make the
same one.
"""
import pytest

from modules.core.settings import (
    _PROVIDER_SPECIFIC_SECRET_FIELDS, _SECRET_KEY_RE, _is_secret_key,
    mask_secrets_in_settings,
)
from modules.core.utils import _DNS_PROVIDER_CREDENTIALS

pytestmark = [pytest.mark.unit]


# Credential-registry fields the regex does not match, and why each is not a
# secret. A field here is a decision; a field in neither this nor
# _PROVIDER_SPECIFIC_SECRET_FIELDS is an oversight.
NOT_A_SECRET = {
    ('acme-dns', 'api_url'): 'the acme-dns server endpoint',
    ('azure', 'subscription_id'): 'an Azure subscription identifier',
    ('azure', 'resource_group'): 'a resource group name',
    ('azure', 'tenant_id'): 'an Azure tenant identifier',
    ('azure', 'client_id'): 'the application id; client_secret is the secret',
    ('custom-script', 'auth_hook'):
        'a PATH to a script on disk, screened by _validated_hook_path — not '
        'an inline command, so it cannot carry an embedded token',
    ('edgedns', 'host'): 'the Akamai EdgeDNS API host',
    ('google', 'project_id'): 'a GCP project identifier',
    ('he-ddns', 'username'):
        'the Hurricane Electric account name, which the operator knows and '
        'which is not on its own a credential',
    ('namecheap', 'username'): 'the Namecheap account name',
    ('ovh', 'endpoint'): 'the OVH API region endpoint',
    ('powerdns', 'api_url'): 'the PowerDNS API endpoint',
    ('rfc2136', 'nameserver'): 'the address of the nameserver to update',
    ('solidserver', 'host'): 'the SOLIDserver appliance address',
    ('solidserver', 'username'): 'the SOLIDserver account name',
    ('solidserver', 'dns_name'): 'the name of the DNS service on the appliance',
}


def _declared(provider, field):
    return field in _PROVIDER_SPECIFIC_SECRET_FIELDS.get(provider,
                                                         frozenset())


# --- the census ----------------------------------------------------------

def test_every_provider_credential_is_classified():
    unclassified = []
    for provider, fields in sorted(_DNS_PROVIDER_CREDENTIALS.items()):
        for field in fields:
            if _SECRET_KEY_RE.search(field) or _declared(provider, field):
                continue
            if (provider, field) in NOT_A_SECRET:
                continue
            unclassified.append(f'{provider}.{field}')

    assert not unclassified, (
        "these DNS provider credential fields are matched by neither the "
        "secret-name regex nor _PROVIDER_SPECIFIC_SECRET_FIELDS, so they are "
        "returned in cleartext by GET /api/web/settings and written into the "
        "share-safe backup:\n  " + '\n  '.join(unclassified)
        + "\n\nIf one IS a secret, add it to _PROVIDER_SPECIFIC_SECRET_FIELDS "
          "in modules/core/settings.py. If it is not, add it to NOT_A_SECRET "
          "here with the reason."
    )


def test_the_not_a_secret_list_does_not_outlive_its_fields():
    """A stale entry is a standing exemption for a name that may come back
    meaning something else."""
    stale = sorted(
        f'{provider}.{field}' for provider, field in NOT_A_SECRET
        if field not in _DNS_PROVIDER_CREDENTIALS.get(provider, ()))
    assert not stale, (
        'NOT_A_SECRET names fields no provider declares any more: '
        + ', '.join(stale))


def test_every_exemption_says_why():
    for (provider, field), reason in NOT_A_SECRET.items():
        assert len(reason.strip()) > 15, (
            f'{provider}.{field} is exempt with no usable reason: {reason!r}')


def test_a_field_is_not_exempted_and_declared_at_once():
    """CONTROL: the two lists must not disagree — a field in both would have
    one of them saying something false about it."""
    both = sorted(
        f'{provider}.{field}' for provider, field in NOT_A_SECRET
        if _declared(provider, field))
    assert not both, (
        'these are listed as not-a-secret AND declared as secret: '
        + ', '.join(both))


# --- controls on the census ---------------------------------------------

def test_the_registry_has_the_providers_it_should():
    """Without this, an empty registry makes every assertion above pass."""
    assert len(_DNS_PROVIDER_CREDENTIALS) > 25
    assert 'cloudflare' in _DNS_PROVIDER_CREDENTIALS


def test_the_regex_still_recognises_an_obvious_credential():
    """CONTROL: a regex that matched nothing would push every field into
    NOT_A_SECRET; one that matched everything would hide a real gap."""
    for name in ('api_token', 'client_secret', 'password', 'api_key',
                 'hmac_key', 'credentials_json'):
        assert _is_secret_key(name), f'{name} is no longer seen as a secret'
    for name in ('domain', 'email', 'port', 'enabled'):
        assert not _is_secret_key(name), f'{name} is now seen as a secret'


def test_the_key_option_defaults_are_still_not_secrets():
    """They match the regex on 'key' and are not credentials. Treating them
    as secrets would make an empty value mean "preserve", so an operator
    could never clear one."""
    for name in ('default_key_type', 'default_key_size',
                 'default_elliptic_curve'):
        assert _is_secret_key(name) is False


# --- and the masking actually happens -----------------------------------

def test_a_declared_field_is_masked_even_though_its_name_is_innocent():
    """The webhook URL: for Slack, Discord, ntfy and Gotify the incoming URL
    embeds the bearer secret in its path, and 'url' matches no pattern."""
    masked = mask_secrets_in_settings({
        'notifications': {'channels': {'webhooks': [
            {'name': 'ops', 'url': 'https://hooks.example.invalid/T/B/XXXX'}]}}
    })
    webhook = masked['notifications']['channels']['webhooks'][0]
    assert webhook['url'] != 'https://hooks.example.invalid/T/B/XXXX'
    assert webhook['name'] == 'ops', 'the label was masked too'


def test_an_ordinary_credential_is_masked():
    masked = mask_secrets_in_settings(
        {'dns_providers': {'cloudflare': {'default': {'api_token': 'abc'}}}})
    assert masked['dns_providers']['cloudflare']['default']['api_token'] \
        != 'abc'


def test_a_non_secret_is_left_readable():
    """CONTROL: masking everything would make the settings page unusable and
    would round-trip real values away on save."""
    masked = mask_secrets_in_settings({'email': 'ops@example.com',
                                       'auto_renew': True})
    assert masked['email'] == 'ops@example.com'
    assert masked['auto_renew'] is True
