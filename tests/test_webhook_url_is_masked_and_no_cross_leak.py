"""A webhook URL is a credential: it is masked on read and never leaks another
webhook's secret across a save.

For Slack, Discord, ntfy and Gotify the incoming-webhook URL embeds the bearer
secret in its path, so anyone who reads it can post to the channel. mask_secrets_
in_settings masks by field NAME and 'url' matched nothing, so GET /api/web/settings
returned it in cleartext to the viewer role and the share-safe backup ZIP carried
it. It is now masked (#16), and restored on a round-trip like any other secret.

Masking the url also forced the identity used to restore masked secrets off 'url'
onto (type, name), and removed the positional fallback that used to copy a
different webhook's credential into the survivor and send it to the wrong
endpoint (#11).
"""
import pytest

from modules.core.settings import (
    mask_secrets_in_settings,
    _restore_masked_list_secrets,
    SECRET_MASK_SENTINEL as MASK,
)

pytestmark = [pytest.mark.unit]


def _webhooks(settings):
    return settings['notifications']['channels']['webhooks']


def test_a_webhook_url_is_masked_on_read():
    s = {'notifications': {'channels': {'webhooks': [
        {'name': 'Slack', 'type': 'slack', 'enabled': True,
         'url': 'https://hooks.slack.com/services/T/B/SECRET'}]}}}
    wh = _webhooks(mask_secrets_in_settings(s))[0]
    assert wh['url'] == MASK
    assert wh['name'] == 'Slack'      # non-secret fields survive
    assert wh['enabled'] is True


def test_a_masked_url_round_trips_back_to_the_real_value():
    old = [{'name': 'Slack', 'type': 'slack',
            'url': 'https://hooks.slack.com/services/REAL', 'auth_token': 'tok'}]
    # UI re-submits url and token masked, edits only `enabled`
    new = [{'name': 'Slack', 'type': 'slack', 'url': MASK,
            'auth_token': MASK, 'enabled': False}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['url'] == 'https://hooks.slack.com/services/REAL'
    assert new[0]['auth_token'] == 'tok'
    assert new[0]['enabled'] is False


def test_deleting_one_webhook_and_fixing_anothers_url_does_not_swap_tokens():
    """#11: the survivor keeps its OWN token, matched by (type, name)."""
    old = [
        {'name': 'PagerDuty', 'type': 'generic', 'url': 'https://pd',
         'auth_token': 'TOKEN-PAGERDUTY'},
        {'name': 'ITSM', 'type': 'generic', 'url': 'https://itsm-typo',
         'auth_token': 'TOKEN-ITSM'},
    ]
    # PagerDuty deleted, ITSM's URL corrected (sent in clear), token left masked
    new = [{'name': 'ITSM', 'type': 'generic', 'url': 'https://itsm',
            'auth_token': MASK}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['auth_token'] == 'TOKEN-ITSM'


def test_a_renamed_survivor_drops_the_secret_rather_than_guessing():
    """#11 worst case: identity changed AND position shifted. The secret is
    dropped (operator re-enters), never a positional guess that would hand over
    another webhook's credential."""
    old = [
        {'name': 'PagerDuty', 'type': 'generic', 'url': 'https://pd',
         'auth_token': 'TOKEN-PAGERDUTY'},
        {'name': 'ITSM', 'type': 'generic', 'url': 'https://itsm',
         'auth_token': 'TOKEN-ITSM'},
    ]
    new = [{'name': 'ITSM-prod', 'type': 'generic', 'url': 'https://itsm',
            'auth_token': MASK}]
    _restore_masked_list_secrets(old, new)
    assert new[0].get('auth_token') != 'TOKEN-PAGERDUTY'
    assert new[0].get('auth_token') in (None, MASK) or 'auth_token' not in new[0]


def test_acme_dns_masking_is_unchanged():
    """CONTROL: the list-context change must not disturb the provider-context
    masking of acme-dns username/subdomain."""
    s = {'dns_providers': {'acme-dns': {'username': 'u', 'subdomain': 'sub',
                                        'token': 't'}}}
    a = mask_secrets_in_settings(s)['dns_providers']['acme-dns']
    assert a['username'] == MASK and a['subdomain'] == MASK
