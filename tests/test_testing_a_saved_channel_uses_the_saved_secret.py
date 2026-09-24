"""Pressing Test on a saved notification channel sent it the mask.

The save path strips the `'********'` sentinel and deep-merges against what
is on disk, so a GET → edit → POST round-trip keeps the real secret. The test
path did neither: `POST /api/notifications/test` handed `data['config']`
straight to `test_channel`, and the UI posts exactly what the masked GET
returned (`static/js/settings-notifications.js` sends
`self.config.channels.smtp`, and the webhook object as loaded).

So an operator who saved a channel, came back later and pressed Test sent
`password='********'` to their mail server, or `url='********'` to the webhook
sender — which answers "Webhook URL must use http or https scheme". The toast
reported a correctly configured channel as broken, and the only way to get a
green test was to re-type the secret: the one thing masking exists to avoid.

Found by the certmate-website session reading v2.35.0.
"""
import pytest

from modules.web.misc_routes import _unmasked_test_config

pytestmark = [pytest.mark.unit]

MASK = '********'


class _Settings:
    """Just enough settings manager: the helper only reads."""

    def __init__(self, notifications):
        self._data = {'notifications': notifications}

    def load_settings(self):
        return self._data


def _stored(**channels):
    return _Settings({'channels': channels})


# --- smtp: a dict channel -------------------------------------------------

def test_a_masked_password_is_filled_in_from_what_was_saved():
    """THE regression."""
    settings = _stored(smtp={'host': 'smtp.example.com', 'port': 587,
                             'username': 'mailer',
                             'password': 'REAL-SMTP-PASSWORD'})

    config = _unmasked_test_config(settings, 'smtp', {
        'host': 'smtp.example.com', 'port': 587,
        'username': 'mailer', 'password': MASK})

    assert config['password'] == 'REAL-SMTP-PASSWORD'


def test_a_password_the_operator_did_retype_wins():
    """CONTROL. Filling from storage must not override a real edit — that
    would make it impossible to test a new credential before saving it."""
    settings = _stored(smtp={'host': 'smtp.example.com', 'port': 587,
                             'password': 'OLD'})

    config = _unmasked_test_config(settings, 'smtp', {
        'host': 'smtp.example.com', 'port': 587, 'password': 'NEW'})

    assert config['password'] == 'NEW'


def test_the_rest_of_the_payload_is_the_one_being_tested():
    """The point of Test is to try a change before saving it, so every
    non-masked field must come from the request, not from disk."""
    settings = _stored(smtp={'host': 'old.example.com', 'port': 25,
                             'password': 'REAL'})

    config = _unmasked_test_config(settings, 'smtp', {
        'host': 'new.example.com', 'port': 587, 'password': MASK})

    assert (config['host'], config['port']) == ('new.example.com', 587)
    assert config['password'] == 'REAL'


def test_a_channel_that_was_never_saved_is_tested_as_sent():
    """Nothing to fill in from. The sentinel must not survive into the
    sender, so it is stripped rather than passed through."""
    settings = _stored()

    config = _unmasked_test_config(settings, 'smtp', {
        'host': 'new.example.com', 'password': MASK})

    assert config.get('password') in (None, '')
    assert config['host'] == 'new.example.com'


# --- webhooks: a list, matched by identity --------------------------------

def test_a_saved_webhook_is_tested_against_its_real_url():
    settings = _stored(webhooks=[
        {'name': 'ops', 'type': 'slack',
         'url': 'https://hooks.slack.com/services/REAL'}])

    config = _unmasked_test_config(settings, 'webhook', {
        'name': 'ops', 'type': 'slack', 'url': MASK})

    assert config['url'] == 'https://hooks.slack.com/services/REAL'


def test_the_wrong_webhook_is_never_borrowed_from():
    """CONTROL, and the reason the save path matches by identity and not by
    position: copying a neighbour's URL would transmit a credential to the
    wrong endpoint. A name that matches nothing stored gets nothing."""
    settings = _stored(webhooks=[
        {'name': 'ops', 'type': 'slack', 'url': 'https://hooks.slack.com/A'},
        {'name': 'alerts', 'type': 'slack', 'url': 'https://hooks.slack.com/B'}])

    config = _unmasked_test_config(settings, 'webhook', {
        'name': 'brand-new', 'type': 'slack', 'url': MASK})

    assert config.get('url') != 'https://hooks.slack.com/A'
    assert config.get('url') != 'https://hooks.slack.com/B'


def test_the_two_paths_use_the_same_helpers():
    """They diverged once. Asserting that both reach for the same three
    functions is what stops the test path drifting again."""
    import inspect

    from modules.web import misc_routes

    helper = inspect.getsource(misc_routes._unmasked_test_config)

    for name in ('_strip_masked_values', '_deep_merge_dict',
                 '_restore_masked_list_secrets'):
        assert name in helper, f'the test path no longer uses {name}'


def test_the_route_actually_calls_it():
    """A helper nothing calls is the same defect with more code."""
    import ast
    import inspect

    from modules.web import misc_routes

    source = inspect.getsource(misc_routes)
    calls = [ast.unparse(n) for n in ast.walk(ast.parse(source))
             if isinstance(n, ast.Call)]

    assert any('_unmasked_test_config(' in c for c in calls)
