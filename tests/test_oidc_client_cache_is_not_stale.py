"""OIDC config changes must take effect, and an algorithm rejection must not
be permanent (#647).

Reported by a user connecting Authentik: every login failed on the id_token
signing algorithm, and every algorithm they tried failed in turn —

    unsupported_algorithm: Algorithm of 'RS256' is not allowed
    invalid_key_type: Algorithm 'HS256' requires 'oct' key

The 'not allowed' wording is the clue. Authlib restricts accepted signing
algorithms to whatever the discovery document advertised
(`id_token_signing_alg_values_supported`), and that document is fetched once,
when the Authlib client is first built, then cached.

The client was cached on `issuer_url` alone. So nothing the operator changed —
not the client secret, not the scopes, and nothing at all on the IdP side —
ever reached CertMate again until the process restarted. The instance went on
enforcing an algorithm list from the first login attempt of that container's
life.

Two properties here. The cache must follow the configuration, and a failure on
the algorithm must drop the cached document so the next attempt refetches:
otherwise a reconfigured IdP means an SSO that can never work again without a
restart, which is what the report describes.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.core.oidc import OIDCManager

pytestmark = [pytest.mark.unit]

BASE_CONFIG = {
    'enabled': True,
    'issuer_url': 'https://idp.example.com',
    'client_id': 'certmate',
    'client_secret': 'original-secret',
    'scopes': ['openid', 'profile'],
    'username_claim': 'preferred_username',
}


@pytest.fixture
def manager():
    settings = MagicMock()
    settings.load_settings.return_value = {'oidc': dict(BASE_CONFIG)}
    instance = OIDCManager.__new__(OIDCManager)
    instance.settings_manager = settings
    instance._oauth = None
    instance._cached_issuer = None
    instance._cached_client_key = None
    return instance


def _reconfigure(manager, **changes):
    manager.settings_manager.load_settings.return_value = {
        'oidc': {**BASE_CONFIG, **changes}}


# ---------------------------------------------------------------------------
# The cache has to follow the configuration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('change', [
    {'client_secret': 'rotated-secret'},
    {'client_id': 'a-different-client'},
    {'scopes': ['openid', 'profile', 'email']},
    {'issuer_url': 'https://other-idp.example.com'},
])
def test_a_config_change_rebuilds_the_client(manager, change):
    """Each of these changes what Authlib is registered with. Keyed on the
    issuer alone, three of the four were silently ignored until a restart —
    including a rotated client secret, which is a credential an operator
    reasonably expects to take effect when they save it.
    """
    pytest.importorskip('authlib', reason='OIDC is an optional dependency')
    import authlib.integrations.flask_client  # noqa: F401
    from flask import Flask

    app = Flask(__name__)
    app.secret_key = 'test'

    with patch('authlib.integrations.flask_client.OAuth') as OAuthClass:
        manager._build_oauth_client(app)
        before = OAuthClass.return_value.register.call_count

        _reconfigure(manager, **change)
        manager._build_oauth_client(app)
        after = OAuthClass.return_value.register.call_count

    assert after > before, (
        f'changing {list(change)} did not rebuild the client, so it never '
        f'reached Authlib — and neither did the discovery document, which is '
        f'what decides the accepted signing algorithms'
    )


def test_an_unchanged_config_reuses_the_client(manager):
    """CONTROL: rebuilding on every call would refetch the discovery document
    on every login, which is why it is cached in the first place."""
    pytest.importorskip('authlib', reason='OIDC is an optional dependency')
    import authlib.integrations.flask_client  # noqa: F401
    from flask import Flask

    app = Flask(__name__)
    app.secret_key = 'test'

    with patch('authlib.integrations.flask_client.OAuth') as OAuthClass:
        first = manager._build_oauth_client(app)
        second = manager._build_oauth_client(app)
        assert OAuthClass.return_value.register.call_count == 1
    assert first is second


def test_the_fingerprint_does_not_keep_the_secret_in_the_clear():
    """It lives on the manager and ends up in comparisons — and one day in
    somebody's debug print."""
    fingerprint = OIDCManager._client_fingerprint(BASE_CONFIG)
    assert BASE_CONFIG['client_secret'] not in fingerprint


def test_the_fingerprint_still_distinguishes_two_secrets():
    """CONTROL: hashing must not collapse different secrets into one key, or
    a rotation would go unnoticed again."""
    other = dict(BASE_CONFIG, client_secret='a-different-secret')
    assert (OIDCManager._client_fingerprint(BASE_CONFIG)
            != OIDCManager._client_fingerprint(other))


# ---------------------------------------------------------------------------
# An algorithm rejection must not be permanent
# ---------------------------------------------------------------------------

class _AlgorithmRejected(Exception):
    def __str__(self):
        return "unsupported_algorithm: Algorithm of 'RS256' is not allowed"


def test_an_algorithm_failure_drops_the_cached_discovery_document(manager):
    """The reported loop: without this, every subsequent login re-applies the
    same stale algorithm list and fails identically, forever."""
    manager._oauth = MagicMock()
    manager._cached_issuer = BASE_CONFIG['issuer_url']
    manager._cached_client_key = OIDCManager._client_fingerprint(BASE_CONFIG)

    with patch.object(OIDCManager, '_client',
                      side_effect=_AlgorithmRejected()):
        claims, error = manager.handle_callback(MagicMock())

    assert claims is None
    assert error == 'token_exchange_algorithm', (
        'the algorithm case must be distinguishable from a generic exchange '
        'failure, or the login page cannot say anything useful about it'
    )
    assert manager._oauth is None, (
        'the cached client survived, so the next attempt would re-apply the '
        'same stale algorithm list'
    )


def test_an_ordinary_failure_keeps_the_cache(manager):
    """CONTROL: dropping the client on every failure would refetch discovery
    on each bad login, which is a request to the IdP per failed attempt."""
    manager._oauth = MagicMock()
    manager._cached_client_key = OIDCManager._client_fingerprint(BASE_CONFIG)

    with patch.object(OIDCManager, '_client',
                      side_effect=RuntimeError('connection reset')):
        claims, error = manager.handle_callback(MagicMock())

    assert claims is None
    assert error == 'token_exchange'
    assert manager._oauth is not None, (
        'an unrelated failure invalidated the client'
    )


def test_the_login_page_explains_the_algorithm_case():
    """The generic rendering turns the code into 'token exchange algorithm',
    which tells an operator nothing about where to look."""
    from pathlib import Path

    login = (Path(__file__).resolve().parent.parent
             / 'templates' / 'login.html').read_text(encoding='utf-8')

    assert 'oidc_token_exchange_algorithm' in login
    assert 'id_token_signing_alg_values_supported' in login, (
        'the message must name the IdP setting to check, or it is just a '
        'longer way of saying it did not work'
    )
