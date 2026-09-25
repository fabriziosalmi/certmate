"""Deploy-hook commands came back verbatim to the viewer role.

`mask_secrets_in_settings` masks by **field name** — `token`, `secret`,
`password`, `key`, `credential`, `hmac`, `authorization`. `command` is not
one of those, so a deploy hook such as

    curl -H "X-Api-Key: ..." https://lb.internal/reload

was returned intact by `GET /api/settings` and `GET /api/web/settings`, both
of which take the **viewer** role.

The project already says what it thinks of those strings. Two hundred lines
below that route, the deploy-config save refuses to record them:

    # Hook commands themselves are NEVER logged (would leak
    # secrets + risk log-injection).

So the audit log, which only an admin can read, holds less than a settings
read available to every viewer.

The fix follows the rule that was already there rather than inventing one.
`users` and `api_keys` are stripped below admin in that same handler, with
the reason "they have dedicated admin-only endpoints". `deploy_hooks` has
one too — `/api/deploy/config`, admin — and it is the only thing the UI's
deploy editor reads, so nothing in the product loses a field.
"""
import os
import secrets

import pytest

pytestmark = [pytest.mark.unit]

TOKEN = secrets.token_urlsafe(32)
HOOK_COMMAND = 'curl -H "X-Api-Key: SUPERSECRET123" https://lb.internal/reload'


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('viewer-settings')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', TOKEN)
        os.environ['API_BEARER_TOKEN'] = TOKEN
        from modules.factory import create_app
        app, container = create_app()

        container.managers['settings'].update(
            lambda s: s.__setitem__('deploy_hooks', {
                'enabled': True,
                'global_hooks': [{'id': 'h1', 'name': 'reload',
                                  'command': HOOK_COMMAND,
                                  'on_events': ['renewed']}],
                'domain_hooks': {'example.com': [
                    {'id': 'h2', 'name': 'per-domain',
                     'command': HOOK_COMMAND, 'on_events': ['renewed']}]},
                'targets': [],
            }), 'seed_hooks')
        yield app, container


def _as(app, container, role):
    """A client carrying a real API key of *role*.

    The contract is copied from tests/test_api_key_expiry_and_masking.py and
    from create_api_key itself — `(ok, {..., 'token': plaintext})`. The first
    draft guessed `result['key']` and every assertion here failed with 401,
    which is the right failure for an invented contract but says nothing
    about the behaviour under test.
    """
    auth = container.managers['auth']
    ok, created = auth.create_api_key(f'probe-{role}-{secrets.token_hex(4)}',
                                      role=role)
    assert ok is True, created
    return app.test_client(), {'Authorization': f"Bearer {created['token']}",
                               'Origin': 'http://localhost'}


def _settings(app, container, role, path='/api/web/settings'):
    client, headers = _as(app, container, role)
    response = client.get(path, headers=headers)
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


# --- the regression -------------------------------------------------------

def test_a_viewer_does_not_read_hook_commands(instance):
    """THE regression, at the address that had it.

    `/api/web/settings` is answered by the web handler, which returns the
    whole settings tree and removes a few keys — a DENYLIST. That is why
    this kept happening: every subtree added since is included by default,
    and only the ones somebody remembered are taken out.
    """
    app, container = instance

    body = _settings(app, container, 'viewer', '/api/web/settings')

    assert 'SUPERSECRET123' not in str(body), (
        'a viewer read a deploy hook command, which the project refuses to '
        'even write to the audit log')
    assert 'deploy_hooks' not in body


def test_the_other_address_is_safe_by_construction(instance):
    """`/api/settings` GET is registered twice and the flask-restx resource
    wins, so it is NOT the handler above. It marshals through an explicit
    model — an ALLOWLIST — so `deploy_hooks` was never in its output and
    could not have been.

    Recorded because it is the more interesting half: the mutation that
    removed the fix left this address green, which is the right answer for
    the wrong-looking reason. Two addresses, two handlers, two opposite
    safety models.
    """
    app, container = instance

    body = _settings(app, container, 'viewer', '/api/settings')

    assert 'deploy_hooks' not in body
    assert 'SUPERSECRET123' not in str(body)

    from flask import Flask
    from flask_restx import Api

    from modules.api.models import create_api_models

    models = create_api_models(Api(Flask('model-probe')))
    declared = set(models['settings_model'].keys())

    assert declared, 'the settings model declares nothing — this reads nothing'
    assert 'deploy_hooks' not in declared
    assert 'users' not in declared and 'api_keys' not in declared


def test_an_operator_does_not_either(instance):
    """Operator is not admin. The deploy editor is admin-only, so there is
    no role between the two that needs these."""
    app, container = instance

    body = _settings(app, container, 'operator')

    assert 'SUPERSECRET123' not in str(body)


def test_an_admin_still_reads_them(instance):
    """CONTROL. A fix that stripped them for everyone would break the
    settings view for the role that edits them — and would be
    indistinguishable from this one in the tests above."""
    app, container = instance

    body = _settings(app, container, 'admin')

    assert body['deploy_hooks']['global_hooks'][0]['command'] == HOOK_COMMAND


def test_the_admin_only_editor_is_unaffected(instance):
    """The UI reads and writes deploy config here, not through settings —
    which is why stripping the subtree costs the product nothing."""
    app, container = instance
    client, headers = _as(app, container, 'admin')

    response = client.get('/api/deploy/config', headers=headers)

    assert response.status_code == 200
    body = response.get_json()
    assert body['global_hooks'][0]['command'] == HOOK_COMMAND


def test_a_viewer_still_reads_what_a_viewer_needs(instance):
    """CONTROL on proportionality: the settings view exists so a viewer can
    render the interface. Stripping one subtree must not empty it."""
    app, container = instance

    body = _settings(app, container, 'viewer')

    assert 'email' in body or 'dns_providers' in body
    assert isinstance(body, dict) and len(body) > 3


def test_the_neighbouring_strips_are_still_in_place(instance):
    """`users` and `api_keys` were stripped below admin for the same reason,
    and this change sits beside them. If one goes, they all go."""
    app, container = instance

    body = _settings(app, container, 'viewer')

    assert 'users' not in body
    assert 'api_keys' not in body


def test_the_masker_alone_would_not_have_caught_it():
    """Why the strip is at the route and not in the masker: the masker works
    on field names, and `command` is not a secret-sounding one. Stated here
    so nobody 'simplifies' this by moving it."""
    from modules.core.settings import mask_secrets_in_settings

    masked = mask_secrets_in_settings({
        'deploy_hooks': {'global_hooks': [{'command': HOOK_COMMAND}]},
        'dns_providers': {'cloudflare': {'default': {'api_token': 'REAL'}}},
    })

    assert masked['deploy_hooks']['global_hooks'][0]['command'] == HOOK_COMMAND
    assert masked['dns_providers']['cloudflare']['default']['api_token'] == '********'
