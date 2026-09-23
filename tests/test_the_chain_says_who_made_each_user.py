"""A user created during the setup window is attributable, afterwards.

#862 stopped the setup window from being used to plant credentials: while an
instance is in setup mode every request is served as admin, so it may only
bootstrap — the first admin, then local auth. A second user, or an API key,
gets 409.

An API key left over from *before* that change carries `created_by:
'setup_user'`, is badged in the UI and waits for an operator to confirm or
revoke it. A **user** has no such field: `create_user` stores `created_at`,
`role`, `email` and `enabled`, and nothing about who asked for it.

It is recorded anyway, in the place that matters more. The route audits the
creation, and in setup mode `request.current_user` is `setup_user`, so the
hash-chained audit trail carries:

    'create' / 'user' / id='admin' / user='setup_user'

That is a better home for the fact than a field in `settings.json` would be:
the chain is tamper-evident and `settings.json` is not, and one fact with two
homes is how the two start disagreeing. So no field was added — this pins the
property instead, because `docs/compliance.md` now tells operators to rely on
it, and an attribution that silently stopped being written would make that
advice worse than none.

The distinguishing half is the second test. `setup_user` only means something
if an ordinary creation says something else.
"""
import json
import pathlib

import pytest

from modules.core.auth import SETUP_USERNAME

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
PASSWORD = 'Str0ng-Passw0rd-For-A-Test!'
# The web routes refuse a state-changing request with no Origin/Referer
# ("CSRF protection: missing Origin/Referer"). Without this the control case
# below returns 403 and the test measures the CSRF guard, not attribution.
ORIGIN = {'Origin': 'http://localhost'}


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """A real app over a temporary data tree, in setup mode.

    `API_BEARER_TOKEN` is deliberately removed: with one set the instance is
    not in setup mode and the window under test does not exist.
    """
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)

    from modules.core.factory import create_app
    app, container = create_app()
    assert container.managers['auth'].is_setup_mode(), (
        'the window under test does not exist on this instance')
    return app.test_client(), tmp_path


def _user_entries(tmp_path):
    """Every `user` record in the chain, as (resource_id, attributed-to)."""
    chain = tmp_path / 'data' / 'audit' / 'certificate_audit.chain.jsonl'
    if not chain.exists():
        return []
    out = []
    for line in chain.read_text(encoding='utf-8').splitlines():
        entry = json.loads(line).get('entry', {})
        if entry.get('resource_type') == 'user':
            out.append((entry.get('resource_id'), entry.get('user')))
    return out


def _bootstrap(client, username='admin'):
    return client.post('/api/web/settings/users',
                       json={'username': username, 'password': PASSWORD,
                             'role': 'admin'}, headers=ORIGIN)


def test_the_chain_is_on_and_recording(instance):
    """Guard the guard. If the audit chain were off by default, or user
    creation were not audited, every assertion here would pass over an empty
    list and prove nothing."""
    client, tmp_path = instance
    assert _bootstrap(client).status_code == 201
    assert _user_entries(tmp_path), 'no user records in the chain at all'


def test_a_user_made_in_the_window_is_attributed_to_setup_user(instance):
    """The property `docs/compliance.md` points operators at."""
    client, tmp_path = instance
    _bootstrap(client)
    assert _user_entries(tmp_path) == [('admin', SETUP_USERNAME)]


def test_a_user_made_afterwards_is_attributed_to_the_operator(instance):
    """The half that makes the first one mean something. If every creation
    were recorded as `setup_user`, the marker would separate nothing."""
    client, tmp_path = instance
    _bootstrap(client)
    assert client.post('/api/auth/config', json={'local_auth_enabled': True},
                       headers=ORIGIN).status_code == 200
    assert client.post('/api/auth/login',
                       json={'username': 'admin', 'password': PASSWORD},
                       headers=ORIGIN).status_code == 200
    created = client.post('/api/web/settings/users',
                          json={'username': 'bob', 'password': PASSWORD,
                                'role': 'viewer'}, headers=ORIGIN)

    assert created.status_code == 201, created.get_data(as_text=True)
    assert _user_entries(tmp_path) == [('admin', SETUP_USERNAME), ('bob', 'admin')]


def test_the_window_still_refuses_a_second_user(instance):
    """#862's half of this, kept here because the attribution above is only
    a forensic answer for instances bootstrapped before it."""
    client, _ = instance
    assert _bootstrap(client).status_code == 201
    second = _bootstrap(client, username='planted')
    assert second.status_code == 409
    assert second.get_json().get('code') == 'SETUP_BOOTSTRAP_ONLY'


def test_the_name_in_the_chain_is_the_constant_the_docs_name():
    """`docs/compliance.md` tells an operator to look for `setup_user`. If the
    constant were renamed, the chain would carry the new spelling and the page
    would keep naming the old one."""
    assert SETUP_USERNAME == 'setup_user'


@pytest.mark.parametrize('page', ['compliance.md', 'it/compliance.md'])
def test_the_compliance_page_says_where_to_look(page):
    text = (REPO / 'docs' / page).read_text(encoding='utf-8')
    assert SETUP_USERNAME in text, (
        f'docs/{page} no longer tells operators what attributes a bootstrap '
        f'action, so the property pinned above serves nobody')


def test_a_user_record_still_carries_no_created_by(tmp_path):
    """Stated as a decision, not left as an omission.

    A `created_by` on the user record would be a second copy of what the chain
    already holds, in a mutable file, and the two would drift. If one is added
    later this fails, so it is added deliberately and this note gets rewritten
    rather than silently contradicted.
    """
    import inspect

    from modules.core.auth import AuthManager

    source = inspect.getsource(AuthManager.create_user)
    assert 'created_by' not in source, (
        'create_user now records created_by; the chain was the single home '
        'for that fact — decide which one is canonical and say so'
    )
    assert 'created_at' in source


def test_the_password_used_here_would_be_accepted():
    """Guard the guard: the route enforces 12 chars with a digit and a symbol.
    A password that failed the policy would turn every creation above into a
    400 and every chain assertion into a vacuous empty list."""
    import re

    assert len(PASSWORD) >= 12
    assert re.search(r'\d', PASSWORD) and re.search(r'[^A-Za-z0-9]', PASSWORD)
