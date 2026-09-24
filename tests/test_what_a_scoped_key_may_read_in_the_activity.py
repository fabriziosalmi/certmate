"""`/api/activity` had no scope filter, so a scoped key read every tenant.

The route takes the **viewer** role and returns audit entries. Every
neighbouring route that returns domain-bearing data filters by the caller's
`allowed_domains` — `CertificateList.get` does, and `Settings.get` was given
the filter by audit finding M4, whose words were:

    this endpoint previously returned the full settings['domains'] array to
    any viewer-role caller. A scoped API key could therefore enumerate every
    domain the host had ever issued a cert for, regardless of scope.

The activity feed is the same disclosure by another door, and it was the one
route left without the filter. Measured before:

    chiave ristretta a: ['tenant-a.example.com']
    domini visibili in /api/activity: ['tenant-a.example.com',
                                       'tenant-b-SEGRETO.example.com']

**Why the fix is the filter and not the role.** Raising `/api/activity` to
admin would remove a feature — that page is built for the read-only role, and
it is the only window a viewer has on what is happening — while leaving the
real problem in place, because the problem is not "a viewer reads the audit",
it is "a key restricted to one tenant reads another". A single-tenant install
never had the first problem; a multi-tenant one has the second even between
two administrators.

Instance-level entries — a login, a settings change, a backup — are withheld
from a scoped key too. A key restricted to one tenant has no claim on which
administrator signed in, from which address, or what they changed. Scoping
applies to API keys only (a session and a local user carry no
`allowed_domains`), so no dashboard user loses anything.
"""
import os
import secrets

import pytest

pytestmark = [pytest.mark.unit]

MINE = 'tenant-a.example.com'
THEIRS = 'tenant-b-confidential.example.com'


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('activity-scope')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.core.factory import create_app
        app, container = create_app()

        audit = container.managers['audit']
        for domain in (MINE, THEIRS):
            audit.log_operation(
                operation='create', resource_type='certificate',
                resource_id=domain, status='success',
                details={'domain': domain, 'ca_provider': 'letsencrypt'},
                user='admin', ip_address='203.0.113.5')
        # Instance-level work: no domain anywhere in it. A distinct address,
        # so a test can tell "the scoped key cannot see the LOGIN's address"
        # from "it cannot see any address" — it does see the one on its own
        # tenant's entry, and deliberately: that entry is about its domain,
        # and who issued that certificate from where is its business.
        audit.log_operation(
            operation='login', resource_type='session', resource_id='admin',
            status='success', details={}, user='admin',
            ip_address='198.51.100.9')
        yield app, container


def _read(instance, scope, query=''):
    app, container = instance
    ok, key = container.managers['auth'].create_api_key(
        f'probe-{secrets.token_hex(4)}', role='viewer', allowed_domains=scope)
    assert ok is True, key
    headers = {'Authorization': f"Bearer {key['token']}",
               'Origin': 'http://localhost'}
    response = app.test_client().get(f'/api/activity?limit=50{query}',
                                     headers=headers)
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def _ids(body):
    return [f"{e.get('resource_type')}:{e.get('resource_id')}"
            for e in body.get('entries', [])]


# --- the regression -------------------------------------------------------

def test_a_scoped_key_does_not_read_another_tenant(instance):
    """THE regression."""
    body = _read(instance, [MINE])

    assert THEIRS not in str(body), (
        'a key scoped to one tenant read another tenant out of the activity '
        'feed')
    assert f'certificate:{MINE}' in _ids(body)


def test_a_scoped_key_does_not_read_instance_level_work(instance):
    """A key restricted to one tenant has no claim on which administrator
    signed in, or from where.

    The login carries its own address so this can be precise. The scoped key
    still sees the administrator's name and address on its OWN tenant's
    entry — that entry is about its domain, and withholding it would leave
    the feed unable to say who did what to the thing the key is scoped to.
    """
    body = _read(instance, [MINE])

    assert 'session:admin' not in _ids(body)
    assert '198.51.100.9' not in str(body), "the login's address leaked"
    assert '203.0.113.5' in str(body), (
        'the key cannot see its own tenant\'s entry either — the filter is '
        'a blanket refusal, not a scope check')


def test_an_unscoped_key_still_reads_everything(instance):
    """CONTROL, and the reason this is a filter and not a role change: an
    unrestricted viewer is what the activity page is FOR. A fix that hid
    entries from everyone would satisfy the tests above and delete the
    feature."""
    body = _read(instance, None)
    ids = _ids(body)

    assert f'certificate:{MINE}' in ids
    assert f'certificate:{THEIRS}' in ids
    assert 'session:admin' in ids


def test_a_key_scoped_to_both_reads_both(instance):
    """CONTROL on the matching itself: the filter must not be a blanket
    refusal dressed up as a scope check."""
    body = _read(instance, [MINE, THEIRS])
    ids = _ids(body)

    assert f'certificate:{MINE}' in ids
    assert f'certificate:{THEIRS}' in ids


def test_the_count_matches_what_was_returned(instance):
    """The envelope is built from the filtered list, not the raw one — a
    count that says 3 beside one entry tells a client something false."""
    body = _read(instance, [MINE])

    assert body['count'] == len(body['entries'])


def test_a_filtered_search_is_scoped_too(instance):
    """The route has two paths — recent entries and a filtered search — and
    a filter applied to one of them is a filter that can be walked around by
    adding a query parameter."""
    body = _read(instance, [MINE], query='&operation=create')

    assert THEIRS not in str(body)
    assert body['count'] == len(body['entries'])


# --- how an entry's domain is decided ------------------------------------

def test_an_entry_is_matched_by_the_domain_it_names():
    from modules.web.misc_routes import _entry_domain

    assert _entry_domain({'details': {'domain': 'a.example.com'}}) == 'a.example.com'
    assert _entry_domain({'resource_type': 'certificate',
                          'resource_id': 'b.example.com'}) == 'b.example.com'


def test_an_entry_about_the_instance_names_no_domain():
    """`resource_id` is a username on a login and a filename on a backup.
    Reading it as a domain would let a scope pattern match by accident."""
    from modules.web.misc_routes import _entry_domain

    assert _entry_domain({'resource_type': 'session',
                          'resource_id': 'admin'}) is None
    assert _entry_domain({'resource_type': 'backup',
                          'resource_id': 'backup_2026.zip'}) is None
    assert _entry_domain({}) is None


def test_the_route_asks_the_same_matcher_as_its_neighbours():
    """`domain_matches_scope` is the shared rule. A second spelling of
    "does this domain fall in scope" is how two answers to one question
    start."""
    import ast
    import inspect

    from modules.web import misc_routes

    calls = [ast.unparse(node) for node in
             ast.walk(ast.parse(inspect.getsource(misc_routes)))
             if isinstance(node, ast.Call)]

    assert any('domain_matches_scope' in call for call in calls)
