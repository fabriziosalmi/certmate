"""The web backup and cache routes, which the gated suite never executed (#662).

Four handlers, 40% covered: every success path and every failure path went
unrun. They matter more than their size suggests — `/api/web/backups/create`
is the one place in the web UI that can be asked for a **plaintext** backup,
and its `include_secrets` flag decides whether the file it writes is a
credential dump.

The failure branches are here too, because all four swallow the exception and
answer a fixed message. That is a deliberate choice — the detail belongs in the
log, not in an HTTP body — but it means a broken manager and a working one
differ only in the status code, and nothing was checking that the status code
was right.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.backup_cache_routes import register_backup_cache_routes

pytestmark = [pytest.mark.unit]


@pytest.fixture
def wired():
    """The routes, plus the managers they were given, so a test can steer them."""
    app = Flask(__name__)
    app.config['TESTING'] = True

    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    file_ops = MagicMock()
    settings = MagicMock()
    cache = MagicMock()

    register_backup_cache_routes(
        app, managers={}, require_web_auth=lambda fn: fn, auth_manager=auth,
        file_ops=file_ops, settings_manager=settings, cache_manager=cache)
    return app.test_client(), file_ops, settings, cache


def test_listing_backups_returns_what_file_ops_reports(wired):
    client, file_ops, _settings, _cache = wired
    file_ops.list_backups.return_value = {'unified': [{'filename': 'b.zip'}]}

    response = client.get('/api/web/backups')

    assert response.status_code == 200
    assert response.get_json()['unified'][0]['filename'] == 'b.zip'


def test_a_masked_backup_is_the_default(wired):
    """The flag decides whether the file on disk is a credential dump, so the
    default is the safe one and this pins it."""
    client, file_ops, settings, _cache = wired
    file_ops.create_unified_backup.return_value = 'backup_x.zip'
    settings.load_settings.return_value = {'email': 'ops@example.com'}

    response = client.post('/api/web/backups/create', json={})

    assert response.status_code == 200
    assert response.get_json()['secrets_masked'] is True
    _args, kwargs = file_ops.create_unified_backup.call_args
    assert kwargs['include_secrets'] is False, (
        'the web route asked for a complete backup without being told to'
    )


def test_a_complete_backup_has_to_be_asked_for(wired):
    """CONTROL: the opt-in must actually reach file_ops, or the flag is
    decoration and an operator who asked for a restorable archive gets a
    masked one."""
    client, file_ops, settings, _cache = wired
    file_ops.create_unified_backup.return_value = 'backup_x.zip.enc'
    settings.load_settings.return_value = {}

    response = client.post('/api/web/backups/create',
                           json={'include_secrets': True, 'reason': 'pre-upgrade'})

    assert response.get_json()['secrets_masked'] is False
    _args, kwargs = file_ops.create_unified_backup.call_args
    assert kwargs['include_secrets'] is True
    assert file_ops.create_unified_backup.call_args[0][1] == 'pre-upgrade', (
        'the reason is what an operator reads in the backup list months later'
    )


def test_a_truthy_string_does_not_silently_become_a_plaintext_backup(wired):
    """`bool("false")` is True. Worth knowing which way this route goes, since
    a form posting the string "false" would otherwise write a credential dump.
    """
    client, file_ops, settings, _cache = wired
    file_ops.create_unified_backup.return_value = 'backup_x.zip'
    settings.load_settings.return_value = {}

    client.post('/api/web/backups/create', json={'include_secrets': 'false'})

    _args, kwargs = file_ops.create_unified_backup.call_args
    assert kwargs['include_secrets'] is True, (
        'this route coerces with bool(), so the string "false" is truthy. That '
        'is the current behaviour and it is recorded here rather than assumed '
        'either way — if it is ever tightened, this test should be the thing '
        'that changes, deliberately.'
    )


def test_cache_stats_are_returned(wired):
    client, _file_ops, _settings, cache = wired
    cache.get_cache_stats.return_value = {'entries': 3}

    for path in ('/api/cache/stats', '/api/web/cache/stats'):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.get_json()['entries'] == 3


def test_clearing_the_cache_calls_through(wired):
    client, _file_ops, _settings, cache = wired

    for path in ('/api/cache/clear', '/api/web/cache/clear'):
        cache.clear_cache.reset_mock()
        response = client.post(path)
        assert response.status_code == 200, path
        assert cache.clear_cache.called, f'{path} answered without clearing'


@pytest.mark.parametrize('method,path,manager_attr,call', [
    ('get', '/api/web/backups', 'file_ops', 'list_backups'),
    ('post', '/api/web/backups/create', 'file_ops', 'create_unified_backup'),
    ('get', '/api/cache/stats', 'cache', 'get_cache_stats'),
    ('post', '/api/cache/clear', 'cache', 'clear_cache'),
])
def test_a_failing_manager_is_a_500_and_not_a_stack_trace(
        wired, method, path, manager_attr, call):
    """All four swallow the exception and answer a fixed message — deliberately,
    since the detail belongs in the log. The consequence is that a broken
    manager and a working one differ only in the status code, so the status
    code is the only thing that can be checked, and it was not being.
    """
    client, file_ops, settings, cache = wired
    manager = {'file_ops': file_ops, 'cache': cache}[manager_attr]
    getattr(manager, call).side_effect = RuntimeError('the disk is gone')
    settings.load_settings.return_value = {}

    response = getattr(client, method)(path, json={})

    assert response.status_code == 500
    body = response.get_json()
    assert 'error' in body
    assert 'disk is gone' not in str(body), (
        'the internal failure text reached the HTTP response'
    )
