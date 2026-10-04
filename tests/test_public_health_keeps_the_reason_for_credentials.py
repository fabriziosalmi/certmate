"""The public health routes say that something failed; the reason needs credentials.

`/health` and `/health/ready` answer anyone who can reach the instance, which
is the point: a load balancer and a readiness probe carry no token. When
certbot cannot run, or the scheduler failed to start, they used to return the
reason as well: the tail of certbot's output, the scheduler's exception text.
That text names install paths, versions and libraries.

The verdict stays public (`certbot: failed`, 503 from readiness). The reason
is in the server log, and in the same field for a caller with credentials.
This drives the real AuthManager, not a stub, so the identity check is the one
production runs.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager
from modules.web.misc_routes import register_misc_routes

pytestmark = [pytest.mark.unit]

REASON = "/opt/venv/bin/certbot: exited 1: ImportError in /opt/venv/lib/python3.12/site-packages"


def _auth(tmp_path, *, configured=True):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for d in dirs:
        d.mkdir()
    sm = SettingsManager(file_ops=FileOperations(*dirs), settings_file=dirs[1] / 'settings.json')
    sm.load_settings()
    am = AuthManager(sm)
    am.set_hmac_key('k')
    am._operator_bearer_token = False
    token = None
    if configured:
        am.create_user('admin', 'Password123!', role='admin')
        am.enable_local_auth(True)
        created, key = am.create_api_key('monitor', role='viewer')
        assert created, key
        token = key['token']
    return am, token


def _app(am):
    scheduler = MagicMock()
    scheduler.running = True
    managers = {'scheduler': scheduler, 'scheduler_status': {'state': 'running'},
                'issuance_status': {'state': 'failed', 'error': REASON}}
    app = Flask(__name__)
    app.config['VERSION'] = 'test'
    register_misc_routes(app, managers, require_web_auth=None, auth_manager=am)
    return app


def test_an_anonymous_caller_gets_the_verdict_without_the_reason(tmp_path):
    am, _ = _auth(tmp_path)
    client = _app(am).test_client()

    health = client.get('/health').get_json()
    assert health['status'] == 'degraded' and health['checks']['certbot'] == 'failed'
    assert '/opt/venv' not in health['checks']['certbot_error']

    ready = client.get('/health/ready')
    assert ready.status_code == 503
    assert '/opt/venv' not in ready.get_json()['certbot_error']


def test_a_caller_with_a_token_gets_the_reason(tmp_path):
    am, token = _auth(tmp_path)
    client = _app(am).test_client()
    headers = {'Authorization': f'Bearer {token}'}

    assert client.get('/health', headers=headers).get_json()['checks']['certbot_error'] == REASON
    assert client.get('/health/ready', headers=headers).get_json()['certbot_error'] == REASON


def test_a_wrong_token_is_an_anonymous_caller(tmp_path):
    am, _ = _auth(tmp_path)
    client = _app(am).test_client()
    body = client.get('/health', headers={'Authorization': 'Bearer not-a-token'}).get_json()
    assert '/opt/venv' not in body['checks']['certbot_error']


def test_setup_mode_identifies_nobody(tmp_path):
    """Before the first credential every request is served as admin, which
    says nothing about who is asking. It must not unlock the reason."""
    am, _ = _auth(tmp_path, configured=False)
    assert am.is_setup_mode() is True
    body = _app(am).test_client().get('/health').get_json()
    assert '/opt/venv' not in body['checks']['certbot_error']


def test_anything_that_is_not_a_user_record_is_no_identity(tmp_path):
    """Fail closed: the reason is shown for a user record and nothing else.
    An auth manager that answers with something truthy that is not one (a
    stub, a future refactor returning a flag) gets the anonymous answer."""
    am = MagicMock()
    am.optional_identity.return_value = True
    body = _app(am).test_client().get('/health').get_json()
    assert '/opt/venv' not in body['checks']['certbot_error']
