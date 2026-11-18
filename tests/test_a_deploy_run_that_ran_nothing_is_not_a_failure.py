"""A manual deploy run that ran nothing is not written to Activity as a failed deploy.

UX perception audit, 2026-11-18 (P51): with deploy hooks off, "Run deploy
hooks now" answered 200 with `total: 0` and "Deploy hooks are disabled", and
the route wrote an Activity entry `deploy ... status: failure` for a deploy
that never ran. The same for a certificate no hook or target applies to. The
answer is unchanged (the dashboard shows its sentence); the audit entry is
written when something ran, and then says how it went.

The browser half (the button is not offered while hooks are off, and a failed
run's toast names the hook and its error) is
tests/test_ui_certificate_actions_are_labelled.py.
"""
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources

pytestmark = [pytest.mark.unit]

DOMAIN = 'site1.example.test'
DISABLED = {'ok': False, 'total': 0, 'succeeded': 0, 'failed': 0, 'results': [],
            'error': 'Deploy hooks are disabled. Enable them in Settings → Deploy.'}
NOTHING_APPLIES = {'ok': False, 'total': 0, 'succeeded': 0, 'failed': 0, 'results': [],
                   'error': f'No enabled hooks or deploy targets configured for {DOMAIN}.'}
FAILED = {'ok': False, 'total': 1, 'succeeded': 0, 'failed': 1,
          'results': [{'hook_name': 'reload-lb', 'success': False, 'exit_code': 1,
                       'stderr': 'ls: /run/lb01-admin.sock: No such file or directory\n'}]}
SUCCEEDED = {'ok': True, 'total': 1, 'succeeded': 1, 'failed': 0,
             'results': [{'hook_name': 'reload-lb', 'success': True, 'exit_code': 0}]}


def _passthrough(_role):
    def deco(fn):
        return fn
    return deco


def _client(tmp_path, summary):
    (tmp_path / DOMAIN).mkdir()
    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough)
    audit = MagicMock()
    deployer = MagicMock()
    deployer.run_manual_deploy.return_value = summary
    managers = {
        'auth': auth, 'settings': MagicMock(), 'dns': MagicMock(), 'cache': MagicMock(),
        'certificates': MagicMock(cert_dir=Path(tmp_path), storage_manager=None),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'deployer': deployer, 'audit': audit,
    }
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_api_resources(api, create_api_models(api), managers)
    ns = Namespace('certificates')
    api.add_namespace(ns)
    ns.add_resource(resources['CertificateRunDeploy'], '/<string:domain>/deploy')
    return app.test_client(), audit


def _deploy_entries(audit):
    return [call.kwargs for call in audit.log_operation.call_args_list if call.kwargs.get('operation') == 'deploy']


@pytest.mark.parametrize('summary', [DISABLED, NOTHING_APPLIES], ids=['hooks-off', 'nothing-applies'])
def test_a_run_that_ran_nothing_writes_no_failed_deploy(tmp_path, summary):
    client, audit = _client(tmp_path, summary)
    response = client.post(f'/api/certificates/{DOMAIN}/deploy')
    assert response.status_code == 200
    # The answer still says why nothing ran, for the dashboard to show.
    assert response.get_json()['total'] == 0 and response.get_json()['error'] == summary['error']
    assert [e for e in _deploy_entries(audit) if e['status'] == 'failure'] == [], _deploy_entries(audit)


def test_a_run_whose_hook_failed_is_still_a_failure(tmp_path):
    """CONTROL: what ran and failed is written as a failure, with its counts."""
    client, audit = _client(tmp_path, FAILED)
    assert client.post(f'/api/certificates/{DOMAIN}/deploy').status_code == 200
    [entry] = _deploy_entries(audit)
    assert entry['status'] == 'failure' and entry['details']['total'] == 1 and entry['details']['failed'] == 1


def test_a_run_that_succeeded_is_a_success(tmp_path):
    """CONTROL: and what ran and succeeded is a success."""
    client, audit = _client(tmp_path, SUCCEEDED)
    assert client.post(f'/api/certificates/{DOMAIN}/deploy').status_code == 200
    [entry] = _deploy_entries(audit)
    assert entry['status'] == 'success'
