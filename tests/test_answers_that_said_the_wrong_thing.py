"""Seven answers that contradicted what they meant, found by calling every route (#1105).

The route walk (`tests/contract_routes.py`) records what each route answers, and its snapshot
moves with these fixes. These tests say what each one is FOR, in the words of the defect, so a
change that brings one back fails with the name of the condition and not with a diff in a
file of 5,000 lines:

  * #1106  deleting a DNS account that does not exist: 404, not 500 (a 500 is for a settings
           file that could not be written);
  * #1107  testing a deploy hook that exists: 200 whether it passed or not, not 404 with
           `"success": true` in the body; a hook that does not exist stays 404;
  * #1111  renewing or revoking a client certificate that does not exist: 404, as the detail
           route says, not 400;
  * #1108  `GET /api/backups` sends the `size` and `created` its model declares, and the
           renewal answer sends the `dns_provider` and `duration` it has always had keys for.
           And `certificate_match` is declared as the boolean it is.

They run in the world of the walk (`tests/contract_world.py`): sealed from the network, with a
stand-in for certbot.
"""
import contextlib
from pathlib import Path
from unittest import mock

import pytest

from tests import contract_support as support
from tests import contract_world as world

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def instance():
    app, token = support.build_app()
    container = app.extensions['certmate_container']
    certbot = world.Certbot()
    with world.sealed(), world.certbot_standing_in(certbot), world.serving() as port, world.environment():
        seeded = world.seed(container, port)
        client = app.test_client()
        headers = {'Authorization': f'Bearer {token}'}

        class Instance:
            pass

        instance = Instance()
        instance.app, instance.container, instance.certbot, instance.world = app, container, certbot, seeded

        def call(verb, path, body=None, **kwargs):
            # One request a minute, as far as the rate limiter can tell: this module makes dozens.
            container.managers['rate_limiter'].requests.clear()
            options = {'headers': headers, **kwargs}
            if body is not None:
                options['json'] = body
            return getattr(client, verb)(path, **options)

        instance.call = call
        yield instance


# --- #1106 -----------------------------------------------------------------

def _account(instance, provider, name):
    config = {'api_token': 'k' * 24}
    return instance.call('post', f'/api/dns/{provider}/accounts', {'name': name, 'config': config})


def test_deleting_a_dns_account_that_exists_is_a_200(instance):
    assert _account(instance, 'cloudflare', 'doomed').status_code == 200
    response = instance.call('delete', '/api/dns/cloudflare/accounts/doomed')
    assert response.status_code == 200 and response.get_json()['success'] is True


def test_deleting_a_dns_account_that_does_not_exist_is_a_404_not_a_500(instance):
    response = instance.call('delete', '/api/dns/cloudflare/accounts/never-existed')
    assert response.status_code == 404
    assert 'never-existed' in response.get_json()['error']


def test_deleting_the_same_account_twice_is_a_200_then_a_404(instance):
    _account(instance, 'cloudflare', 'twice')
    assert instance.call('delete', '/api/dns/cloudflare/accounts/twice').status_code == 200
    assert instance.call('delete', '/api/dns/cloudflare/accounts/twice').status_code == 404


def test_the_account_of_another_provider_with_the_same_id_is_not_the_one_deleted(instance):
    _account(instance, 'cloudflare', 'shared')
    _account(instance, 'digitalocean', 'shared')
    assert instance.call('delete', '/api/dns/cloudflare/accounts/shared').status_code == 200
    # Not there under cloudflare any more, still there under digitalocean.
    assert instance.call('delete', '/api/dns/cloudflare/accounts/shared').status_code == 404
    assert instance.call('delete', '/api/dns/digitalocean/accounts/shared').status_code == 200


def test_a_settings_file_that_cannot_be_written_is_still_a_500(instance):
    """The 500 is kept for what it means: the account exists and the delete failed."""
    _account(instance, 'cloudflare', 'unwritable')
    with mock.patch.object(instance.container.managers['dns'], 'delete_account', return_value=False):
        response = instance.call('delete', '/api/dns/cloudflare/accounts/unwritable')
    assert response.status_code == 500
    assert instance.call('delete', '/api/dns/cloudflare/accounts/unwritable').status_code == 200


def test_the_dashboards_route_says_404_too(instance):
    """`/api/web/settings/accounts/<id>` finds its provider (#1089) and, once it has, deletes."""
    _account(instance, 'cloudflare', 'webdoomed')
    assert instance.call('delete', '/api/web/settings/accounts/webdoomed').status_code == 200
    assert instance.call('delete', '/api/web/settings/accounts/webdoomed').status_code == 404


# --- #1107 -----------------------------------------------------------------

def _hooks(instance, command='echo deployed'):
    body = {'enabled': False, 'domain_hooks': {},
            'global_hooks': [{'id': 'wrong-thing', 'name': 'wrong-thing', 'command': command,
                              'enabled': True, 'on_events': ['manual']}]}
    assert instance.call('post', '/api/deploy/config', body).status_code == 200


def test_a_hook_that_ran_is_a_200_with_the_run_in_the_body(instance):
    _hooks(instance)
    response = instance.call('post', '/api/deploy/test/wrong-thing', {})
    body = response.get_json()
    assert response.status_code == 200
    assert body['success'] is True and body['exit_code'] == 0 and body['error'] is None
    assert body['dry_run'] is True and body['hook_id'] == 'wrong-thing'


def test_a_hook_that_ran_and_failed_is_also_a_200_and_says_so_in_the_body(instance):
    """A 404 for it would be the defect again: the hook exists, and it ran."""
    _hooks(instance)
    instance.certbot.fail_with('the hook failed')
    response = instance.call('post', '/api/deploy/test/wrong-thing', {})
    body = response.get_json()
    assert response.status_code == 200
    assert body['success'] is False and body['error'], body


def test_a_hook_that_does_not_exist_is_still_a_404(instance):
    _hooks(instance)
    response = instance.call('post', '/api/deploy/test/not-a-hook', {})
    assert response.status_code == 404
    assert response.get_json()['reason'] == 'hook_missing_from_config'


# --- #1111 -----------------------------------------------------------------

@pytest.fixture
def client_cert(instance):
    response = instance.call('post', '/api/client-certs/create',
                             {'common_name': 'wrong-thing@example.test', 'email': 'wrong-thing@example.test'})
    assert response.status_code == 201, response.get_json()
    return response.get_json()['identifier']


def test_renewing_a_client_certificate_that_exists_is_a_201(instance, client_cert):
    response = instance.call('post', f'/api/client-certs/{client_cert}/renew', {})
    assert response.status_code == 201 and response.get_json()['identifier'] != client_cert


def test_revoking_a_client_certificate_that_exists_is_a_200(instance, client_cert):
    assert instance.call('post', f'/api/client-certs/{client_cert}/revoke', {}).status_code == 200


@pytest.mark.parametrize('action', ['renew', 'revoke'])
def test_a_client_certificate_that_does_not_exist_is_a_404_like_the_detail_route_says(instance, action):
    missing = 'no-such-certificate'
    assert instance.call('get', f'/api/client-certs/{missing}').status_code == 404
    response = instance.call('post', f'/api/client-certs/{missing}/{action}', {})
    assert response.status_code == 404
    assert missing in response.get_json()['error']


@pytest.mark.parametrize('action', ['renew', 'revoke'])
def test_an_identifier_that_is_not_one_is_still_a_400(instance, action):
    """404 is for a well-formed identifier nobody has; a malformed one never reaches the lookup."""
    assert instance.call('post', f'/api/client-certs/bad..id/{action}', {}).status_code in (400, 404)
    assert instance.call('post', f'/api/client-certs/{"x" * 400}/{action}', {}).status_code == 400


# --- #1108 -----------------------------------------------------------------

def test_a_backup_entry_has_the_size_and_created_its_model_declares(instance):
    response = instance.call('post', '/api/backups/create', {'type': 'unified', 'reason': 'wrong-thing'})
    name = response.get_json()['backups'][0]['filename']
    entries = instance.call('get', '/api/backups').get_json()['unified']
    entry = next(item for item in entries if item['filename'] == name)
    on_disk = Path(instance.container.backup_dir) / 'unified' / name
    assert entry['size'] == on_disk.stat().st_size and isinstance(entry['size'], int)
    assert isinstance(entry['created'], str) and entry['created'] == entry['metadata']['created']
    assert all(isinstance(item['size'], int) and isinstance(item['created'], str) for item in entries), (
        'an entry of the list has a null size or created')


def test_a_renewal_says_which_provider_and_how_long_it_took(instance):
    response = instance.call('post', f'/api/certificates/{world.DOMAIN}/renew', {})
    body = response.get_json()
    assert response.status_code == 200 and body['renewed'] is True
    assert body['dns_provider'] == 'cloudflare'
    assert isinstance(body['duration'], float) and body['duration'] >= 0


def test_an_async_renewal_job_carries_them_in_its_result(instance):
    response = instance.call('post', f'/api/certificates/{world.DOMAIN}/renew', {'async': True})
    assert response.status_code == 202
    job = response.get_json()['job_id']
    instance.call('get', f'/api/certificates/jobs/{job}')            # touch it, then wait
    result = None
    for _ in range(200):
        record = instance.call('get', f'/api/certificates/jobs/{job}').get_json()
        if record['status'] in ('succeeded', 'failed'):
            result = record
            break
        with contextlib.suppress(Exception):
            import time
            time.sleep(0.02)
    assert result and result['status'] == 'succeeded', result
    assert result['result']['dns_provider'] == 'cloudflare' and result['result']['duration'] >= 0


def test_the_openapi_document_declares_certificate_match_as_the_boolean_it_is_sent_as(instance):
    document = instance.call('get', '/api/swagger.json').get_json()
    assert document['definitions']['DeploymentStatus']['properties']['certificate_match']['type'] == 'boolean'
    status = instance.call('get', f'/api/certificates/{world.DOMAIN}/deployment-status').get_json()
    assert isinstance(status['certificate_match'], bool)
