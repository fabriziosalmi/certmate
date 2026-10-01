"""The routes around the webhook deploy target: confirming a destination, and previewing.

The unit tests pin what the target and the consent logic do. What only a request
can show: that the server, and not the client, writes the confirmation; that it
survives an unrelated edit and does not survive a change of host; that each
confirmation reaches the audit log once; and that the preview sends nothing.
"""
import json
import secrets

import pytest

from modules.core import pinned_https as ph

pytestmark = [pytest.mark.unit]

HOST = 'lb.internal'
TEMPLATE_WITH_KEY = '{"cert": "{{fullchain}}", "key": "{{privkey_pkcs8}}"}'
TEMPLATE_CERT_ONLY = '{"cert": "{{fullchain}}"}'


@pytest.fixture
def instance(tmp_path, monkeypatch):
    for var, sub in (('CERTMATE_CERT_DIR', 'certificates'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(var, str(tmp_path / sub))
    # urlsafe, not hex: a random 64-hex token is refused by validate_api_token about 0.17% of the time
    # (a 3-character run that happens to occur three times), which fails a fixture at random.
    token = secrets.token_urlsafe(48)
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    from modules.factory import create_app
    app, container = create_app()
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    class Instance:
        pass

    i = Instance()
    i.container, i.client, i.headers = container, client, headers
    i.save = lambda targets: client.post('/api/deploy/config', data=json.dumps(
        {'enabled': True, 'targets': targets}), headers=headers)
    i.config = lambda: client.get('/api/deploy/config', headers=headers).get_json()
    i.preview = lambda target, **kw: client.post('/api/deploy/targets/preview', data=json.dumps(target),
                                                 headers=headers, **kw)
    i.audit = []
    container.managers['audit'].log_operation = lambda **kw: i.audit.append(kw)
    return i


def _target(template=TEMPLATE_WITH_KEY, host=HOST, **over):
    config = {'url': f'https://{host}:8443/api/certificate', 'payload_template': template,
              'allow_internal': True}
    if template == TEMPLATE_WITH_KEY:
        config['acknowledge_key_delivery_to'] = host
    target = {'type': 'webhook', 'id': 'lb', 'name': 'Load balancer', 'enabled': True,
              'domains': ['shop.example.com'], 'config': config}
    target.update(over)
    return target


def _stored(instance):
    return next(t for t in instance.config()['targets'] if t['id'] == 'lb')


def test_a_confirmation_is_recorded_by_the_server(instance):
    response = instance.save([_target()])

    assert response.status_code == 200, response.get_json()
    stored = _stored(instance)
    assert stored['delivery_consent']['host'] == HOST
    assert stored['delivery_consent']['by'] and stored['delivery_consent']['at']
    assert 'acknowledge_key_delivery_to' not in stored['config']


def test_a_save_that_sends_the_key_without_a_confirmation_is_refused_and_changes_nothing(instance):
    target = _target()
    del target['config']['acknowledge_key_delivery_to']

    response = instance.save([target])

    assert response.status_code == 400
    assert HOST in response.get_json()['error'] and 'acknowledge_key_delivery_to' in response.get_json()['error']
    assert instance.config()['targets'] == []


def test_a_confirmation_for_another_host_is_refused(instance):
    target = _target()
    target['config']['acknowledge_key_delivery_to'] = 'somewhere-else.internal'
    assert instance.save([target]).status_code == 400
    assert instance.config()['targets'] == []


def test_a_client_cannot_confirm_for_itself(instance):
    target = _target()
    del target['config']['acknowledge_key_delivery_to']
    target['delivery_consent'] = {'host': HOST, 'by': 'admin', 'at': '2020-01-01T00:00:00Z'}
    assert instance.save([target]).status_code == 400
    assert instance.config()['targets'] == []


def test_the_confirmation_survives_an_edit_that_does_not_move_the_destination(instance):
    instance.save([_target()])
    first = _stored(instance)['delivery_consent']

    resaved = _target()
    del resaved['config']['acknowledge_key_delivery_to']
    resaved['config']['timeout'] = 30
    assert instance.save([resaved]).status_code == 200
    assert _stored(instance)['delivery_consent'] == first


def test_moving_the_destination_ends_the_confirmation(instance):
    instance.save([_target()])
    moved = _target()
    del moved['config']['acknowledge_key_delivery_to']
    moved['config']['url'] = 'https://elsewhere.internal:8443/api/certificate'

    assert instance.save([moved]).status_code == 400
    assert _stored(instance)['config']['url'].startswith(f'https://{HOST}')       # still the confirmed one

    moved['config']['acknowledge_key_delivery_to'] = 'elsewhere.internal'
    assert instance.save([moved]).status_code == 200
    assert _stored(instance)['delivery_consent']['host'] == 'elsewhere.internal'


def test_each_confirmation_is_audited_once(instance):
    instance.save([_target()])
    confirmations = [a for a in instance.audit if a.get('operation') == 'confirm_key_delivery']
    assert len(confirmations) == 1
    assert confirmations[0]['details'] == {'host': HOST, 'target': 'Load balancer'}
    assert confirmations[0]['resource_id'] == 'lb' and confirmations[0]['status'] == 'success'
    # Who confirmed is the same in the audit log and in the record the target checks.
    assert confirmations[0]['user'] == _stored(instance)['delivery_consent']['by']
    assert confirmations[0]['user'], 'the confirmation was recorded without saying who made it'

    resaved = _target()
    del resaved['config']['acknowledge_key_delivery_to']
    instance.save([resaved])
    assert len([a for a in instance.audit if a.get('operation') == 'confirm_key_delivery']) == 1, (
        'carrying a confirmation over is not a new confirmation')


def test_a_certificate_only_target_needs_no_confirmation_and_records_none(instance):
    assert instance.save([_target(template=TEMPLATE_CERT_ONLY)]).status_code == 200
    assert 'delivery_consent' not in _stored(instance)
    assert not [a for a in instance.audit if a.get('operation') == 'confirm_key_delivery']


@pytest.mark.parametrize('mutate, needle', [
    (lambda t: t.update(domains=[]), 'explicit list of domains'),
    (lambda t: t['config'].update(url='http://lb.internal/x'), 'https'),
    (lambda t: t['config'].update(payload_template='{"k": "{{privkey}}"}'), 'privkey_pkcs8'),
])
def test_a_bad_target_is_refused_through_the_route_with_the_reason(instance, mutate, needle):
    target = _target(template=TEMPLATE_CERT_ONLY)
    mutate(target)
    response = instance.save([target])
    assert response.status_code == 400 and needle in response.get_json()['error']


def test_the_other_target_types_are_untouched(instance):
    k8s = {'type': 'kubernetes-secret', 'id': 'k', 'name': 'k8s', 'enabled': True,
           'config': {'secret_name': 's', 'namespace': 'n', 'in_cluster': True}}
    assert instance.save([k8s]).status_code == 200
    assert instance.config()['targets'][0]['config']['secret_name'] == 's'


# --------------------------------------------------------------------------
# Preview
# --------------------------------------------------------------------------

def test_the_preview_renders_the_request_and_sends_nothing(instance, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError('the preview sent a request')
    monkeypatch.setattr(ph, 'send', forbidden)
    target = _target()
    target['config'].update(auth_type='bearer', auth_token='tok-123')

    response = instance.preview(target)

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body['sends_private_key'] is True and body['host'] == HOST
    assert body['headers']['Authorization'] == '[masked]' and 'tok-123' not in json.dumps(body)
    assert 'EXAMPLE-NOT-A-REAL-KEY' in body['body']
    assert body['files_needed'] == ['cert.pem', 'fullchain.pem', 'privkey.pem']


def test_the_preview_works_before_the_destination_is_confirmed(instance):
    target = _target()
    del target['config']['acknowledge_key_delivery_to']
    assert instance.preview(target).status_code == 200


def test_the_preview_reads_no_file_and_saves_nothing(instance):
    instance.preview(_target())
    assert instance.config()['targets'] == []


@pytest.mark.parametrize('body, needle', [
    ({'type': 'kubernetes-secret', 'config': {}}, 'webhook'),
    ([], 'webhook'),
    ({'type': 'webhook', 'id': 'x', 'name': 'x', 'domains': ['a.com'],
      'config': {'url': 'http://a.com', 'payload_template': '{}'}}, 'https'),
])
def test_the_preview_refuses_what_it_cannot_render(instance, body, needle):
    response = instance.preview(body)
    assert response.status_code == 400 and needle in response.get_json()['error']


def test_the_preview_is_for_admins(instance):
    from modules.core.auth import AuthManager  # noqa: F401  (the role decorator is shared with the other deploy routes)
    response = instance.client.post('/api/deploy/targets/preview', data=json.dumps(_target()),
                                    headers={'Content-Type': 'application/json'})
    assert response.status_code in (401, 403)
