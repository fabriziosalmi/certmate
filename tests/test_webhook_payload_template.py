"""Generic webhooks: payload templates, method, authentication, timeout and
retries (#218), and the masking of credential-bearing custom headers.

The template rules are the part that can hurt: a value with quotes or a
newline must not break out of a JSON string, and a placeholder used as a bare
value must stay a JSON literal. Everything else is plumbing — captured at the
urllib Request so a wrong method/header is a failing test, not a silent 401.
"""
import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from modules.core.notifier import (
    Notifier, render_payload_template, validate_webhook_config,
    webhook_template_variables,
)
from modules.core.settings import (
    SECRET_MASK_SENTINEL as MASK, mask_secrets_in_settings,
    _restore_masked_list_secrets,
)

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _vars(**details):
    base = {'domain': 'shop.example.com', 'days_until_expiry': 12}
    base.update(details)
    return webhook_template_variables('certificate_expiring', 'Certificate Expiring',
                                      'Certificate Expiring: shop.example.com', base)


def test_placeholder_inside_a_string_is_escaped_not_injected():
    evil = 'x", "admin": true, "y": "'
    out = render_payload_template('{"text": "Domain {{domain}} said {{details.error}}"}',
                                  _vars(error=evil))
    parsed = json.loads(out)
    assert parsed == {'text': f'Domain shop.example.com said {evil}'}
    assert 'admin' not in parsed  # the quote did not close the string


def test_newlines_and_backslashes_survive_inside_a_string():
    out = render_payload_template('{"m": "{{details.error}}"}',
                                  _vars(error='line1\nline2 \\ "q"'))
    assert json.loads(out)['m'] == 'line1\nline2 \\ "q"'


def test_bare_placeholder_becomes_a_json_literal():
    out = render_payload_template(
        '{"days": {{details.days_until_expiry}}, "name": {{domain}}, "all": {{details}}}',
        _vars())
    parsed = json.loads(out)
    assert parsed['days'] == 12
    assert parsed['name'] == 'shop.example.com'
    assert parsed['all']['domain'] == 'shop.example.com'


def test_unknown_placeholder_is_null_outside_and_empty_inside():
    out = render_payload_template('{"a": {{details.nope}}, "b": "x{{details.nope}}y"}', _vars())
    assert json.loads(out) == {'a': None, 'b': 'xy'}


def test_object_inside_a_string_is_embedded_as_escaped_json_text():
    out = render_payload_template('{"blob": "payload={{details}}"}', _vars())
    blob = json.loads(out)['blob']
    assert blob.startswith('payload={') and json.loads(blob[len('payload='):])['days_until_expiry'] == 12


def test_template_that_does_not_render_to_json_is_an_error():
    with pytest.raises(ValueError) as err:
        render_payload_template('{"a": {{event}', _vars())
    assert 'valid JSON' in str(err.value)


def test_whitespace_inside_braces_is_tolerated():
    assert json.loads(render_payload_template('{"e": "{{ event }}"}', _vars()))['e'] == 'certificate_expiring'


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('cfg, fragment', [
    ({'type': 'generic', 'method': 'DELETE'}, 'method'),
    ({'type': 'generic', 'auth_type': 'oauth'}, 'auth_type'),
    ({'type': 'generic', 'auth_type': 'bearer'}, 'auth_token'),
    ({'type': 'generic', 'auth_type': 'basic', 'auth_username': 'u'}, 'auth_password'),
    ({'type': 'generic', 'auth_type': 'header', 'auth_token': 't', 'auth_header': 'bad header'}, 'auth_header'),
    ({'type': 'generic', 'timeout': 0}, 'timeout'),
    ({'type': 'generic', 'timeout': 'soon'}, 'timeout'),
    ({'type': 'generic', 'max_retries': 9}, 'max_retries'),
    ({'type': 'generic', 'payload_template': '{"x": {{event}'}, 'valid JSON'),
])
def test_validate_rejects(cfg, fragment):
    err = validate_webhook_config(cfg)
    assert err and fragment in err


def test_validate_accepts_a_full_generic_config_and_ignores_other_types():
    assert validate_webhook_config({
        'type': 'generic', 'method': 'put', 'auth_type': 'bearer', 'auth_token': 't',
        'timeout': '30', 'max_retries': 0,
        'payload_template': '{"text": "{{title}} {{domain}}"}',
    }) is None
    # A Slack webhook with a nonsense method is not judged here: the field
    # does not apply to it.
    assert validate_webhook_config({'type': 'slack', 'method': 'DELETE'}) is None


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #

class _Resp:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _send(cfg, event='certificate_renewed', details=None):
    n = Notifier(settings_manager=MagicMock(), data_dir='/nonexistent')
    cap = {}

    def fake_urlopen(req, timeout=None):
        cap['url'] = req.full_url
        cap['method'] = req.get_method()
        cap['data'] = req.data
        cap['timeout'] = timeout
        cap['headers'] = {k.lower(): v for k, v in req.header_items()}
        return _Resp()

    with patch('modules.core.notifier.urlopen', side_effect=fake_urlopen), \
            patch('modules.core.notifier._webhook_url_is_internal', return_value=False):
        res = n._send_webhook(cfg, event, 'Certificate Renewed',
                              'Certificate Renewed: a.example', details or {'domain': 'a.example'})
    return res, cap


def test_template_body_method_timeout_and_bearer_reach_the_wire():
    res, cap = _send({
        'type': 'generic', 'url': 'https://hooks.example/in', 'method': 'put',
        'auth_type': 'bearer', 'auth_token': 'sekrit', 'timeout': 25,
        'payload_template': '{"text": "{{title}} for {{domain}}", "event": "{{event}}"}',
    })
    assert res == {'success': True, 'status': 202}
    assert cap['method'] == 'PUT'
    assert cap['timeout'] == 25
    assert cap['headers']['authorization'] == 'Bearer sekrit'
    assert json.loads(cap['data']) == {'text': 'Certificate Renewed for a.example',
                                       'event': 'certificate_renewed'}


def test_basic_auth_and_custom_header_auth():
    _, cap = _send({'type': 'generic', 'url': 'https://h.example', 'auth_type': 'basic',
                    'auth_username': 'bob', 'auth_password': 'pw:1'})
    assert cap['headers']['authorization'] == 'Basic ' + base64.b64encode(b'bob:pw:1').decode()

    _, cap = _send({'type': 'generic', 'url': 'https://h.example', 'auth_type': 'header',
                    'auth_header': 'X-Service-Key', 'auth_token': 'k1'})
    assert cap['headers']['x-service-key'] == 'k1'


def test_signature_covers_the_templated_body():
    import hashlib
    import hmac as _hmac
    _, cap = _send({'type': 'generic', 'url': 'https://h.example', 'secret': 's3',
                    'payload_template': '{"d": "{{domain}}"}'})
    sig = cap['headers']['x-certmate-signature']
    ts = sig.split(',')[0].split('=')[1]
    expected = _hmac.new(b's3', f'{ts}.'.encode() + cap['data'], hashlib.sha256).hexdigest()
    assert sig.endswith(f'v1={expected}')


def test_without_the_new_fields_the_wire_shape_is_unchanged():
    res, cap = _send({'type': 'generic', 'url': 'https://h.example', 'headers': {'X-Env': 'prod'}})
    assert res['success'] and cap['method'] == 'POST' and cap['timeout'] == 10
    body = json.loads(cap['data'])
    assert set(body) == {'event', 'title', 'message', 'details', 'timestamp'}
    assert cap['headers']['x-env'] == 'prod'


def test_broken_template_is_a_config_error_not_a_send():
    res, cap = _send({'type': 'generic', 'url': 'https://h.example',
                      'payload_template': '{"a": {{event}'})
    assert res.get('config_error') and 'valid JSON' in res['error']
    assert cap == {}  # never reached the network


def test_retry_count_comes_from_the_config():
    n = Notifier(settings_manager=MagicMock(), data_dir='/nonexistent')
    calls = []
    with patch.object(n, '_send_webhook', side_effect=lambda *a, **k: calls.append(1) or {'error': 'x'}), \
            patch.object(n, '_log_delivery'), patch('modules.core.notifier.time.sleep'):
        n._send_webhook_with_retry({'type': 'generic', 'url': 'https://h', 'max_retries': 1},
                                   'e', 't', 'm')
        assert len(calls) == 1
        calls.clear()
        n._send_webhook_with_retry({'type': 'generic', 'url': 'https://h'}, 'e', 't', 'm')
        assert len(calls) == 3  # the historical default


# --------------------------------------------------------------------------- #
# Masking: credentials in custom headers and the new auth fields
# --------------------------------------------------------------------------- #

def test_auth_fields_and_authorization_header_are_masked_on_read():
    masked = mask_secrets_in_settings({'notifications': {'channels': {'webhooks': [{
        'type': 'generic', 'url': 'https://h', 'auth_type': 'bearer', 'auth_token': 'T',
        'auth_username': 'u', 'auth_password': 'P',
        'headers': {'Authorization': 'Bearer X', 'X-Api-Key': 'K', 'X-Env': 'prod'},
    }]}}})
    wh = masked['notifications']['channels']['webhooks'][0]
    assert wh['auth_token'] == MASK and wh['auth_password'] == MASK
    assert wh['auth_username'] == 'u'
    assert wh['headers']['Authorization'] == MASK and wh['headers']['X-Api-Key'] == MASK
    assert wh['headers']['X-Env'] == 'prod'


def test_masked_header_values_are_restored_on_round_trip():
    old = [{'name': 'w', 'type': 'generic', 'url': 'https://h', 'auth_token': 'T',
            'headers': {'Authorization': 'Bearer X', 'X-Env': 'prod'}}]
    new = [{'name': 'w', 'type': 'generic', 'url': 'https://h', 'auth_token': MASK,
            'headers': {'Authorization': MASK, 'X-Env': 'staging'}}]
    _restore_masked_list_secrets(old, new)
    assert new[0]['auth_token'] == 'T'
    assert new[0]['headers'] == {'Authorization': 'Bearer X', 'X-Env': 'staging'}


# --------------------------------------------------------------------------- #
# Routes: save-time validation and preview
# --------------------------------------------------------------------------- #

def _app(notifier):
    from modules.web.misc_routes import register_misc_routes
    app = Flask(__name__)
    app.secret_key = 't'
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=lambda *a, **k: (lambda f: f))
    settings_manager = MagicMock()
    managers = {'notifier': notifier, 'settings': settings_manager, 'audit': None}
    register_misc_routes(app, managers, lambda f: f, auth_manager)
    return app, settings_manager


def test_saving_a_webhook_with_a_broken_template_is_a_400():
    notifier = Notifier(settings_manager=MagicMock(), data_dir='/nonexistent')
    app, settings_manager = _app(notifier)
    r = app.test_client().post('/api/notifications/config', json={
        'enabled': True,
        'channels': {'webhooks': [{'name': 'ops', 'type': 'generic', 'url': 'https://h',
                                   'payload_template': '{"a": {{event}'}]}})
    assert r.status_code == 400
    assert 'webhook ops' in r.get_json()['error']
    settings_manager.update.assert_not_called()


def test_preview_renders_without_sending_and_masks_credentials():
    notifier = Notifier(settings_manager=MagicMock(), data_dir='/nonexistent')
    app, _ = _app(notifier)
    with patch('modules.core.notifier.urlopen') as sent:
        r = app.test_client().post('/api/notifications/webhook/preview', json={'config': {
            'type': 'generic', 'url': 'https://h.example', 'method': 'PUT',
            'auth_type': 'bearer', 'auth_token': 'sekrit',
            'payload_template': '{"text": "{{title}}: {{domain}} in {{details.days_until_expiry}} days"}',
        }})
    assert not sent.called
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['method'] == 'PUT'
    assert body['headers']['Authorization'] == '********'
    assert json.loads(body['body'])['text'] == 'Certificate Renewed: example.com in 29 days'
    assert any(v['name'] == 'details.<field>' for v in body['variables'])


def test_preview_of_a_broken_config_is_a_400_with_the_reason():
    notifier = Notifier(settings_manager=MagicMock(), data_dir='/nonexistent')
    app, _ = _app(notifier)
    r = app.test_client().post('/api/notifications/webhook/preview',
                               json={'config': {'type': 'generic', 'auth_type': 'bearer'}})
    assert r.status_code == 400 and 'auth_token' in r.get_json()['error']
