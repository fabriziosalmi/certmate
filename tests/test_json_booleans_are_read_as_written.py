"""A boolean field is read as written: "false" is a string, not false.

`bool(value)` is not parsing. Every non-empty string is true in Python, so
``bool("false")`` is True and a caller that sent a boolean as a string got the
opposite of what it asked for, with a 200. It is easy to send one: a shell, an
Ansible or Terraform template, an agent filling a tool schema by hand.

`resources_backup.py` found this once, for `include_secrets`, where the
opposite meant a plaintext dump of every private key instead of the masked
archive that was asked for. Here it is for every boolean the API reads, plus
the gate that keeps `bool(data.get(...))` from coming back.
"""
import ast
import pathlib

import pytest

from modules.core.request_fields import json_bool

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# The helper
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('value', [True, False])
def test_a_json_boolean_is_taken_as_is(value):
    assert json_bool({'f': value}, 'f', default=True) == (value, None)


def test_an_absent_field_falls_back_to_the_default():
    assert json_bool({}, 'f', default=True) == (True, None)
    assert json_bool({}, 'f', default=False) == (False, None)


def test_an_absent_field_without_a_default_is_required():
    value, err = json_bool({}, 'enabled')
    assert value is None
    assert 'required' in err


@pytest.mark.parametrize('value', ['false', 'true', 'no', '0', '', 0, 1, None, [], {}])
def test_anything_that_is_not_a_boolean_is_refused(value):
    parsed, err = json_bool({'f': value}, 'f', default=True)
    assert parsed is None
    assert err.startswith('f must be a JSON boolean')


def test_the_message_names_what_arrived():
    _, err = json_bool({'f': 'false'}, 'f', default=True)
    assert "the string 'false'" in err
    _, err = json_bool({'f': None}, 'f', default=True)
    assert 'null' in err
    _, err = json_bool({'f': 3}, 'f', default=True)
    assert 'int 3' in err


def test_a_body_that_is_not_an_object_uses_the_default():
    assert json_bool(None, 'f', default=False) == (False, None)
    assert json_bool('nope', 'f', default=True) == (True, None)


# --------------------------------------------------------------------------- #
# Every endpoint that reads one
# --------------------------------------------------------------------------- #

@pytest.fixture
def real_app(tmp_path, monkeypatch):
    import secrets
    from modules.core.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    application, container = create_app()
    application.test_headers = {'Authorization': f'Bearer {token}'}
    return application, container


# (method, path, body with the field as a string, the field's name)
STRING_BOOLEANS = [
    ('post', '/api/web/backups/create', {'include_secrets': 'false'}, 'include_secrets'),
    ('post', '/api/auth/config', {'local_auth_enabled': 'false'}, 'local_auth_enabled'),
    ('put', '/api/settings/rate-limits', {'enabled': 'false'}, 'enabled'),
    ('post', '/api/keys', {'name': 'k', 'role': 'viewer', 'is_agent': 'false'}, 'is_agent'),
    ('post', '/api/certificates/check-dns-alias',
     {'domain': 'a.example.com', 'domain_alias': 'b.example.org', 'wildcard': 'true'}, 'wildcard'),
    ('post', '/api/certificates/a.example.com/renew', {'force': 'false'}, 'force'),
    ('put', '/api/certificates/a.example.com/auto-renew', {'enabled': 'false'}, 'enabled'),
]


@pytest.mark.parametrize('method, path, body, field',
                         STRING_BOOLEANS, ids=[f'{m}{p}' for m, p, _b, _f in STRING_BOOLEANS])
def test_a_string_is_refused_wherever_a_boolean_is_read(real_app, method, path, body, field):
    application, _ = real_app
    client = application.test_client()
    response = getattr(client, method)(path, headers=application.test_headers, json=body)
    assert response.status_code == 400, (path, response.get_json())
    payload = response.get_json()
    assert payload['code'] == 'INVALID_REQUEST'
    assert payload['error'].startswith(f'{field} must be a JSON boolean')


def test_the_masked_backup_is_not_a_plaintext_one(real_app):
    """The instance of this that mattered: "false" asked for a share-safe
    archive and produced one carrying every private key."""
    application, container = real_app
    client = application.test_client()
    refused = client.post('/api/web/backups/create', headers=application.test_headers,
                          json={'include_secrets': 'false'})
    assert refused.status_code == 400
    honest = client.post('/api/web/backups/create', headers=application.test_headers,
                         json={'include_secrets': False})
    assert honest.status_code == 200, honest.get_json()
    assert honest.get_json()['secrets_masked'] is True


def test_a_real_boolean_still_works(real_app):
    application, _ = real_app
    client = application.test_client()
    ok = client.post('/api/keys', headers=application.test_headers,
                     json={'name': 'agent', 'role': 'viewer', 'is_agent': True})
    assert ok.status_code in (200, 201), ok.get_json()
    listed = client.get('/api/keys', headers=application.test_headers).get_json()['keys']
    assert [k['is_agent'] for k in listed.values()] == [True]


def test_an_absent_boolean_keeps_its_documented_default(real_app):
    application, _ = real_app
    client = application.test_client()
    created = client.post('/api/keys', headers=application.test_headers,
                          json={'name': 'plain', 'role': 'viewer'})
    assert created.status_code in (200, 201)
    listed = client.get('/api/keys', headers=application.test_headers).get_json()['keys']
    assert [k['is_agent'] for k in listed.values()] == [False]


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #

WATCHED = ('modules/api', 'modules/web')


# What a request body is called in this codebase. `bool(result.get(...))` on a
# manager's own dict is fine: the value was produced here, not sent by a
# caller. This is about values that arrived over HTTP.
REQUEST_BODIES = {'data', 'payload', 'body', 'json_body', 'req_body'}


def _is_request_body(node):
    """True for `data`, `api.payload`, `request.json`, `request.get_json(...)`
    and `(request.get_json(...) or {})`."""
    if isinstance(node, ast.BoolOp):      # (request.get_json() or {})
        return any(_is_request_body(v) for v in node.values)
    if isinstance(node, ast.Name):
        return node.id in REQUEST_BODIES
    if isinstance(node, ast.Attribute):   # api.payload, request.json
        return node.attr in {'payload', 'json'}
    if isinstance(node, ast.Call):        # request.get_json(...)
        return (isinstance(node.func, ast.Attribute)
                and node.func.attr in {'get_json'})
    return False


def _coerced_request_booleans(tree):
    """Lines where a field of a request body is read through ``bool()``."""
    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == 'bool' and len(node.args) == 1):
            continue
        arg = node.args[0]
        if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                and arg.func.attr == 'get' and _is_request_body(arg.func.value)):
            found.append(node.lineno)
    return found


def test_no_request_boolean_is_coerced_with_bool():
    """`bool(data.get('x'))` reads "false" as true. Use
    `modules.core.request_fields.json_bool`, which refuses what it cannot read.
    """
    offenders = []
    for directory in WATCHED:
        for path in sorted((REPO / directory).rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            offenders += [f'{path.relative_to(REPO)}:{line}'
                          for line in _coerced_request_booleans(tree)]
    assert offenders == [], (
        'these read a request field through bool(), which turns the string '
        '"false" into True: ' + ', '.join(offenders))


@pytest.mark.parametrize('source', [
    "value = bool(data.get('enabled', False))",
    "value = bool(payload.get('force'))",
    "value = bool(api.payload.get('x'))",
    "value = bool((request.get_json(silent=True) or {}).get('force', False))",
    "value = bool(request.json.get('x'))",
])
def test_the_gate_can_see_one(source):
    """The check above proves nothing if it cannot find the pattern."""
    assert _coerced_request_booleans(ast.parse(source + '\n')) == [1]


@pytest.mark.parametrize('source', [
    "renewed = bool(result.get('renewed', True))",     # a manager's own answer
    "has_users = bool(settings.get('users'))",         # what is on disk
    "reachable = bool(backend.get('reachable'))",      # a probe's own result
])
def test_the_gate_leaves_internal_values_alone(source):
    """bool() on a value this process produced is not the defect: nobody could
    have sent it as a string."""
    assert _coerced_request_booleans(ast.parse(source + '\n')) == []


def test_the_sdk_sends_a_boolean_or_says_which_argument_is_wrong():
    """Read from the source, not by importing it: the SDK is only installed in
    the jobs that exercise the clients, and `pytest.importorskip` here would
    turn this into a check that quietly does not run.

    `bool(force)` on the client repeats the server's old trap one layer out:
    `force="false"` would be sent as true.
    """
    source = (REPO / 'clients' / 'certmate-sdk' / 'certmate' / 'client.py').read_text(encoding='utf-8')
    assert 'def _require_bool' in source
    for call in ('self._require_bool("force", force)', 'self._require_bool("enabled", enabled)'):
        assert call in source, call
    assert 'bool(force)' not in source
    assert 'bool(enabled)' not in source


def test_the_mcp_server_refuses_a_non_boolean():
    source = (REPO / 'mcp' / 'index.js').read_text(encoding='utf-8')
    assert 'function requireBoolean' in source
    assert 'requireBoolean("enabled", args.enabled)' in source
