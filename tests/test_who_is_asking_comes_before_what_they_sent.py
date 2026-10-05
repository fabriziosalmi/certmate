"""A request is refused for who sent it before it is answered about its body.

flask-restx validates a request's body against the route's model before it
calls the method, and the role check is a decorator on the method. A request
with no credentials, or with too low a role, was therefore answered about its
body ("'domain' is a required property") by a route that would have refused it
either way. `setup_authorization_before_validation` runs the decorator's own
check first, for every method that has both a model and a role.

The routes are found here the way the application finds them, so one added
later with a model and a role is tried without being listed.
"""
import os
import re
import secrets

import pytest

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('auth-first')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import _role_required_before_validation, create_app
        app, container = create_app()
        headers = {'admin': {'Authorization': f'Bearer {token}'}}
        for role in ('viewer', 'operator'):
            ok, key = container.managers['auth'].create_api_key(f'plain-{role}', role=role)
            assert ok, key
            headers[role] = {'Authorization': f"Bearer {key['token']}"}
        routes = []
        for rule in app.url_map.iter_rules():
            view_class = getattr(app.view_functions.get(rule.endpoint), 'view_class', None)
            if view_class is None:
                continue
            for verb in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
                role = _role_required_before_validation(view_class, verb)
                if role:
                    routes.append((verb, re.sub(r'<[^>]+>', 'x', str(rule)), role))
        yield app.test_client(), headers, sorted(set(routes)), container


@pytest.fixture(autouse=True)
def _a_minute_of_its_own(instance):
    limiter = instance[3].managers.get('rate_limiter')
    if limiter is not None:
        limiter.requests.clear()


def test_there_are_routes_with_a_model_and_a_role(instance):
    """CONTROL: the tests below are about something. These seven answered 400
    to a request with no credentials before this."""
    routes = {(verb, path) for verb, path, _role in instance[2]}
    assert {('POST', '/api/certificates/create'), ('POST', '/api/backups/create'),
            ('POST', '/api/backups/restore/x'), ('POST', '/api/storage/test'),
            ('POST', '/api/storage/migrate'), ('POST', '/api/settings/test-ca-provider'),
            ('POST', '/api/certificates/deployment-status/browser')} <= routes, sorted(routes)


def test_no_credentials_is_401_whatever_the_body(instance):
    client, _headers, routes, _container = instance
    for verb, path, _role in routes:
        for kwargs in ({'json': {}}, {'data': '{not json', 'content_type': 'application/json'},
                       {'json': {'unexpected': ['a'] * 5}}):
            response = client.open(path, method=verb, **kwargs)
            assert response.status_code == 401, (verb, path, kwargs, response.status_code,
                                                 response.get_data(as_text=True)[:160])
            assert 'required property' not in response.get_data(as_text=True)


def test_too_low_a_role_is_403_whatever_the_body(instance):
    client, headers, routes, _container = instance
    below = {'admin': ['viewer', 'operator'], 'operator': ['viewer'], 'viewer': []}
    tried = 0
    for verb, path, role in routes:
        for who in below[role]:
            response = client.open(path, method=verb, headers=headers[who], json={})
            assert response.status_code == 403, (verb, path, who, response.status_code)
            assert response.get_json()['code'] == 'INSUFFICIENT_ROLE'
            tried += 1
    assert tried >= 8, tried


def test_with_the_role_the_body_is_still_validated(instance):
    """CONTROL: the validation was moved behind the check, not removed."""
    client, headers, routes, _container = instance
    answered_about_the_body = 0
    for verb, path, _role in routes:
        response = client.open(path, method=verb, headers=headers['admin'], json={})
        assert response.status_code not in (401, 403), (verb, path, response.status_code)
        if response.status_code == 400 and 'required property' in response.get_data(as_text=True):
            answered_about_the_body += 1
    assert answered_about_the_body >= 7, answered_about_the_body


def test_a_refusal_is_recorded_once(instance):
    """The check runs before the validation and again in the decorator. A
    request it refuses never reaches the second, so the audit has one entry."""
    client, headers, _routes, container = instance
    audit = container.managers['audit']
    before = len([e for e in audit.get_recent_entries(limit=200) if e.get('status') == 'denied'])
    response = client.post('/api/storage/test', headers=headers['viewer'], json={})
    assert response.status_code == 403
    after = len([e for e in audit.get_recent_entries(limit=200) if e.get('status') == 'denied'])
    assert after - before == 1


def test_a_valid_request_with_the_role_goes_through(instance):
    client, headers, _routes, _container = instance
    response = client.post('/api/storage/test', headers=headers['admin'],
                           json={'backend': 'local_filesystem', 'config': {}})
    assert response.status_code == 200, response.get_data(as_text=True)[:200]


def _guard(role):
    def decorator(fn):
        return fn
    decorator._certmate_protection = f'require_role:{role}'
    return decorator


def test_the_role_is_read_from_either_place_it_is_declared():
    from modules.factory import _role_required_before_validation as role_of

    def with_model(fn):
        fn.__apidoc__ = {'expect': [object()]}
        return fn

    class OnTheMethod:
        @with_model
        def post(self):
            pass
    OnTheMethod.post._certmate_protection = 'require_role:admin'

    class OnTheClass:
        method_decorators = (_guard('operator'),)

        @with_model
        def post(self):
            pass

    class NoModel:
        method_decorators = (_guard('admin'),)

        def post(self):
            pass

    class NoRole:
        @with_model
        def post(self):
            pass

    assert role_of(OnTheMethod, 'POST') == 'admin'
    assert role_of(OnTheClass, 'POST') == 'operator'
    assert role_of(NoModel, 'POST') is None      # nothing is validated ahead of its own check
    assert role_of(NoRole, 'POST') is None       # public, with a model: validated as before
    assert role_of(OnTheClass, 'DELETE') is None
