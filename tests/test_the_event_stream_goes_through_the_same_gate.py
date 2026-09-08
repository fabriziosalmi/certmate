"""The event stream's access rule belongs with the other access rules.

`/api/events/stream` decided who could read it with an inline
`if not auth_manager.is_setup_mode(): ...check the cookie...`. The *behaviour*
was right — `EventSource` offers no way to add an Authorization header, so a
bearer token cannot reach this route however the caller is configured, and only
the cookie session can serve.

Three things were wrong with expressing that in the route rather than as a
decorator:

* **The route was invisible.** Nothing enumerating protection could see it, so
  it sat in the public allowlist (#761) with "checked inline" as its reason —
  a protected route recorded as an exception.
* **The check had drifted.** It never consulted a role, so a `viewer`-only
  session and an `admin` one were the same to it, while every other route in
  the system distinguishes them.
* **A second such surface would have copied it.** SSE is the whole set today;
  it is not obviously the whole set forever.

`require_session_role('viewer')` is that rule expressed once. Setup mode is
honoured exactly as the other decorators honour it: with no operator credential
configured at all, every caller is admin, and the live stream is no different
from the dashboard it feeds.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.auth import AuthManager

pytestmark = [pytest.mark.unit]


def _auth(*, setup_mode, session_user=None):
    auth = AuthManager.__new__(AuthManager)
    auth.settings_manager = MagicMock()
    auth.is_setup_mode = lambda: setup_mode
    auth.validate_session = lambda sid: session_user if sid else None
    auth._log_rbac_denial = MagicMock()
    return auth


def _app(auth, min_role='viewer'):
    app = Flask(__name__)

    @app.route('/stream')
    @auth.require_session_role(min_role)
    def stream():
        from flask import request
        return {'ok': True, 'user': request.current_user.get('username')}

    return app


# --- the cookie is the only credential -----------------------------------

def test_a_valid_session_is_let_through():
    auth = _auth(setup_mode=False,
                 session_user={'username': 'ada', 'role': 'operator'})
    client = _app(auth).test_client()
    client.set_cookie('certmate_session', 'abc')

    response = client.get('/stream')
    assert response.status_code == 200
    assert response.get_json()['user'] == 'ada'


def test_no_cookie_is_a_401_not_a_redirect():
    """An EventSource cannot follow a redirect usefully — a 302 to the login
    page arrives as an opaque stream error. 401 lets the client decide to
    reconnect after logging in."""
    auth = _auth(setup_mode=False)
    response = _app(auth).test_client().get('/stream')

    assert response.status_code == 401
    assert response.get_json()['code'] == 'SESSION_REQUIRED'


def test_an_invalid_session_is_refused():
    auth = _auth(setup_mode=False, session_user=None)
    client = _app(auth).test_client()
    client.set_cookie('certmate_session', 'stale')
    assert client.get('/stream').status_code == 401


def test_a_bearer_token_does_not_open_it():
    """CONTROL, and the reason this decorator exists rather than require_role:
    a browser cannot send this header on an EventSource, so accepting it here
    would be a credential path only a non-browser could use — on a surface
    that exists for the browser."""
    auth = _auth(setup_mode=False)
    auth.authenticate_api_token = MagicMock(
        return_value={'username': 'api', 'role': 'admin'})

    response = _app(auth).test_client().get(
        '/stream', headers={'Authorization': 'Bearer whatever'})
    assert response.status_code == 401


# --- roles, which the inline check never looked at ----------------------

def test_a_role_below_the_requirement_is_refused():
    auth = _auth(setup_mode=False,
                 session_user={'username': 'bob', 'role': 'viewer'})
    client = _app(auth, min_role='admin').test_client()
    client.set_cookie('certmate_session', 'abc')

    response = client.get('/stream')
    assert response.status_code == 403
    assert response.get_json()['code'] == 'INSUFFICIENT_ROLE'


def test_a_role_denial_is_audited():
    """The same treatment require_role gives it: privilege enumeration must
    leave a trace rather than vanishing behind a silent 403."""
    auth = _auth(setup_mode=False,
                 session_user={'username': 'bob', 'role': 'viewer'})
    client = _app(auth, min_role='admin').test_client()
    client.set_cookie('certmate_session', 'abc')
    client.get('/stream')

    assert auth._log_rbac_denial.called


def test_a_higher_role_satisfies_a_lower_requirement():
    auth = _auth(setup_mode=False,
                 session_user={'username': 'root', 'role': 'admin'})
    client = _app(auth, min_role='viewer').test_client()
    client.set_cookie('certmate_session', 'abc')
    assert client.get('/stream').status_code == 200


# --- setup mode ----------------------------------------------------------

def test_setup_mode_lets_everyone_in_as_it_does_everywhere_else():
    """With no operator credential configured at all, every caller is admin.
    The live stream must not be stricter than the dashboard it feeds — that
    would break the onboarding it exists to show."""
    auth = _auth(setup_mode=True)
    response = _app(auth).test_client().get('/stream')

    assert response.status_code == 200
    assert response.get_json()['user'] == 'setup_user'


# --- the census sees it now ---------------------------------------------

def test_the_decorator_marks_what_it_protects():
    auth = _auth(setup_mode=False)

    def view():
        pass

    factory = auth.require_session_role('viewer')
    assert factory._certmate_protection == 'require_session_role:viewer'
    assert factory(view)._certmate_protection == 'require_session_role:viewer'


def test_the_stream_is_no_longer_listed_as_a_public_route():
    """The point of the change: a protected route was recorded as an
    exception, which is the one thing an allowlist must not contain."""
    import tests.test_every_route_is_protected_or_listed as census
    assert '/api/events/stream' not in census.PUBLIC_ROUTES


def test_the_route_actually_carries_the_decorator():
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
              / 'web' / 'misc_routes.py').read_text()
    stream = source.split("@app.route('/api/events/stream')")[1][:200]
    assert "require_session_role('viewer')" in stream, (
        'the event stream went back to deciding access inline'
    )
