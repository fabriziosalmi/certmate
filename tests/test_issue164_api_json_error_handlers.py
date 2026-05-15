"""
Regression test for issue #164: API endpoints must never serve HTML error
pages. The reporter saw `NETWORK_ERROR` / "Unexpected token '<'" because
Werkzeug's default HTML 404 page reached the browser; the in-app fetch
wrapper then failed to parse the body as JSON and surfaced it as a
client-side network error.

The fix registers two global error handlers (`HTTPException` and
`Exception`) that force JSON for any request whose path starts with
`/api/`, while leaving Flask's default rendering intact for the rest
of the application.
"""
import pytest

from modules.core import factory


pytestmark = [pytest.mark.unit]


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    factory._flask_app = None
    flask_app, _container = factory.create_app(test_config={'TESTING': True})
    return flask_app


def _assert_json_error(resp, expected_status):
    assert resp.status_code == expected_status
    assert resp.content_type.startswith('application/json'), (
        f"expected JSON content-type, got {resp.content_type!r}: {resp.data[:120]!r}"
    )
    body = resp.get_json()
    assert body is not None
    assert 'error' in body
    assert body.get('code') == expected_status


def test_api_404_on_unknown_path_returns_json(app):
    """Path that no route matches (typo) → JSON 404, not HTML."""
    client = app.test_client()
    resp = client.post('/api/certificates/example.com/renw')
    _assert_json_error(resp, 404)


def test_api_404_on_anomalous_trailing_slash_returns_json(app):
    """Trailing slash that isn't registered → JSON 404, not HTML.

    This is the most plausible production trigger for #164: a proxy
    (Kubernetes Ingress, NGINX) or a client redirect normalises the
    path with a trailing slash that the strict Werkzeug routing
    doesn't recognise.
    """
    client = app.test_client()
    resp = client.post('/api/certificates/example.com/renew/')
    _assert_json_error(resp, 404)


def test_non_api_404_keeps_html(app):
    """Non-API paths must keep Flask's default HTML 404 page."""
    client = app.test_client()
    resp = client.get('/some-random-non-api-page-xyz')
    assert resp.status_code == 404
    assert 'text/html' in resp.content_type, (
        f"non-API 404 should remain HTML, got {resp.content_type!r}"
    )


def test_api_405_method_not_allowed_returns_json(app):
    """RESTX already returns JSON for 405; this locks that contract in."""
    client = app.test_client()
    # /api/health is GET-only; POST should yield 405
    resp = client.post('/api/health')
    assert resp.status_code in (404, 405)
    assert resp.content_type.startswith('application/json')
