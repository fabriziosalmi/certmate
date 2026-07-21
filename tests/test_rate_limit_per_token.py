"""The /api/* rate-limit before_request buckets per API key, under a per-IP ceiling.

Before, every authenticated request from one NAT/proxy IP shared a single
bucket (false positives) and an abusive key wasn't throttled independently. The
before_request derives the working bucket from a hash of the bearer token when
present, falling back to the client IP for cookie/session and anonymous calls.

Since #420 every request is ALSO checked against a coarse per-IP ceiling,
first: bucketing solely on a caller-supplied token meant a fresh bucket per
request, so varying the Authorization header bypassed the limiter entirely.
Each request therefore produces two is_allowed() calls: ('ip:...',
'ip_ceiling') then the working bucket.
"""
import types
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.factory import setup_rate_limiting

pytestmark = [pytest.mark.unit]


def _app_with_spy():
    app = Flask(__name__)

    @app.route('/api/certificates')
    def _certs():
        return 'ok'

    spy = MagicMock()
    spy.is_allowed.return_value = True  # never block; we only inspect the bucket key
    container = types.SimpleNamespace(managers={'rate_limiter': spy})
    setup_rate_limiting(app, container)
    return app, spy


def _bucket_ids(spy):
    """Working buckets only — the ip_ceiling probe is asserted separately."""
    return [call.args[0] for call in spy.is_allowed.call_args_list
            if call.args[1] != 'ip_ceiling']


def _all_calls(spy):
    return [(call.args[0], call.args[1]) for call in spy.is_allowed.call_args_list]


def test_distinct_bearer_tokens_get_distinct_buckets():
    app, spy = _app_with_spy()
    client = app.test_client()
    client.get('/api/certificates', headers={'Authorization': 'Bearer token-AAA'})
    client.get('/api/certificates', headers={'Authorization': 'Bearer token-BBB'})

    ids = _bucket_ids(spy)
    assert all(i.startswith('key:') for i in ids), ids
    assert ids[0] != ids[1]  # two keys behind the same IP are throttled separately


def test_same_token_reuses_one_bucket():
    app, spy = _app_with_spy()
    client = app.test_client()
    client.get('/api/certificates', headers={'Authorization': 'Bearer token-AAA'})
    client.get('/api/certificates', headers={'Authorization': 'Bearer token-AAA'})

    ids = _bucket_ids(spy)
    assert ids[0] == ids[1] and ids[0].startswith('key:')


def test_no_token_falls_back_to_ip_bucket():
    app, spy = _app_with_spy()
    app.test_client().get('/api/certificates')
    ids = _bucket_ids(spy)
    assert ids and ids[0].startswith('ip:')


def test_every_request_is_checked_against_the_ip_ceiling_first(  # noqa: D103
):
    """#420: the ceiling is what makes the per-key bucket un-bypassable, and it
    must be evaluated BEFORE the key bucket so a rejected caller never
    allocates one."""
    app, spy = _app_with_spy()
    app.test_client().get('/api/certificates',
                          headers={'Authorization': 'Bearer token-AAA'})

    calls = _all_calls(spy)
    assert calls[0][1] == 'ip_ceiling'
    assert calls[0][0].startswith('ip:')
    assert calls[1][1] == 'certificate_list'
    assert calls[1][0].startswith('key:')


def test_a_caller_over_the_ip_ceiling_never_reaches_the_key_bucket():
    app, spy = _app_with_spy()
    spy.is_allowed.side_effect = lambda ident, endpoint: endpoint != 'ip_ceiling'

    resp = app.test_client().get('/api/certificates',
                                 headers={'Authorization': 'Bearer token-AAA'})

    assert resp.status_code == 429
    assert _all_calls(spy) == [(_all_calls(spy)[0][0], 'ip_ceiling')]


def test_token_is_not_used_in_cleartext():
    app, spy = _app_with_spy()
    app.test_client().get('/api/certificates', headers={'Authorization': 'Bearer super-secret-token'})
    ids = _bucket_ids(spy)
    assert 'super-secret-token' not in ids[0]  # hashed, never the raw token


def test_auth_endpoints_are_skipped():
    app, spy = _app_with_spy()

    @app.route('/api/auth/login')
    def _login():
        return 'ok'

    app.test_client().get('/api/auth/login', headers={'Authorization': 'Bearer x'})
    # /api/auth/* has its own login limiter; the generic one must not fire.
    spy.is_allowed.assert_not_called()
