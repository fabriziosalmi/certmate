"""The rate limits hold when requests run at once, and cover /api/auth/.

The app serves 8 threads in one process. The request limiter's table and the
login buckets were read and rewritten with no lock, so two requests evicting
the same key could raise a KeyError (a 500) and counts could be lost. And every
/api/auth/ path skipped the request limiter on the grounds that login has its
own; only login does, and the OIDC callback calls out to the identity provider.
"""
import threading

import pytest

from tests import contract_support

pytestmark = [pytest.mark.unit]


def _blocked_while_held(lock, call):
    """True when *call* waits for *lock*, and finishes once it is released."""
    done = threading.Event()
    with lock:
        worker = threading.Thread(target=lambda: (call(), done.set()), daemon=True)
        worker.start()
        waited = not done.wait(0.3)
    finished = done.wait(5)
    return waited and finished


def test_the_request_limiter_decides_one_request_at_a_time():
    from modules.core.rate_limit import RateLimitConfig, SimpleRateLimiter
    limiter = SimpleRateLimiter(RateLimitConfig())
    assert _blocked_while_held(limiter._lock, lambda: limiter.is_allowed('ip:10.0.0.1', 'default'))


def test_the_login_buckets_are_read_and_written_one_request_at_a_time():
    from modules.web import routes
    assert _blocked_while_held(routes._login_lock, lambda: routes._check_login_rate_limit('10.0.0.2', 'alice'))
    assert _blocked_while_held(routes._login_lock, lambda: routes._record_login_attempt('10.0.0.2', 'alice'))


def test_auth_paths_other_than_login_count_against_the_request_limit():
    app, token = contract_support.build_app()
    app.extensions['certmate_container'].managers['settings'].update(
        lambda s: s.__setitem__('rate_limits', {'enabled': True, 'limits': {'default': 2}}), 'test')
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}'}
    statuses = [client.get('/api/auth/me', headers=headers).status_code for _ in range(3)]
    # /api/auth/me answers a bearer token 401 (it describes a session); what
    # matters is that the third request meets the limit and the first two do not.
    assert 429 not in statuses[:2] and statuses[2] == 429, statuses
