"""A test starts with an empty login limiter, whatever ran before it.

The limiter (modules.web.routes) allows five attempts from one IP in 60
seconds, and every test client is 127.0.0.1. These two tests run in file order
in one process: the first fills the limiter, the second logs in. Without the
reset in tests/conftest.py the second gets 429, which is what happened at
random under xdist when a test that logs in landed after others that had.
Under xdist the two may run on different workers, where the second passes
either way; run serially, it is the check.
"""
import time

import pytest

from modules.web import routes

pytestmark = [pytest.mark.unit]


def test_a_test_that_fills_the_limiter():
    routes._login_attempts_by_ip['127.0.0.1'] = [time.time()] * routes._LOGIN_RATE_LIMIT_IP
    allowed, _ = routes._check_login_rate_limit('127.0.0.1')
    assert not allowed


def test_the_next_test_can_log_in():
    allowed, _ = routes._check_login_rate_limit('127.0.0.1')
    assert allowed
