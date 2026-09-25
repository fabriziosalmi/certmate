"""Three from the #591 re-triage that shared a shape: nothing looked wrong.

**A login told you whether a username exists.** Both early returns in
`authenticate_user` — unknown user, disabled user — answered in microseconds
while a real username paid for bcrypt. Measured on this project's own bench
before the fix:

    esistente, password sbagliata :  180.47 ms
    inesistente                   :    0.29 ms
    rapporto                      :     628x

One request was enough to learn whether a username exists, and a second to
learn whether it is disabled. The rate limiter bounds how fast that can be
asked, not whether the answer is there.

**The session cookie shipped without `Secure` on the compose default.**
`secure=request.is_secure` is a per-request fact, and behind a
TLS-terminating proxy it is False unless `BEHIND_PROXY` wires ProxyFix. So an
operator who declared HTTPS still got a session cookie without `Secure` while
their users were on HTTPS. `factory.py` already computes exactly that
decision for Flask's own cookie, with the reasoning beside it; the hand-rolled
one ignored it.

**A busy domain was reported as a renewal failure.**
`DomainOperationInProgress` landed in the sweep's generic handler, so a
domain whose lock was held by a manual renewal drove a failure metric, an
audit failure entry and a `certificate_failed` notification — paging someone
for a queue. Every request-facing caller already answers 409 for it.
"""
import logging
import statistics
import time

import pytest

pytestmark = [pytest.mark.unit]


# --- the login oracle -----------------------------------------------------

@pytest.fixture
def auth(tmp_path):
    from modules.core.auth import AuthManager
    from modules.core.file_operations import FileOperations
    from modules.core.settings import SettingsManager

    dirs = [tmp_path / n for n in
            ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    settings = SettingsManager(file_ops=FileOperations(*dirs),
                               settings_file=dirs[1] / 'settings.json')
    settings.load_settings()
    manager = AuthManager(settings)
    manager.set_hmac_key('k' * 32)
    manager.create_user('alice', 'correct-horse-battery', role='admin')
    manager.create_user('bob', 'another-password-entirely', role='viewer')
    manager.update_user('bob', enabled=False)
    return manager


def _median_ms(manager, username, password, rounds=9):
    manager.authenticate_user(username, password)      # warm up
    samples = []
    for _ in range(rounds):
        started = time.perf_counter()
        manager.authenticate_user(username, password)
        samples.append((time.perf_counter() - started) * 1000)
    return statistics.median(samples)


def test_an_unknown_username_costs_what_a_known_one_costs(auth, caplog):
    """THE regression. The ratio was about 600 with no overlap between the
    distributions; a factor of two here would still be a usable oracle."""
    caplog.set_level(logging.CRITICAL)

    known = _median_ms(auth, 'alice', 'wrong-password')
    unknown = _median_ms(auth, 'nosuchuser', 'wrong-password')

    ratio = max(known, unknown) / max(min(known, unknown), 0.001)
    assert ratio < 2.0, (
        f'known {known:.1f}ms vs unknown {unknown:.1f}ms — ratio {ratio:.0f}x')


def test_a_disabled_user_costs_the_same_too(auth, caplog):
    """The second question the oracle answered. `bob` exists and is
    disabled, so the branch returns before verifying."""
    caplog.set_level(logging.CRITICAL)

    known = _median_ms(auth, 'alice', 'wrong-password')
    disabled = _median_ms(auth, 'bob', 'wrong-password')

    ratio = max(known, disabled) / max(min(known, disabled), 0.001)
    assert ratio < 2.0, (
        f'known {known:.1f}ms vs disabled {disabled:.1f}ms — {ratio:.0f}x')


def test_the_answers_themselves_did_not_change(auth, caplog):
    """CONTROL. Paying the cost must not start letting anyone in, and must
    not start refusing the one account that should work."""
    caplog.set_level(logging.CRITICAL)

    assert auth.authenticate_user('nosuchuser', 'anything') is None
    assert auth.authenticate_user('bob', 'another-password-entirely') is None
    assert auth.authenticate_user('alice', 'wrong-password') is None
    assert auth.authenticate_user('alice', 'correct-horse-battery') is not None


def test_the_decoy_is_built_once(auth, caplog):
    """A hash per attempt would make the fix a denial-of-service lever of
    its own — bcrypt is expensive on purpose."""
    from modules.core.auth import AuthManager

    caplog.set_level(logging.CRITICAL)
    AuthManager._decoy_hash = None
    auth.authenticate_user('nosuchuser', 'x')
    first = AuthManager._decoy_hash
    auth.authenticate_user('nosuchuser', 'y')

    assert first is not None
    assert AuthManager._decoy_hash is first


# --- the cookie -----------------------------------------------------------

@pytest.mark.parametrize('module_name,marker', [
    ('modules/web/auth_routes.py', 'certmate_session'),
    ('modules/web/oidc_routes.py', 'certmate_session'),
])
def test_both_cookies_ask_the_app_not_the_request(module_name, marker):
    """`request.is_secure` is a per-request fact a TLS-terminating proxy
    hides. factory.py already decides this from PREFERRED_URL_SCHEME and
    CERTMATE_ENABLE_HSTS; both cookie sites now read that decision."""
    import pathlib

    repo = pathlib.Path(__file__).resolve().parent.parent
    source = (repo / module_name).read_text(encoding='utf-8')

    assert marker in source
    assert "secure=request.is_secure" not in source
    assert "SESSION_COOKIE_SECURE" in source


@pytest.mark.parametrize('env,expected', [
    ({}, False),                                    # plain HTTP: cookie must be accepted
    ({'PREFERRED_URL_SCHEME': 'https'}, True),      # operator declared HTTPS
    ({'CERTMATE_ENABLE_HSTS': 'true'}, True),       # ditto, the other way
    ({'PREFERRED_URL_SCHEME': 'http'}, False),
])
def test_the_decision_follows_what_the_operator_declared(monkeypatch, env,
                                                         expected, tmp_path):
    """Read from a real app rather than restated here.

    The first version of this test recomputed the rule in the test body,
    which asserts that I can copy an expression — not that the app does it.
    It also carried an `or True`, so half of it could not fail.

    The False cases are the control and the reason this is not simply
    `secure=True`: a browser REFUSES a Secure cookie over plain HTTP, so on
    an install with no HTTPS signal that would not harden anything, it would
    stop anyone logging in.
    """
    import os
    import secrets as _secrets

    for var in ('PREFERRED_URL_SCHEME', 'CERTMATE_ENABLE_HSTS'):
        monkeypatch.delenv(var, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                     ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'),
                     ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    token = _secrets.token_urlsafe(32)
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    os.environ['API_BEARER_TOKEN'] = token

    from modules.factory import create_app
    app, _ = create_app()

    assert app.config['SESSION_COOKIE_SECURE'] is expected


# --- the busy domain ------------------------------------------------------

def _manager_that_raises(exception):
    """A CertificateManager stubbed only as far as `_renew_if_due` reaches.

    It calls `get_certificate_info` first and only proceeds when the result
    says `needs_renewal` — the first draft of this test stubbed neither and
    died on an attribute the sweep never got to, which says nothing about
    the branch under test.
    """
    from unittest.mock import MagicMock

    from modules.core.certificates import CertificateManager

    manager = CertificateManager.__new__(CertificateManager)
    manager.get_certificate_info = MagicMock(
        return_value={'exists': True, 'needs_renewal': True})
    manager.renew_certificate = MagicMock(side_effect=exception)
    manager._audit_scheduled_renew = MagicMock()
    manager._record_renewal_metrics = MagicMock()
    manager._publish_failed_event = MagicMock()
    manager._publish_renewed_event = MagicMock()
    return manager


def test_a_busy_domain_is_skipped_not_failed():
    """THE regression, driven through the sweep's own handler."""
    from modules.core.certificates import DomainOperationInProgress

    manager = _manager_that_raises(
        DomainOperationInProgress('busy.example.com'))
    summary = {'checked': 0, 'renewed': 0, 'failed': 0, 'skipped_busy': 0,
               'skipped_not_due': 0}

    result = manager._renew_if_due('busy.example.com', {}, summary)

    assert result is False
    assert summary['failed'] == 0, 'a busy domain was counted as a failure'
    assert summary['skipped_busy'] == 1
    manager._publish_failed_event.assert_not_called()
    manager._audit_scheduled_renew.assert_not_called()
    manager._record_renewal_metrics.assert_not_called()


def test_a_real_failure_is_still_a_failure():
    """CONTROL. The notifier exists for exactly this case, and a fix that
    quietened everything would pass the test above."""
    manager = _manager_that_raises(RuntimeError('certbot exited 1'))
    summary = {'checked': 0, 'renewed': 0, 'failed': 0, 'skipped_busy': 0,
               'skipped_not_due': 0}

    result = manager._renew_if_due('broken.example.com', {}, summary)

    assert result is False
    assert summary['failed'] == 1
    assert summary['skipped_busy'] == 0
    manager._publish_failed_event.assert_called_once()
    manager._audit_scheduled_renew.assert_called_once()


def test_every_shape_of_the_summary_carries_the_key():
    """The sweep has an early return for auto-renew-off, and a caller that
    reads a key must not have to know which return produced the dict — the
    comment beside that early return says so about `unmanaged`."""
    import ast
    import inspect

    from modules.core import certificates

    tree = ast.parse(inspect.getsource(certificates))
    summaries = [node for node in ast.walk(tree) if isinstance(node, ast.Dict)
                 and any(isinstance(k, ast.Constant) and k.value == 'skipped_not_due'
                         for k in node.keys if k is not None)]

    assert summaries, 'no sweep summary found — this test reads nothing'
    for node in summaries:
        keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
        assert 'skipped_busy' in keys, (
            f'a sweep summary is missing skipped_busy: {sorted(keys)}')
