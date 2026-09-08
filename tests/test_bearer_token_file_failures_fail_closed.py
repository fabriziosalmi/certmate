"""An unreadable credential file leaves the instance locked, not open.

`setup_mode_for` decides whether this instance requires a credential at all.
Its first question is whether the operator provided an API bearer token, and
when that token is supplied as a file — the documented Docker and Kubernetes
pattern — the answer came from reading it.

A read failure was reported as "the operator provided no token". On a
deployment whose only credential is that file, with no local users and no
OIDC, that is the difference between a locked instance and one where
`_authenticate_request` hands an anonymous caller an admin identity. The
decision was also memoised, so a file that was unreadable for one instant at
startup stayed unreadable in effect until the process was restarted.

The two answers are now separate values. "No token was configured" is still
False, because a fresh install must stay open long enough to be bootstrapped —
that case is a CONTROL here, and it is the one these tests could most easily
break. "A token was configured and cannot be read right now" raises, and the
caller treats it as configured: locked, logged at ERROR, and not cached, so the
next check retries.
"""
import logging
import pathlib
import secrets
import tempfile
from unittest.mock import MagicMock

import pytest

from modules.core.auth import AuthManager, BearerTokenFileUnreadable

pytestmark = [pytest.mark.unit]

UNCONFIGURED = {'local_auth_enabled': False, 'users': {}, 'oidc': {}}


@pytest.fixture
def token_file(monkeypatch):
    path = pathlib.Path(tempfile.mkdtemp()) / 'api_bearer_token'
    path.write_text(secrets.token_urlsafe(48))
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(path))
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    return path


def _manager():
    manager = AuthManager.__new__(AuthManager)
    manager.settings_manager = MagicMock()
    return manager


# ---------------------------------------------------------------------------
# The two answers that must not be the same
# ---------------------------------------------------------------------------

def test_a_readable_token_file_locks_the_instance(token_file):
    """CONTROL for everything below: the ordinary configured case."""
    assert _manager().setup_mode_for(UNCONFIGURED) is False


def test_no_token_configured_at_all_still_opens_setup_mode(monkeypatch):
    """THE control. A fresh install has no credential of any kind and must
    stay open long enough for an operator to create one — that is what setup
    mode is for. A fix that locked this case would make the product
    unbootstrappable, which is a worse failure than the one being fixed."""
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)

    assert _manager().setup_mode_for(UNCONFIGURED) is True


@pytest.mark.parametrize('break_it,label', [
    (lambda p: p.chmod(0o000), 'permissions changed'),
    (lambda p: p.unlink(), 'file not there yet'),
])
def test_an_unreadable_token_file_keeps_the_instance_locked(
        token_file, break_it, label):
    """The defect. Both shapes are ordinary operational events — a secret
    remounted with different ownership, a volume that is not ready when the
    container starts — and neither may open the instance."""
    break_it(token_file)

    assert _manager().setup_mode_for(UNCONFIGURED) is False, (
        f'an unreadable token file ({label}) put the instance into setup mode, '
        f'where an anonymous caller is admin'
    )


def test_the_read_failure_is_distinguishable_from_absence(token_file):
    """The mechanism, asserted directly: the detector raises rather than
    returning the same False it returns for 'nothing was configured'."""
    token_file.chmod(0o000)

    with pytest.raises(BearerTokenFileUnreadable) as excinfo:
        AuthManager._detect_operator_bearer_token()

    assert str(token_file) in str(excinfo.value), (
        'the error does not name the file the operator configured'
    )


def test_the_failure_is_logged_at_error(token_file, caplog):
    """A decision this consequential must not be silent. The previous code
    discarded the exception without a line, so the only evidence that the
    instance had decided it was unconfigured was its behaviour."""
    token_file.unlink()

    with caplog.at_level(logging.ERROR):
        _manager().setup_mode_for(UNCONFIGURED)

    assert 'API_BEARER_TOKEN_FILE' in caplog.text
    assert 'locked' in caplog.text.lower()


# ---------------------------------------------------------------------------
# The failure must not be cached
# ---------------------------------------------------------------------------

def test_a_transient_read_failure_is_not_remembered(token_file):
    """The memoisation was justified on the premise that env and file are
    fixed for the process lifetime. The variable is; the file it names is not.
    A secret mounted a moment late produced one failed read, and caching it
    fixed the wrong state in place until a restart."""
    manager = _manager()
    token_file.chmod(0o000)
    assert manager.setup_mode_for(UNCONFIGURED) is False

    # The cache must be EMPTY, not holding the failure's answer. Asserting the
    # answer alone cannot see this: a cached failure and a fresh failure both
    # say "locked", so only the absence of the cache entry distinguishes them.
    assert not hasattr(manager, '_operator_bearer_token'), (
        'the read failure was cached, so a secret mounted one instant late '
        'stays unreadable in effect until the process restarts'
    )

    token_file.chmod(0o600)
    assert manager.has_operator_bearer_token() is True
    assert manager._operator_bearer_token is True, (
        'the successful read was not cached, so every request re-reads the file'
    )


def test_a_successful_determination_is_still_cached(token_file, caplog):
    """CONTROL: the memoisation exists for a reason — this is on the path of
    every authorization decision. Only the failure is exempt from it."""
    manager = _manager()
    assert manager.has_operator_bearer_token() is True

    # Deleting the file must now be invisible, because the cache answers.
    # Asserting the return value alone cannot see a missing cache — an
    # uncached call would read, fail, and return True as well. The absence of
    # the ERROR line is what proves the file was not consulted.
    token_file.unlink()
    with caplog.at_level(logging.ERROR):
        assert manager.has_operator_bearer_token() is True
    assert 'API_BEARER_TOKEN_FILE' not in caplog.text, (
        'the cached determination was discarded and the file was read again'
    )


def test_an_absent_configuration_is_cached_too(monkeypatch):
    """CONTROL: 'no token configured' is a determination, not a failure, and
    caching it is what keeps the common path cheap."""
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    manager = _manager()

    assert manager.has_operator_bearer_token() is False
    assert manager._operator_bearer_token is False


# ---------------------------------------------------------------------------
# The environment-variable form is unaffected
# ---------------------------------------------------------------------------

def test_the_environment_variable_form_still_works(monkeypatch):
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)
    monkeypatch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(48))

    assert _manager().setup_mode_for(UNCONFIGURED) is False


def test_an_invalid_environment_token_does_not_count_as_configured(monkeypatch):
    """CONTROL: fail-closed on a read failure must not become fail-closed on
    anything. A token that does not pass validation is not a configured
    credential, and the instance must still open so it can be fixed."""
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)
    monkeypatch.setenv('API_BEARER_TOKEN', 'short')

    assert _manager().setup_mode_for(UNCONFIGURED) is True


def test_an_empty_token_file_is_not_a_configured_credential(token_file):
    """An empty file is readable and says nothing. That is a determination
    (no usable token) rather than a failure, so it does not lock the instance
    — otherwise touching the file by mistake would brick onboarding."""
    token_file.write_text('')

    assert _manager().setup_mode_for(UNCONFIGURED) is True
