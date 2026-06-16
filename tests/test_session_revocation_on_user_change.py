"""Regression: disabling, demoting, or deleting a user revokes live sessions.

create_session() snapshots the role at login; validate_session() returned that
frozen snapshot with only an expiry check. update_user(enabled=False) / a role
change / delete_user mutated settings.json but left the in-memory session valid
for up to SESSION_TIMEOUT_HOURS — a just-disabled / demoted / deleted account
stayed privileged with no kill switch. The fix invalidates a user's sessions on
those transitions; an unrelated edit (e.g. email) must NOT log the user out.
"""
import copy
from unittest.mock import MagicMock

import pytest

from modules.core.auth import AuthManager

pytestmark = [pytest.mark.unit]


def _mk_settings_manager(initial):
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: copy.deepcopy(initial)

    def _update(fn, _audit_label):
        state = copy.deepcopy(initial)
        fn(state)
        initial.clear()
        initial.update(state)
        return True

    sm.update.side_effect = _update
    return sm


@pytest.fixture
def auth():
    initial = {}
    am = AuthManager(_mk_settings_manager(initial))
    # A standing admin so the last-admin guards never block our mutations.
    ok, _ = am.create_user("root", "rootpw", role="admin")
    assert ok
    return am


def _session_for(am, username, role="operator"):
    ok, _ = am.create_user(username, "pw", role=role)
    assert ok
    sid = am.create_session(username)
    assert am.validate_session(sid) is not None
    return sid


def test_disable_revokes_session(auth):
    sid = _session_for(auth, "alice")
    assert auth.update_user("alice", enabled=False)[0]
    assert auth.validate_session(sid) is None


def test_role_change_revokes_session(auth):
    sid = _session_for(auth, "bob")
    assert auth.update_user("bob", role="viewer")[0]
    assert auth.validate_session(sid) is None


def test_delete_revokes_session(auth):
    sid = _session_for(auth, "carol")
    assert auth.delete_user("carol")[0]
    assert auth.validate_session(sid) is None


def test_unrelated_update_keeps_session(auth):
    sid = _session_for(auth, "dave")
    assert auth.update_user("dave", email="dave@example.com")[0]
    # An email-only change is not a privilege change — session must survive.
    assert auth.validate_session(sid) is not None
