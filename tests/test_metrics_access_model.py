"""The Prometheus scrape target has one declared, coherent access model.

`/metrics` required the **admin** role while the sibling `/api/metrics`
(`MetricsList`) served the same class of information — domain names, counts,
expiry — at **viewer**, and justified its own gate in a comment that asserted
"the Prometheus scrape target is the separate public '/metrics' route". The
relationship was stated backwards: the scrape route was not public, it was
stricter. The practical effect was that collecting metrics at all required
putting ADMIN credentials into a Prometheus scrape config, or collecting
nothing.

`/metrics` now requires viewer: least privilege for a read-only endpoint, and
consistent with the sibling that already exposes the same data. It is still
authenticated — the series enumerate every managed domain, which is
infrastructure disclosure (#650).
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.misc_routes import register_misc_routes

pytestmark = [pytest.mark.unit]


def _app_recording_declared_roles():
    """Mount the misc routes, tagging each view with the role it declared."""
    app = Flask(__name__)
    app.config['VERSION'] = 'test'

    auth_manager = MagicMock()

    def _recording_require_role(role):
        def deco(fn):
            fn._declared_role = role
            return fn
        return deco

    auth_manager.require_role = _recording_require_role
    auth_manager.is_local_auth_enabled.return_value = False
    auth_manager.has_any_users.return_value = False

    register_misc_routes(app, {}, require_web_auth=None,
                         auth_manager=auth_manager)
    return app


def test_metrics_is_not_public():
    app = _app_recording_declared_roles()
    view = app.view_functions['metrics']
    assert getattr(view, '_declared_role', None) is not None, (
        "/metrics must be authenticated — its series enumerate every managed "
        "domain, which discloses the infrastructure being protected"
    )


def test_metrics_requires_viewer_not_admin():
    app = _app_recording_declared_roles()
    assert app.view_functions['metrics']._declared_role == 'viewer', (
        "a read-only scrape target must not demand admin: that forces admin "
        "credentials into a Prometheus scrape config to collect anything"
    )


def test_metrics_matches_the_sibling_json_summary_gate():
    """CONTROL: the two metrics surfaces must not disagree.

    `/api/metrics` (MetricsList) is gated at viewer. If the scrape route drifts
    to a different role again, one of the two comments explaining the split
    becomes false — which is exactly the state this fixed.
    """
    app = _app_recording_declared_roles()
    activity_role = app.view_functions['activity_api']._declared_role
    metrics_role = app.view_functions['metrics']._declared_role
    assert metrics_role == activity_role == 'viewer', (
        "read-only informational endpoints should share one gate; "
        f"/metrics={metrics_role} vs /api/activity={activity_role}"
    )
