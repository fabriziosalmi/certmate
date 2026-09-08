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
    auth_manager.require_session_role = _recording_require_role
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


def _metrics_list_declared_role():
    """The role `/api/metrics` (MetricsList) declares.

    MetricsList is defined inside create_api_resources, so reaching it means
    constructing the whole resource graph — there is no cheaper way in, which
    is itself the point of #667.
    """
    from flask_restx import Api

    from modules.api.models import create_api_models
    from modules.api.resources import create_api_resources

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')

    auth_manager = MagicMock()

    def _recording_require_role(role):
        def deco(fn):
            fn._declared_role = role
            return fn
        return deco

    auth_manager.require_role = _recording_require_role
    auth_manager.require_session_role = _recording_require_role

    class _Managers(dict):
        """Supplies a stub for any manager the closure reaches for, so the
        test does not have to enumerate the whole graph."""

        def __missing__(self, key):
            value = MagicMock()
            self[key] = value
            return value

    managers = _Managers(auth=auth_manager)
    resources = create_api_resources(api, create_api_models(api), managers)
    return resources['MetricsList'].get._declared_role


def test_the_two_metrics_surfaces_declare_the_same_gate():
    """CONTROL: the scrape route and the JSON summary must not disagree.

    They serve the same class of information. When they drifted apart, the
    comment on one of them explaining the split became false — which is the
    state this change fixed, so it is the state worth pinning.
    """
    app = _app_recording_declared_roles()
    scrape_role = app.view_functions['metrics']._declared_role
    json_role = _metrics_list_declared_role()
    assert scrape_role == json_role == 'viewer', (
        "the two metrics surfaces must declare one gate; "
        f"/metrics={scrape_role} vs /api/metrics={json_role}"
    )
