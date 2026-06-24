"""Regression: GET /api/metrics must require at least a viewer credential.

MetricsList carried no auth decorator at all, while its sibling info endpoints
(CacheStats, BackupList) are require_role('viewer'). An unauthenticated GET hit
the handler. The Prometheus scrape target is the SEPARATE public '/metrics'
route; this JSON summary lives in the authenticated API and must be gated to
match its peers.
"""
from collections import defaultdict
from unittest.mock import MagicMock

import pytest
from flask import Flask, abort
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
from modules.core.auth import ROLE_HIERARCHY

pytestmark = [pytest.mark.unit]


def _build_app(current_user):
    def require_role_factory(min_role):
        def deco(fn):
            def wrapped(*a, **k):
                role = (current_user or {}).get("role")
                if ROLE_HIERARCHY.get(role, -1) < ROLE_HIERARCHY.get(min_role, 999):
                    abort(401)
                return fn(*a, **k)
            return wrapped
        return deco

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=require_role_factory)

    managers = defaultdict(MagicMock)
    managers["auth"] = auth_manager

    app = Flask(__name__)
    app.config["TESTING"] = True
    api = Api(app, prefix="/api")
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns = Namespace("metrics", description="metrics")
    api.add_namespace(ns)
    ns.add_resource(resources["MetricsList"], "")
    return app


def test_metrics_blocked_when_unauthenticated():
    resp = _build_app(current_user=None).test_client().get("/api/metrics")
    assert resp.status_code == 401


def test_metrics_not_blocked_for_viewer():
    # Auth passes; body may be 200 or 503 (prometheus availability) — never 401.
    resp = _build_app(current_user={"role": "viewer"}).test_client().get("/api/metrics")
    assert resp.status_code != 401
