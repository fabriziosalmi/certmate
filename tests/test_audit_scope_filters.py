"""Regression tests for the scope-filter gaps surfaced by the internal
security audit (May 2026): M4 and M5.

### M4 — `GET /api/settings` leaked the full `domains[]` array

Before this fix, both the Flask-RESTX ``Settings.get`` and the web
blueprint ``api_settings_get`` returned ``settings['domains']`` to
any viewer-role caller without scope filtering. A scoped API key
(``allowed_domains`` set to e.g. ``['*.tenant-a.example']``) could
therefore enumerate every domain the org had ever issued a cert for,
regardless of scope. Other endpoints already filtered correctly
(``CertificateList.get`` does this via the same
``domain_matches_scope`` check) — settings was the outlier.

### M5 — `POST /api/certificates/check-dns-alias` had no scope check

The body-style variant accepted ``domain`` + ``san_domains`` straight
from the request body, ran ``require_role('viewer')`` and called
``certificate_manager.check_dns_alias_records`` directly — never
calling ``_check_domain_scope``. The path-style sibling
``CertificateDNSAliasCheck.get(domain)`` did scope-gate, so the body
variant was the asymmetric leak: a scoped viewer could probe
``_acme-challenge`` CNAME topology for any out-of-scope tenant.

Information disclosure rather than direct access, but a scoped key
is supposed to be a hard wall around a tenant — leaking the alias
topology breaks that mental model.
"""

import pytest
from unittest.mock import MagicMock
from pathlib import Path

from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


# =============================================
# M4 — Settings.get filters domains by scope
# =============================================

@pytest.fixture
def settings_get_app(tmp_path):
    """RESTX Settings.get wired in isolation. ``auth_manager.domain_matches_scope``
    is mocked with a realistic fnmatch-style behaviour so the test can
    feed an actual scope and assert per-row filtering."""
    settings_dict = {
        'email': 'ops@example.com',
        'domains': [
            {'domain': 'app.tenant-a.example', 'dns_provider': 'cloudflare'},
            {'domain': 'api.tenant-a.example', 'dns_provider': 'cloudflare'},
            {'domain': 'app.tenant-b.example', 'dns_provider': 'route53'},
            'legacy-string-form.tenant-c.example',  # legacy string entry
        ],
    }

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = settings_dict

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    # Realistic scope predicate: scope=None means unrestricted,
    # otherwise the domain must end with one of the suffixes in
    # `scope` (treating each as a fnmatch-ish suffix without glob).
    def matches_scope(domain, scope):
        if scope is None:
            return True
        for pat in scope:
            # cheap fnmatch-style for the test: `*.tenant-a.example`
            if pat.startswith('*.'):
                if domain.endswith(pat[1:]) or domain == pat[2:]:
                    return True
            elif domain == pat:
                return True
        return False
    auth_manager.domain_matches_scope.side_effect = matches_scope

    managers = {
        'auth': auth_manager,
        'settings': settings_manager,
        'certificates': MagicMock(cert_dir=Path(tmp_path)),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(),
        'dns': MagicMock(),
        'audit': MagicMock(),
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns = Namespace('settings', description='settings')
    api.add_namespace(ns)
    ns.add_resource(resources['Settings'], '')
    return app, settings_dict


def _as_user(app, role, allowed_domains):
    @app.before_request
    def _set_user():
        request.current_user = {
            'username': f'fake_{role}',
            'role': role,
            'allowed_domains': allowed_domains,
        }


class TestSettingsGetFiltersDomainsByScope:

    def test_unrestricted_caller_sees_all_domains(self, settings_get_app):
        app, _ = settings_get_app
        _as_user(app, 'viewer', None)  # no scope
        r = app.test_client().get('/api/settings')
        assert r.status_code == 200, r.data
        body = r.get_json()
        # All four domains visible.
        names = []
        for entry in body.get('domains', []):
            names.append(entry if isinstance(entry, str) else entry.get('domain'))
        assert set(names) == {
            'app.tenant-a.example', 'api.tenant-a.example',
            'app.tenant-b.example', 'legacy-string-form.tenant-c.example',
        }

    def test_scoped_caller_sees_only_in_scope_domains(self, settings_get_app):
        app, _ = settings_get_app
        _as_user(app, 'viewer', ['*.tenant-a.example'])
        r = app.test_client().get('/api/settings')
        assert r.status_code == 200, r.data
        body = r.get_json()
        names = [
            entry if isinstance(entry, str) else entry.get('domain')
            for entry in body.get('domains', [])
        ]
        assert set(names) == {'app.tenant-a.example', 'api.tenant-a.example'}

    def test_scoped_caller_does_not_see_other_tenant_domains(self, settings_get_app):
        """The headline of the audit finding: a scoped key must NOT
        enumerate other tenants' domains via the settings response."""
        app, _ = settings_get_app
        _as_user(app, 'viewer', ['*.tenant-a.example'])
        r = app.test_client().get('/api/settings')
        body = r.get_json()
        # Defensive: no part of the response carries tenant-b or
        # tenant-c domain names.
        assert b'tenant-b' not in r.data
        assert b'tenant-c' not in r.data

    def test_scope_filter_handles_legacy_string_entries(self, settings_get_app):
        """The `domains` list can contain either dicts or bare strings
        (legacy shape). The filter must handle both."""
        app, _ = settings_get_app
        _as_user(app, 'viewer', ['*.tenant-c.example'])
        r = app.test_client().get('/api/settings')
        body = r.get_json()
        names = [
            entry if isinstance(entry, str) else entry.get('domain')
            for entry in body.get('domains', [])
        ]
        assert names == ['legacy-string-form.tenant-c.example']


# =============================================
# M5 — CheckDNSAlias.post scope-checks domain + SANs
# =============================================

@pytest.fixture
def check_dns_alias_app(tmp_path):
    """CheckDNSAlias.post wired with a realistic scope predicate +
    audit_logger mock so we can assert the authz_denied log on
    rejection."""
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    def matches_scope(domain, scope):
        if scope is None:
            return True
        for pat in scope:
            if pat.startswith('*.'):
                if domain.endswith(pat[1:]) or domain == pat[2:]:
                    return True
            elif domain == pat:
                return True
        return False
    auth_manager.domain_matches_scope.side_effect = matches_scope

    # `_check_domain_scope` in resources.py calls
    # `auth_manager.user_can_access_domain(user, domain)`, which is a
    # SEPARATE method from `domain_matches_scope`. Mirror the real
    # AuthManager implementation here so the resource-level scope
    # gate behaves end-to-end.
    def user_can_access(user, domain):
        if not user:
            return False
        return matches_scope(domain, user.get('allowed_domains'))
    auth_manager.user_can_access_domain.side_effect = user_can_access

    certificate_manager = MagicMock()
    certificate_manager.check_dns_alias_records.return_value = {'ok': True}
    audit_logger = MagicMock()

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': certificate_manager,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(),
        'dns': MagicMock(),
        'audit': audit_logger,
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['CheckDNSAlias'], '/check-dns-alias')
    return app, managers


class TestCheckDNSAliasScopeCheck:

    def test_scoped_viewer_cannot_probe_other_tenant(self, check_dns_alias_app):
        """The exploit shape: scoped key for `*.tenant-a.example`
        POSTs a check-dns-alias for `out-of-scope.example.com`.
        Must be rejected before the manager is touched."""
        app, managers = check_dns_alias_app
        _as_user(app, 'viewer', ['*.tenant-a.example'])

        r = app.test_client().post('/api/certificates/check-dns-alias', json={
            'domain': 'out-of-scope.example.com',
            'domain_alias': 'alias.out-of-scope.example.com',
        })
        assert r.status_code == 403, r.data
        managers['certificates'].check_dns_alias_records.assert_not_called()

    def test_scoped_viewer_can_probe_in_scope_domain(self, check_dns_alias_app):
        app, managers = check_dns_alias_app
        _as_user(app, 'viewer', ['*.tenant-a.example'])

        r = app.test_client().post('/api/certificates/check-dns-alias', json={
            'domain': 'app.tenant-a.example',
            'domain_alias': 'alias.tenant-a.example',
        })
        assert r.status_code == 200, r.data
        managers['certificates'].check_dns_alias_records.assert_called_once()

    def test_san_outside_scope_is_rejected(self, check_dns_alias_app):
        """If even ONE SAN is out of scope the whole request is
        rejected. Otherwise the caller could smuggle out-of-scope
        probes via SAN entries on an in-scope primary domain."""
        app, managers = check_dns_alias_app
        _as_user(app, 'viewer', ['*.tenant-a.example'])

        r = app.test_client().post('/api/certificates/check-dns-alias', json={
            'domain': 'app.tenant-a.example',  # in scope
            'domain_alias': 'alias.tenant-a.example',
            'san_domains': ['out-of-scope.example.com'],  # NOT in scope
        })
        assert r.status_code == 403, r.data
        managers['certificates'].check_dns_alias_records.assert_not_called()

    def test_unrestricted_caller_unaffected(self, check_dns_alias_app):
        """Unrestricted callers (legacy bearer tokens, local users
        without an explicit allowed_domains list) behaviour is
        unchanged — scope is None, scope check is a no-op."""
        app, managers = check_dns_alias_app
        _as_user(app, 'viewer', None)

        r = app.test_client().post('/api/certificates/check-dns-alias', json={
            'domain': 'any.example.com',
            'domain_alias': 'alias.any.example.com',
        })
        assert r.status_code == 200, r.data
