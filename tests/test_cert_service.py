"""Unit tests for the shared CertificateService (create/renew orchestration).

These pin the behaviour both HTTP adapters now depend on: validate-before-
side-effect, scope enforcement (DomainOutOfScope + audit), settings-driven
defaults, idempotent domain persistence and exception passthrough. The
adapters (modules/api/resources.py, modules/web/cert_routes.py) are thin
shells over this service, so this is where the create/renew contract lives.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.cert_service import CertificateService, DomainOutOfScope
from modules.core.certificates import DomainOperationInProgress


pytestmark = [pytest.mark.unit]


def _make_service(*, allowed=True, settings=None):
    certs = MagicMock()
    certs.create_certificate.return_value = {
        'success': True, 'domain': 'x', 'dns_provider': 'cloudflare', 'duration': 1.0,
    }
    certs.renew_certificate.return_value = {
        'success': True, 'domain': 'x', 'message': 'Certificate renewed successfully',
    }
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = settings if settings is not None else {
        'email': 'ops@example.com',
        'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
    }
    auth = MagicMock()
    auth.user_can_access_domain.return_value = allowed
    audit = MagicMock()
    svc = CertificateService(certs, settings_mgr, auth, audit_logger=audit)
    return svc, certs, settings_mgr, auth, audit


class TestCreate:
    def test_happy_path_calls_manager_and_persists(self):
        svc, certs, settings_mgr, _auth, _audit = _make_service()
        result = svc.create(
            domain='shiny.example.com',
            user={'username': 'op', 'allowed_domains': None}, ip_address='1.2.3.4',
        )
        certs.create_certificate.assert_called_once()
        kwargs = certs.create_certificate.call_args.kwargs
        assert kwargs['domain'] == 'shiny.example.com'
        assert kwargs['email'] == 'ops@example.com'
        assert kwargs['dns_provider'] == 'cloudflare'
        assert kwargs['challenge_type'] == 'dns-01'
        # Domain persisted under the unified reason.
        settings_mgr.update.assert_called_once()
        assert settings_mgr.update.call_args.args[1] == 'certificate_created'
        assert result['success'] is True

    @pytest.mark.parametrize('bad', [
        '../poisoned', 'foo/bar', '..', 'with space.example.com', 'no-tld',
    ])
    def test_invalid_domain_raises_before_side_effects(self, bad):
        svc, certs, settings_mgr, _auth, _audit = _make_service()
        with pytest.raises(ValueError) as exc:
            svc.create(domain=bad, user={}, ip_address='1.2.3.4')
        assert 'Invalid domain' in str(exc.value)
        certs.create_certificate.assert_not_called()
        settings_mgr.update.assert_not_called()

    def test_invalid_domain_alias_raises(self):
        svc, certs, *_ = _make_service()
        with pytest.raises(ValueError) as exc:
            svc.create(domain='good.example.com', domain_alias='../evil',
                       user={}, ip_address='1.2.3.4')
        assert 'Invalid domain_alias' in str(exc.value)
        certs.create_certificate.assert_not_called()

    def test_non_list_san_raises(self):
        svc, certs, *_ = _make_service()
        with pytest.raises(ValueError) as exc:
            svc.create(domain='good.example.com', san_domains='not-a-list',
                       user={}, ip_address='1.2.3.4')
        assert 'san_domains' in str(exc.value)
        certs.create_certificate.assert_not_called()

    def test_out_of_scope_primary_raises_and_audits(self):
        svc, certs, settings_mgr, _auth, audit = _make_service(allowed=False)
        with pytest.raises(DomainOutOfScope) as exc:
            svc.create(domain='good.example.com',
                       user={'username': 'op', 'allowed_domains': ['other.com']},
                       ip_address='9.9.9.9')
        assert exc.value.domain == 'good.example.com'
        audit.log_authz_denied.assert_called_once()
        assert audit.log_authz_denied.call_args.kwargs['operation'] == 'create'
        certs.create_certificate.assert_not_called()
        settings_mgr.update.assert_not_called()

    def test_out_of_scope_san_raises(self):
        svc, certs, _settings, auth, _audit = _make_service()
        auth.user_can_access_domain.side_effect = \
            lambda user, d: d != 'denied.example.com'
        with pytest.raises(DomainOutOfScope) as exc:
            svc.create(domain='good.example.com',
                       san_domains=['denied.example.com'],
                       user={}, ip_address='1.1.1.1')
        assert exc.value.domain == 'denied.example.com'
        certs.create_certificate.assert_not_called()

    def test_missing_email_raises(self):
        svc, certs, *_ = _make_service(settings={'dns_provider': 'cloudflare'})
        with pytest.raises(ValueError) as exc:
            svc.create(domain='good.example.com', user={}, ip_address='1.1.1.1')
        assert 'Email not configured' in str(exc.value)
        certs.create_certificate.assert_not_called()

    def test_missing_dns_provider_raises_for_dns01(self):
        svc, certs, *_ = _make_service(
            settings={'email': 'a@b.com', 'challenge_type': 'dns-01'})
        with pytest.raises(ValueError) as exc:
            svc.create(domain='good.example.com', user={}, ip_address='1.1.1.1')
        assert 'No DNS provider' in str(exc.value)
        certs.create_certificate.assert_not_called()

    def test_http01_does_not_require_dns_provider(self):
        svc, certs, *_ = _make_service(settings={'email': 'a@b.com'})
        svc.create(domain='good.example.com', challenge_type='http-01',
                   user={}, ip_address='1.1.1.1')
        certs.create_certificate.assert_called_once()
        assert certs.create_certificate.call_args.kwargs['challenge_type'] == 'http-01'

    def test_domain_operation_in_progress_propagates(self):
        svc, certs, *_ = _make_service()
        certs.create_certificate.side_effect = \
            DomainOperationInProgress('good.example.com')
        with pytest.raises(DomainOperationInProgress):
            svc.create(domain='good.example.com', user={}, ip_address='1.1.1.1')

    def test_add_domain_mutator_is_idempotent(self):
        svc, _certs, settings_mgr, *_ = _make_service()
        svc.create(domain='new.example.com', account_id='prod',
                   user={}, ip_address='1.1.1.1')
        mutator = settings_mgr.update.call_args.args[0]

        # Already present -> left untouched (no duplicate entry).
        existing = {'domains': [{'domain': 'new.example.com'}]}
        mutator(existing)
        assert existing['domains'] == [{'domain': 'new.example.com'}]

        # Absent -> appended with provider + account metadata.
        fresh = {'domains': []}
        mutator(fresh)
        assert fresh['domains'] == [{
            'domain': 'new.example.com',
            'dns_provider': 'cloudflare',
            'dns_account_id': 'prod',
        }]


class TestRenew:
    def test_happy_path(self):
        svc, certs, _settings, _auth, _audit = _make_service()
        result = svc.renew(domain='good.example.com', force=True,
                           user={}, ip_address='1.1.1.1')
        certs.renew_certificate.assert_called_once_with('good.example.com', force=True)
        assert result['success'] is True

    def test_out_of_scope_raises_and_audits(self):
        svc, certs, _settings, _auth, audit = _make_service(allowed=False)
        with pytest.raises(DomainOutOfScope):
            svc.renew(domain='good.example.com',
                      user={'username': 'op'}, ip_address='9.9.9.9')
        audit.log_authz_denied.assert_called_once()
        assert audit.log_authz_denied.call_args.kwargs['operation'] == 'renew'
        certs.renew_certificate.assert_not_called()

    def test_domain_operation_in_progress_propagates(self):
        svc, certs, *_ = _make_service()
        certs.renew_certificate.side_effect = \
            DomainOperationInProgress('good.example.com')
        with pytest.raises(DomainOperationInProgress):
            svc.renew(domain='good.example.com', user={}, ip_address='1.1.1.1')
