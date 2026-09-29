"""A batch create is N single creates and one settings write (#666, D9).

`POST /api/web/certificates/batch` called `certificate_manager.create_certificate`
directly, re-implementing the service's checks by hand. Three consequences,
each read off the code and pinned here:

- `account_id` was never passed to issuance: every certificate was issued
  with the provider's DEFAULT DNS account, while the settings entry recorded
  the account the caller named, so issuance and renewal used different
  credentials;
- no success audit record and no `certificate_created` event: deploy hooks,
  webhooks and notifications never fired for a batch-created certificate;
- its own copy of domain validation and scope checking, one more place to drift.

What the route did right, and must keep: ONE settings write for the whole
batch. Every settings save takes a full unified backup (settings plus every
certificate), so one write per domain would zip the whole certificate store N
times. The fix routes each domain through the service's own steps and keeps
the single write.
"""
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.cert_service import CertificateService

pytestmark = [pytest.mark.unit]


def _service(tmp_path, *, scope_denies=(), fail=()):
    certs = MagicMock(cert_dir=Path(tmp_path))

    def create(**kwargs):
        if kwargs['domain'] in fail:
            raise RuntimeError('Certificate creation failed: rateLimited')
        return {'success': True, 'dns_provider': kwargs['dns_provider'],
                'ca_provider': kwargs['ca_provider']}

    certs.create_certificate.side_effect = create
    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': 'ops@example.com', 'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01'}
    auth = MagicMock()
    auth.user_can_access_domain.side_effect = lambda user, d: d not in scope_denies
    audit = MagicMock()
    bus = MagicMock()
    service = CertificateService(certs, settings, auth, audit_logger=audit, event_bus=bus)
    return service, certs, settings, audit, bus


def _batch(service, domains, **kw):
    return service.create_batch(domains=domains, dns_provider='cloudflare',
                                account_id='prod-account',
                                user={'username': 'op', 'role': 'operator'},
                                ip_address='203.0.113.9', **kw)


def test_every_domain_is_issued_with_the_account_the_caller_named(tmp_path):
    """THE regression. The batch dropped account_id on the way to issuance."""
    service, certs, *_ = _service(tmp_path)
    _batch(service, ['a.example.com', 'b.example.com'])

    accounts = [c.kwargs['account_id'] for c in certs.create_certificate.call_args_list]
    assert accounts == ['prod-account', 'prod-account']


def test_every_created_certificate_is_audited_and_announced(tmp_path):
    service, _certs, _settings, audit, bus = _service(tmp_path)
    _batch(service, ['a.example.com', 'b.example.com'])

    created = [c.args[1]['domain'] for c in bus.publish.call_args_list
               if c.args[0] == 'certificate_created']
    assert created == ['a.example.com', 'b.example.com']
    ops = [(c.kwargs.get('operation'), c.kwargs.get('resource_id'), c.kwargs.get('status'))
           for c in audit.log_operation.call_args_list]
    assert ('create', 'a.example.com', 'success') in ops
    assert ('create', 'b.example.com', 'success') in ops


def test_the_whole_batch_is_one_settings_write(tmp_path):
    """The property the route had right: one write, so one backup."""
    service, _certs, settings, *_ = _service(tmp_path)
    _batch(service, ['a.example.com', 'b.example.com', 'c.example.com'])

    assert settings.update.call_count == 1
    mutator = settings.update.call_args.args[0]
    s = {'domains': []}
    mutator(s)
    assert [(d['domain'], d['dns_provider'], d['dns_account_id']) for d in s['domains']] == [
        ('a.example.com', 'cloudflare', 'prod-account'),
        ('b.example.com', 'cloudflare', 'prod-account'),
        ('c.example.com', 'cloudflare', 'prod-account')]


def test_one_failure_does_not_stop_the_rest_and_is_not_registered(tmp_path):
    service, _certs, settings, audit, bus = _service(tmp_path, fail={'b.example.com'})
    results = _batch(service, ['a.example.com', 'b.example.com', 'c.example.com'])

    assert [(r['domain'], r['success']) for r in results] == [
        ('a.example.com', True), ('b.example.com', False), ('c.example.com', True)]
    # Generic per-item text, as the route promised: raw exception text never
    # reaches the client.
    assert results[1]['message'] == 'Certificate creation failed'
    s = {'domains': []}
    settings.update.call_args.args[0](s)
    assert [d['domain'] for d in s['domains']] == ['a.example.com', 'c.example.com']
    assert ('create', 'b.example.com', 'failure') in [
        (c.kwargs.get('operation'), c.kwargs.get('resource_id'), c.kwargs.get('status'))
        for c in audit.log_operation.call_args_list]


def test_an_out_of_scope_domain_is_refused_alone_and_audited(tmp_path):
    service, certs, _settings, audit, _bus = _service(tmp_path, scope_denies={'b.example.com'})
    results = _batch(service, ['a.example.com', 'b.example.com'])

    assert results[1] == {'domain': 'b.example.com', 'success': False,
                          'message': 'API key not authorized for this domain'}
    issued = [c.kwargs['domain'] for c in certs.create_certificate.call_args_list]
    assert issued == ['a.example.com']
    audit.log_authz_denied.assert_called()


def test_an_invalid_domain_keeps_its_message_and_nothing_is_issued_for_it(tmp_path):
    service, certs, *_ = _service(tmp_path)
    results = _batch(service, ['../escape', 'a.example.com'])

    assert results[0]['success'] is False
    assert results[0]['message'].startswith('Invalid domain')
    assert [c.kwargs['domain'] for c in certs.create_certificate.call_args_list] == ['a.example.com']


def test_nothing_created_means_no_settings_write(tmp_path):
    """CONTROL: a write (and its full backup) only when there is something to record."""
    service, _certs, settings, *_ = _service(tmp_path, fail={'a.example.com'})
    _batch(service, ['a.example.com'])

    settings.update.assert_not_called()


def test_the_single_create_path_is_unchanged(tmp_path):
    """CONTROL: create() still registers its own domain, once."""
    service, certs, settings, *_ = _service(tmp_path)
    service.create(domain='solo.example.com', dns_provider='cloudflare',
                   account_id='prod-account', user={'username': 'op'}, ip_address='x')

    assert settings.update.call_count == 1
    assert certs.create_certificate.call_args.kwargs['account_id'] == 'prod-account'


def test_the_route_refuses_a_string_instead_of_walking_it(tmp_path):
    """A string passed where the list goes was walked character by character."""
    from flask import Flask, request

    from modules.core.constants import CERTIFICATE_FILES
    from modules.web.cert_routes import register_cert_routes

    def passthrough(_role=None):
        return (lambda fn: fn) if not callable(_role) else _role

    app = Flask(__name__)
    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=lambda role: (lambda fn: fn))
    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'ops@example.com'}
    register_cert_routes(app, {'audit': MagicMock(), 'cert_service': None}, passthrough,
                         auth, MagicMock(cert_dir=Path(tmp_path)), lambda d: d, MagicMock(),
                         settings, MagicMock(), CERTIFICATE_FILES)

    @app.before_request
    def _user():
        request.current_user = {'username': 'op', 'role': 'operator'}

    response = app.test_client().post('/api/web/certificates/batch',
                                      json={'domains': 'a.example.com'})
    assert response.status_code == 400
