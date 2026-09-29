"""Reissue every certificate that lost its key, at a pace (#966, step 3).

After a share-safe restore, forty certificates need a reissue. One by one
through Edit & Reissue is a chore nobody finishes; all at once is forty orders
against the CA's limits. `POST /api/certificates/reissue-keyless` queues at
most `limit` per call on the async executor (two at a time) and says what
remains.
"""
import threading
from unittest.mock import MagicMock

import pytest

from modules.core.cert_jobs import IssuanceExecutor
from modules.core.cert_service import CertificateService, DomainOutOfScope

pytestmark = [pytest.mark.unit]


def _lineage(cert_dir, domain, *, keyless=True):
    d = cert_dir / domain
    archive = d / 'archive' / domain
    archive.mkdir(parents=True)
    (d / 'cert.pem').write_text('cert')
    (archive / 'cert1.pem').write_text('cert')
    if not keyless:
        (d / 'privkey.pem').write_text('key')
        (archive / 'privkey1.pem').write_text('key')


# --- which certificates -----------------------------------------------------

def test_the_service_lists_exactly_the_lineages_that_lost_their_key(tmp_path):
    for name in ('b.example.com', 'a.example.com'):
        _lineage(tmp_path, name)
    _lineage(tmp_path, 'healthy.example.com', keyless=False)
    auth = MagicMock()
    auth.domain_matches_scope.return_value = True
    service = CertificateService(MagicMock(cert_dir=tmp_path), MagicMock(), auth)

    assert service.keyless_domains({'username': 'op'}) == ['a.example.com', 'b.example.com']


def test_a_scoped_key_sees_only_its_own(tmp_path):
    for name in ('a.tenant1.example', 'b.tenant2.example'):
        _lineage(tmp_path, name)
    auth = MagicMock()
    auth.domain_matches_scope.side_effect = lambda d, scope: d.endswith('tenant1.example')
    service = CertificateService(MagicMock(cert_dir=tmp_path), MagicMock(), auth)

    assert service.keyless_domains({'allowed_domains': ['*.tenant1.example']}) == ['a.tenant1.example']


# --- the route --------------------------------------------------------------

def _client(service, executor):
    from flask import Flask, request
    from flask_restx import Api, Namespace

    from modules.api.models import create_api_models
    from modules.api.resources import create_api_resources

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=lambda role: (lambda fn: fn))
    managers = {'auth': auth, 'settings': MagicMock(), 'certificates': MagicMock(),
                'file_ops': MagicMock(), 'cache': MagicMock(), 'dns': MagicMock(),
                'audit': None, 'cert_service': service, 'cert_executor': executor}
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_api_resources(api, create_api_models(api), managers)
    ns = Namespace('certificates', description='certificates')
    api.add_namespace(ns)
    ns.add_resource(resources['ReissueKeyless'], '/reissue-keyless')

    @app.before_request
    def _user():
        request.current_user = {'username': 'op', 'role': 'operator'}

    return app.test_client()


def _service(domains, *, refuse=()):
    service = MagicMock()
    service.keyless_domains.return_value = list(domains)
    release = threading.Event()

    def prepare(domain, **kwargs):
        if domain in refuse:
            raise DomainOutOfScope(domain)
        return {'domain': domain}

    def issue(prepared):
        release.wait(5)
        return {'success': True}

    service.prepare_reissue.side_effect = prepare
    service.issue_reissue.side_effect = issue
    return service, release


def test_it_queues_at_most_the_limit_and_names_the_rest():
    """THE property: the pace. Twelve waiting, five asked for, five queued."""
    domains = [f'd{i:02}.example.com' for i in range(12)]
    service, release = _service(domains)
    executor = IssuanceExecutor(app=None, max_workers=2)
    try:
        response = _client(service, executor).post('/api/certificates/reissue-keyless',
                                                   json={'limit': 5})
        body = response.get_json()
        assert response.status_code == 202
        assert [q['domain'] for q in body['queued']] == domains[:5]
        assert body['remaining'] == domains[5:]
        assert 'next_step' in body
        assert all(q['status_url'] == f"/api/certificates/jobs/{q['job_id']}" for q in body['queued'])
    finally:
        release.set()
        executor.shutdown()


def test_a_full_queue_stops_the_loop_instead_of_pretending():
    domains = [f'd{i}.example.com' for i in range(6)]
    service, release = _service(domains)
    executor = IssuanceExecutor(app=None, max_workers=1, queue_limit=2)
    try:
        body = _client(service, executor).post('/api/certificates/reissue-keyless',
                                               json={'limit': 50}).get_json()
        assert len(body['queued']) == 2
        assert body['remaining'] == domains[2:]
    finally:
        release.set()
        executor.shutdown()


def test_a_refused_domain_is_reported_not_queued_and_not_left_as_remaining():
    service, release = _service(['a.example.com', 'b.example.com'], refuse={'a.example.com'})
    executor = IssuanceExecutor(app=None)
    try:
        body = _client(service, executor).post('/api/certificates/reissue-keyless', json={}).get_json()
        assert [q['domain'] for q in body['queued']] == ['b.example.com']
        assert body['refused'] == [{'domain': 'a.example.com', 'reason': 'out of scope'}]
        assert body['remaining'] == []
    finally:
        release.set()
        executor.shutdown()


def test_nothing_to_do_is_a_200_with_empty_lists():
    service, _release = _service([])
    executor = IssuanceExecutor(app=None)
    try:
        response = _client(service, executor).post('/api/certificates/reissue-keyless', json={})
        assert response.status_code == 200
        assert response.get_json() == {'queued': [], 'remaining': [], 'refused': []}
    finally:
        executor.shutdown()


def test_without_async_issuance_it_says_so():
    service, _release = _service(['a.example.com'])
    response = _client(service, None).post('/api/certificates/reissue-keyless', json={})
    assert response.status_code == 503
    assert response.get_json()['code'] == 'ASYNC_ISSUANCE_DISABLED'
    service.prepare_reissue.assert_not_called()


@pytest.mark.parametrize('raw, expected', [(None, 10), (0, 1), (-1, 1), (999, 50), ('x', 10), (7, 7)])
def test_the_limit_is_clamped(raw, expected):
    from modules.api.resources_reissue_keyless import _limit
    assert _limit({} if raw is None else {'limit': raw}) == expected
