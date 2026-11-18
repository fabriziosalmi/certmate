"""A failed renewal is kept beside the certificate, with what to check, until
a renewal replaces the certificate.

UX perception audit, 2026-11-18, P37: after a renewal failed, the detail panel
still said "Due: the next renewal run renews it" and nothing about the
failure. The certificate API had no field it could have used: the failed job
lived only in the page's memory and was gone after a reload, and the nightly
sweep's failures were never shown on the certificate at all.

Now a renewal that fails leaves `last_renewal_attempt` on the certificate,
whether it was asked for (`CertificateService.issue_renew`: the synchronous
route, the web route and the background job) or run by the nightly sweep
(`CertificateManager._renew_if_due`): when, the outcome, certbot's error and
the hint the renewal job gives. A renewal that happens removes it, and a
record about a certificate that has since been replaced is not shown. A busy
domain is not a failed renewal and leaves nothing. The browser side is
tests/test_ui_a_failed_renewal_stays_one_row.py.
"""
import datetime
import json
from collections import defaultdict
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from flask import Flask
from flask_restx import Api, marshal

from modules.api.models import create_api_models
from modules.core.cert_service import CertificateService
from modules.core.certificates import DomainOperationInProgress
from modules.core.failure_hints import PREVIOUS_KEPT
from tests.contract_world import write_certificate
from tests.test_one_certbot_failure_message import _manager, _shell
from tests.tls_support import key_pem, pem

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'
DNS_REFUSAL = ('Certbot failed to authenticate some domains (authenticator: dns-duckdns). '
               'The Certificate Authority reported these problems:\n'
               '  Domain: app.example.com\n  Type: dns\n'
               '  Detail: DNS problem: NXDOMAIN looking up TXT for _acme-challenge.app.example.com\n')


def _certificate(tmp_path):
    directory = tmp_path / DOMAIN
    write_certificate(directory, DOMAIN)
    (directory / 'metadata.json').write_text(json.dumps({
        'domain': DOMAIN, 'ca_provider': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_provider': 'duckdns'}), encoding='utf-8')
    return directory


def _due(directory):
    """A 90-day certificate with 5 days left: due for the sweep under any rule."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=85)).not_valid_after(now + datetime.timedelta(days=5))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), False)
            .sign(key, hashes.SHA256()))
    for filename, content in {'cert.pem': pem(cert), 'fullchain.pem': pem(cert), 'chain.pem': pem(cert),
                              'privkey.pem': key_pem(key)}.items():
        (directory / filename).write_bytes(content)


def _renew(mgr):
    """A renewal asked for: what the routes and the job call."""
    return CertificateService(mgr, mgr.settings_manager, MagicMock()).renew(domain=DOMAIN, force=True)


def _fail(mgr):
    with pytest.raises(RuntimeError):
        _renew(mgr)


def _sweep(mgr):
    """One certificate through the nightly sweep. The CA's renewal window is
    not asked (no network here); the certificate's 30 days are due under the
    default 30-day threshold."""
    mgr._refresh_renewal_info = lambda *args, **kwargs: None
    summary = defaultdict(int)
    renewed = mgr._renew_if_due(DOMAIN, mgr.settings_manager.load_settings(), summary)
    return renewed, summary


def test_a_failed_renewal_is_on_the_certificate_with_what_to_check(tmp_path):
    _certificate(tmp_path)
    mgr = _manager(tmp_path, _shell(1, stderr=DNS_REFUSAL))
    _fail(mgr)

    attempt = mgr.get_certificate_info(DOMAIN)['last_renewal_attempt']

    assert attempt is not None, 'a failed renewal left nothing on the certificate'
    assert attempt['outcome'] == 'failed'
    assert attempt['attempted_at'].endswith('Z'), attempt['attempted_at']
    assert 'NXDOMAIN looking up TXT' in attempt['error']
    # The hint the renewal job gives for the same error: what to check, then
    # that the certificate being served is still the previous one.
    assert 'DNS TXT record' in attempt['hint'], attempt['hint']
    assert attempt['hint'].endswith(PREVIOUS_KEPT), attempt['hint']


def test_the_certificate_api_answers_with_it(tmp_path):
    """The list route marshals its rows through the Certificate model, which
    drops a key it does not name."""
    _certificate(tmp_path)
    mgr = _manager(tmp_path, _shell(1, stderr=DNS_REFUSAL))
    _fail(mgr)
    models = create_api_models(Api(Flask(__name__)))

    row = marshal(mgr.get_certificate_info(DOMAIN), models['certificate_model'])

    assert row['last_renewal_attempt']['outcome'] == 'failed'
    assert row['last_renewal_attempt']['hint'].endswith(PREVIOUS_KEPT)


def test_a_renewal_that_happens_removes_it(tmp_path):
    directory = _certificate(tmp_path)
    mgr = _manager(tmp_path, _shell(1, stderr=DNS_REFUSAL))
    _fail(mgr)
    assert mgr.get_certificate_info(DOMAIN)['last_renewal_attempt'] is not None

    # What certbot leaves after a renewal: a new certificate in the lineage.
    write_certificate(directory / 'live' / DOMAIN, DOMAIN)
    mgr.shell_executor.set_next_result(returncode=0, stdout='Congratulations, all renewals succeeded')
    assert _renew(mgr)['renewed'] is True

    assert mgr.get_certificate_info(DOMAIN)['last_renewal_attempt'] is None
    assert not list(directory.glob('*renewal-attempt*')), 'the record of the failure is still on disk'


def test_a_record_about_the_certificate_it_replaced_is_not_shown(tmp_path):
    """A reissue or an upload replaces the certificate without a renewal: the
    failure was about the one before."""
    directory = _certificate(tmp_path)
    mgr = _manager(tmp_path, _shell(1, stderr=DNS_REFUSAL))
    _fail(mgr)

    write_certificate(directory, DOMAIN)

    assert mgr.get_certificate_info(DOMAIN)['last_renewal_attempt'] is None


def test_a_busy_domain_is_not_a_failed_renewal(tmp_path):
    _certificate(tmp_path)
    mgr = _manager(tmp_path, _shell(1, stderr=DNS_REFUSAL))
    mgr._domain_lock_timeout = lambda: 0
    lock = mgr._get_domain_lock(DOMAIN)
    lock.acquire()
    try:
        with pytest.raises(DomainOperationInProgress):
            _renew(mgr)
    finally:
        lock.release()

    assert mgr.get_certificate_info(DOMAIN)['last_renewal_attempt'] is None


def test_a_renewal_the_sweep_failed_is_kept_too(tmp_path):
    """Nobody watched this one: the record is the only place it shows."""
    _due(_certificate(tmp_path))
    mgr = _manager(tmp_path, _shell(1, stderr=DNS_REFUSAL))

    renewed, summary = _sweep(mgr)

    assert (renewed, summary['failed']) == (False, 1), summary
    attempt = mgr.get_certificate_info(DOMAIN)['last_renewal_attempt']
    assert attempt is not None, 'the sweep failed a renewal and left nothing on the certificate'
    assert attempt['hint'].endswith(PREVIOUS_KEPT), attempt['hint']


def test_a_renewal_the_sweep_makes_removes_it(tmp_path):
    directory = _certificate(tmp_path)
    _due(directory)
    mgr = _manager(tmp_path, _shell(1, stderr=DNS_REFUSAL))
    _sweep(mgr)
    assert mgr.get_certificate_info(DOMAIN)['last_renewal_attempt'] is not None

    write_certificate(directory / 'live' / DOMAIN, DOMAIN)
    mgr.shell_executor.set_next_result(returncode=0, stdout='Congratulations, all renewals succeeded')
    renewed, summary = _sweep(mgr)

    assert renewed is True, summary
    assert not list(directory.glob('*renewal-attempt*')), 'the record of the failure is still on disk'


def test_a_certificate_never_renewed_has_none(tmp_path):
    """CONTROL: the field is there, and null, for a certificate with no failed
    renewal."""
    _certificate(tmp_path)
    mgr = _manager(tmp_path, _shell(0))

    info = mgr.get_certificate_info(DOMAIN)

    assert 'last_renewal_attempt' in info
    assert info['last_renewal_attempt'] is None
