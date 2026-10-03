"""ARI end to end: a real CA's window drives a real renewal (#962).

Everything below is real except one thing. A certificate is issued by Let's
Encrypt STAGING through Cloudflare DNS-01, the renewal sweep asks staging's
`renewalInfo` endpoint about it, keeps the answer, and — once the ARI client's
clock is placed at the instant the sweep chose inside that window — renews it
through the real certbot, against the real CA.

**The one thing that is not real is that clock**, and only in the ARI client.
A fresh certificate's window opens weeks from now; waiting for it is not a
test. Since #393 the sweep takes its decision on that clock (the wall clock in
production); certbot and the CA run on the wall clock, which is the point:
certbot sees a certificate with most of its life left and, asked without
`--force-renewal`, answers "not yet due". That is the defect this was written
to catch. The unit tests model certbot's gate; this one runs it.

**Why in-process rather than against the container** like the other e2e
files: the container can only be driven over HTTP, and moving the ARI clock
there would need a test-only hook in production code. Here the clock is
injected exactly as the unit tests inject it, and nothing else is replaced.

Requires CLOUDFLARE_API_TOKEN and CERTMATE_TEST_DOMAIN (a zone the token can
edit). Issuance is pinned to staging and the issuer is read off the leaf.
"""
import json
import os
import secrets
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

from modules.core import ari
from tests.e2e_support import TEST_EMAIL, assert_staging_issuer

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

STAGING_DIRECTORY = 'https://acme-staging-v02.api.letsencrypt.org/directory'
BASE_DOMAIN = os.environ.get('CERTMATE_TEST_DOMAIN', 'gpfree.org')
TEST_DOMAIN = f'ari-e2e-{uuid.uuid4().hex[:8]}.{BASE_DOMAIN}'
ACCOUNT_ID = 'ari-e2e'


def _utc_naive(text):
    return datetime.fromisoformat(text.replace('Z', '+00:00')).astimezone(
        timezone.utc).replace(tzinfo=None)


@pytest.fixture(scope='module')
def instance(tmp_path_factory, cloudflare_token):
    """A real CertMate, in this process, pinned to Let's Encrypt staging."""
    tmp = tmp_path_factory.mktemp('ari-e2e')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('API_BEARER_TOKEN', token)
        from modules.factory import create_app
        _, container = create_app()
        managers = container.managers

        settings_manager = managers['settings']
        settings = settings_manager.load_settings()
        settings.update({
            'email': TEST_EMAIL,
            'default_ca': 'letsencrypt_staging',
            # Non-empty on purpose: an EMPTY staging entry aliases back to
            # production in ca_manager.get_ca_config (see e2e_support).
            'ca_providers': {
                'letsencrypt': {'email': TEST_EMAIL},
                'letsencrypt_staging': {'email': TEST_EMAIL},
            },
            'dns_provider': 'cloudflare',
            'domains': [{'domain': TEST_DOMAIN, 'dns_provider': 'cloudflare',
                         'account_id': ACCOUNT_ID, 'auto_renew': True}],
        })
        assert settings_manager.save_settings(settings, 'ari-e2e') is not False
        managers['dns'].add_account(
            ACCOUNT_ID, 'cloudflare', {'api_token': cloudflare_token})
        yield managers['certificates']


def _leaf(manager):
    pem = (manager.cert_dir / TEST_DOMAIN / 'cert.pem').read_bytes()
    return pem, x509.load_pem_x509_certificate(pem)


def _record(manager):
    path = manager.cert_dir / TEST_DOMAIN / 'renewal-info.json'
    return json.loads(path.read_text())


def test_01_issue_on_staging(instance):
    result = instance.create_certificate(
        TEST_DOMAIN, TEST_EMAIL, 'cloudflare', account_id=ACCOUNT_ID,
        ca_provider='letsencrypt_staging')
    assert result, result
    pem, _ = _leaf(instance)
    print('issuer:', assert_staging_issuer(pem.decode()))

    # Notes and tags an operator attaches after issuing (#1043). Written the way
    # the PATCH route writes them; the renewal in test_03 is what has to keep
    # them, through the real certbot run that carries a pre-renewal snapshot of
    # this file across the whole CA exchange.
    metadata = instance._load_metadata(TEST_DOMAIN)
    metadata['notes'] = 'kept across a real renewal'
    metadata['tags'] = ['e2e', 'loadbalancer']
    instance.write_metadata(TEST_DOMAIN, metadata)


def test_02_the_sweep_records_what_staging_says(instance):
    """No renewal yet — the window is in the future — but the answer is
    kept, and it is the CA's answer rather than one CertMate made up."""
    summary = instance.check_renewals()
    assert summary['renewed'] == 0, summary
    assert summary['failed'] == 0, summary

    _, cert = _leaf(instance)
    record = _record(instance)
    cert_id = ari.certificate_id(cert)
    assert record['status'] == ari.STATUS_WINDOW, record
    assert record['cert_id'] == cert_id

    # Asked of staging directly, bypassing CertMate's client entirely.
    with urllib.request.urlopen(STAGING_DIRECTORY, timeout=15) as r:
        base = json.load(r)['renewalInfo']
    with urllib.request.urlopen(f'{base.rstrip("/")}/{cert_id}',
                                timeout=15) as r:
        direct = json.load(r)['suggestedWindow']
    assert _utc_naive(record['window_start']) == _utc_naive(direct['start'])
    assert _utc_naive(record['window_end']) == _utc_naive(direct['end'])

    renew_at = _utc_naive(record['renew_at'])
    assert _utc_naive(direct['start']) <= renew_at <= _utc_naive(direct['end'])
    not_after = cert.not_valid_after_utc.replace(tzinfo=None)
    days_left = (not_after - datetime.utcnow()).days
    print(f'window {direct["start"]} .. {direct["end"]}, renew_at '
          f'{record["renew_at"]}, {days_left} days left')

    # And what the API returns is that record.
    info = instance.get_certificate_info(TEST_DOMAIN, use_cache=False)
    assert info['renewal_info']['renew_at'] == record['renew_at']


def test_03_the_window_drives_a_real_renewal(instance):
    """THE test. The threshold says no; staging's window, read at the instant
    the sweep chose, says yes; the renewal has to reach the CA."""
    pem_before, cert_before = _leaf(instance)
    renew_at = _utc_naive(_record(instance)['renew_at'])
    days_left = (cert_before.not_valid_after_utc.replace(tzinfo=None)
                 - datetime.utcnow()).days
    assert days_left > 30, (
        f'{days_left} days left: certbot would renew this without being '
        f'forced, so this run cannot tell the fix from its absence')

    instance._ari_client = ari.RenewalInfoClient(clock=lambda: renew_at)
    summary = instance.check_renewals()

    assert summary['failed'] == 0, summary
    assert summary['skipped_not_due'] == 0, (
        'certbot answered "not yet due" to a renewal the CA asked for', summary)
    assert summary['renewed'] == 1, summary
    # Attributed to the CA only when its instant comes before the threshold's (#393). Since #393
    # the sweep decides on one clock, this one, and staging's window for a 90-day certificate
    # sits around 30 days before expiry, and the instant it names can fall on either side of the
    # threshold's point (the production window recorded in tests/test_the_ca_says_when_to_renew.py,
    # 2 to 4 November for a certificate expiring 3 December, contains it). After it, the threshold
    # also calls the certificate due at that instant, so the renewal is not one the CA brought
    # forward. Before #393 the threshold ran on the wall clock and this was always 1. Either
    # way the renewal is forced and reaches the CA, which is what the assertions around this
    # one hold.
    planned = cert_before.not_valid_after_utc.replace(tzinfo=None) - timedelta(days=30)
    assert summary['ari_advanced'] == (1 if renew_at < planned else 0), (renew_at, planned, summary)

    pem_after, cert_after = _leaf(instance)
    assert cert_after.serial_number != cert_before.serial_number
    assert_staging_issuer(pem_after.decode())
    kept = instance._load_metadata(TEST_DOMAIN)
    assert kept.get('notes') == 'kept across a real renewal', kept
    assert kept.get('tags') == ['e2e', 'loadbalancer'], kept
    print('renewed:', hex(cert_before.serial_number), '->',
          hex(cert_after.serial_number))


def test_04_the_old_window_is_not_shown_for_the_new_certificate(instance):
    info = instance.get_certificate_info(TEST_DOMAIN, use_cache=False)
    assert info['renewal_info'] is None, info['renewal_info']


def test_05_a_webhook_target_delivers_the_real_renewed_certificate_and_its_key(instance, tmp_path, monkeypatch):
    """The two things no synthetic certificate can show about the webhook target (#218).

    What certbot actually leaves on disk: the real chain files, and a real
    privkey.pem in whatever PEM form certbot wrote it. The target converts that to
    PKCS#8 and to the traditional form; a conversion tested only on keys this
    project generated could be wrong for the key certbot makes. So: a real
    certificate, delivered over real TLS to a local receiver pinned by
    fingerprint, and the key that arrives must be the key of the certificate that
    arrives.
    """
    from unittest.mock import MagicMock

    from cryptography.hazmat.primitives import serialization

    from modules.core import pinned_https
    from modules.core.deployer import DeployManager
    from modules.core.shell import MockShellExecutor
    from tests.tls_support import TLSServer, handler, key_pem, make_cert, pem

    cert_dir = instance.cert_dir / TEST_DOMAIN
    recv_cert, recv_key = make_cert('receiver.internal', san_dns=['receiver.internal'])
    crt, key = tmp_path / 'recv.crt', tmp_path / 'recv.key'
    crt.write_bytes(pem(recv_cert))
    key.write_bytes(key_pem(recv_key))
    pin = __import__('hashlib').sha256(recv_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    seen = []
    server = TLSServer(str(crt), str(key), handler(record=seen))
    monkeypatch.setattr(pinned_https, 'resolve', lambda host, port, allow: '127.0.0.1')

    template = ('{"domain": "{{domain}}", "fullchain": "{{fullchain}}", "chain": "{{chain}}", '
                '"pkcs8": "{{privkey_pkcs8}}", "traditional": "{{privkey_traditional}}"}')
    target = {'type': 'webhook', 'id': 'e2e', 'name': 'e2e receiver', 'enabled': True,
              'domains': [TEST_DOMAIN],
              'delivery_consent': {'host': 'receiver.internal', 'by': 'e2e', 'at': 'now'},
              'config': {'url': f'https://receiver.internal:{server.port}/deliver',
                         'payload_template': template, 'pin_sha256': pin}}
    manager = DeployManager(settings_manager=MagicMock(), shell_executor=MockShellExecutor(),
                            audit_logger=MagicMock(), event_bus=MagicMock(),
                            cert_dir=instance.cert_dir, data_dir=str(tmp_path / 'data'))
    manager._log_history = MagicMock()
    try:
        results = manager._execute_targets(TEST_DOMAIN, 'renewed', {'enabled': True, 'targets': [target]},
                                           targets=[target])
    finally:
        server.close()

    assert results and results[0]['success'] is True, results
    body = json.loads(seen[0]['body'])
    assert body['fullchain'] == (cert_dir / 'fullchain.pem').read_text()
    assert body['chain'] == (cert_dir / 'chain.pem').read_text()
    leaf = x509.load_pem_x509_certificate(body['fullchain'].encode())
    public = leaf.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    for shape, marker in (('pkcs8', '-----BEGIN PRIVATE KEY-----'),):
        delivered = serialization.load_pem_private_key(body[shape].encode(), None)
        assert body[shape].startswith(marker)
        assert delivered.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public, (
            'the key that arrived is not the key of the certificate that arrived')
    traditional = serialization.load_pem_private_key(body['traditional'].encode(), None)
    assert traditional.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public
    print('certbot wrote its key as:', (cert_dir / 'privkey.pem').read_text().splitlines()[0],
          '-> delivered as', body['pkcs8'].splitlines()[0], 'and', body['traditional'].splitlines()[0])
