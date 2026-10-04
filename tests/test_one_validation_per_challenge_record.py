"""One DNS-01 validation at a time per challenge record (#1147, item 6).

`example.com` and `*.example.com` are two certificates with two per-domain
locks, and both answer their DNS-01 challenge at `_acme-challenge.example.com`.
With CERTMATE_ISSUANCE_WORKERS at its default of 2 they can run at once, and
certbot-dns-route53 keeps per process the values it added and UPSERTs the
record set with only those: the second run replaces the first one's value. So
the certbot run holds a lock per challenge record (modules/core/challenge_locks.py).

The integration tests drive the real CertificateManager.create_certificate,
with a certbot stand-in that stays "running" until released, so the second
issuance meets the first one's lock exactly where a real one would.
"""
import threading
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager, ChallengeRecordInUse, DomainOperationInProgress
from modules.core.challenge_locks import ChallengeLocks, ChallengeRecordBusy, challenge_record_names
from modules.core.shell import MockShellExecutor
from tests.test_csr_only_issuance import _csr

pytestmark = [pytest.mark.unit]


# --- which records an issuance writes --------------------------------------

def test_a_wildcard_and_its_apex_write_the_same_record():
    assert challenge_record_names(['*.example.com']) == ['_acme-challenge.example.com']
    assert challenge_record_names(['example.com']) == ['_acme-challenge.example.com']


def test_every_name_of_a_certificate_counts():
    assert challenge_record_names(['example.com', 'www.example.com', '*.example.com']) == [
        '_acme-challenge.example.com', '_acme-challenge.www.example.com']


def test_an_alias_answers_every_challenge_at_one_record():
    assert challenge_record_names(['a.com', 'b.org'], domain_alias='validation.example.net') == [
        '_acme-challenge.validation.example.net']


@pytest.mark.parametrize('challenge_type', ['http-01', 'prevalidated'])
def test_challenges_that_write_no_dns_record_take_no_lock(challenge_type):
    assert challenge_record_names(['example.com'], challenge_type=challenge_type) == []


# --- the locks ----------------------------------------------------------------

def test_an_overlapping_set_is_refused_while_the_first_is_held():
    locks = ChallengeLocks()
    with locks.hold(['_acme-challenge.example.com'], timeout=1):
        with pytest.raises(ChallengeRecordBusy, match=r'_acme-challenge\.example\.com'):
            with locks.hold(['_acme-challenge.example.com', '_acme-challenge.www.example.com'],
                            timeout=0.05):
                pass
    # Released after the refusal: the second record was not left held.
    with locks.hold(['_acme-challenge.www.example.com'], timeout=0.05):
        pass


def test_sets_that_do_not_overlap_are_held_at_once():
    locks = ChallengeLocks()
    with locks.hold(['_acme-challenge.example.com'], timeout=1):
        with locks.hold(['_acme-challenge.example.org'], timeout=0.05):
            pass


def test_the_locks_are_taken_in_one_order_whatever_order_they_are_asked_in():
    """Two runs needing {a, b} and {b, a} must take them in the same order, or
    each can hold one and wait for the other. Checked on the order itself: a
    two-thread race finds the interleaving only by luck (200 rounds of it
    passed with the ordering removed)."""
    asked = []

    class Recording(ChallengeLocks):
        def _lock(self, name):
            asked.append(name)
            return super()._lock(name)

    locks = Recording()
    with locks.hold(['_acme-challenge.z.com', '_acme-challenge.a.com', '_acme-challenge.m.com'],
                    timeout=1):
        pass
    assert asked == sorted(asked)


# --- through the real create_certificate --------------------------------------

def _manager(tmp_path):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01', 'dns_propagation_seconds': {}}
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = ({'api_token': 'x' * 40}, 'default')
    shell = MockShellExecutor()
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings_mgr,
                                 dns_manager=dns_mgr, storage_manager=None, ca_manager=None,
                                 shell_executor=shell)
    return manager, shell


@pytest.fixture
def first_issuance_running(tmp_path, monkeypatch):
    """Start an issuance for example.com whose certbot run does not return
    until the test says so. Yields (manager, release)."""
    monkeypatch.setenv('CERTMATE_DOMAIN_LOCK_TIMEOUT', '0.2')
    manager, shell = _manager(tmp_path)
    entered, release = threading.Event(), threading.Event()
    real_run = shell.run

    def run(cmd, **kwargs):
        # The first certbot run is the fixture's own issuance: it is started
        # before anything else, and the test waits for it to get here.
        if not entered.is_set():
            entered.set()
            release.wait(10)
        return real_run(cmd, **kwargs)

    shell.run = run
    outcome = {}

    def first():
        try:
            manager.create_certificate(domain='example.com', email='a@example.com',
                                       dns_provider='cloudflare',
                                       csr_pem=_csr('example.com', ('example.com',)))
        except Exception as exc:  # the stand-in writes no certificate
            outcome['error'] = exc

    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        thread = threading.Thread(target=first)
        thread.start()
        assert entered.wait(10), 'the first issuance never reached certbot'
        try:
            yield manager, release
        finally:
            release.set()
            thread.join(10)


def test_a_wildcard_is_refused_while_its_apex_is_validating(first_issuance_running):
    manager, _ = first_issuance_running
    with pytest.raises(ChallengeRecordInUse) as refused:
        manager.create_certificate(domain='*.example.com', email='a@example.com',
                                   dns_provider='cloudflare',
                                   csr_pem=_csr('*.example.com', ('*.example.com',)))
    assert refused.value.record == '_acme-challenge.example.com'
    assert isinstance(refused.value, DomainOperationInProgress), (
        'callers that answer 409 or retry on DomainOperationInProgress must treat this the same')


def test_an_unrelated_certificate_still_runs_alongside(first_issuance_running):
    """CONTROL: the lock is per record, not a global queue."""
    manager, _ = first_issuance_running
    try:
        manager.create_certificate(domain='other.org', email='a@example.com',
                                   dns_provider='cloudflare',
                                   csr_pem=_csr('other.org', ('other.org',)))
    except ChallengeRecordInUse:
        pytest.fail('a certificate with no record in common was refused')
    except Exception:  # later failures of the stand-in are not the point
        pass


def test_a_renewal_is_refused_while_another_certificate_validates_its_record(
        first_issuance_running, tmp_path):
    """The renewal path holds the records too. A lineage for *.example.com
    (cert.pem, metadata, renewal conf) renews while example.com is still in
    its certbot run: same record, so refused."""
    import json
    manager, _ = first_issuance_running
    wildcard = tmp_path / '*.example.com'
    (wildcard / 'renewal').mkdir(parents=True)
    (wildcard / 'cert.pem').write_text('certificate')
    (wildcard / 'metadata.json').write_text(json.dumps(
        {'domain': '*.example.com', 'dns_provider': 'cloudflare', 'challenge_type': 'dns-01'}))
    (wildcard / 'renewal' / '*.example.com.conf').write_text(
        'version = 5.8.0\n[renewalparams]\nauthenticator = dns-cloudflare\n')
    with patch.object(CertificateManager, '_renewal_happened', return_value=True), \
            patch.object(CertificateManager, '_publish_renewed_certificate', return_value=None), \
            pytest.raises(ChallengeRecordInUse) as refused:
        manager.renew_certificate('*.example.com', force=True)
    assert refused.value.record == '_acme-challenge.example.com'


def test_the_api_answers_409_naming_the_record_and_promising_no_retry(tmp_path):
    """Through the real application: the refusal reaches the caller as the 409
    every busy certificate gets, names the record, and does not say it will be
    retried, because for an API request nothing retries it."""
    import os
    import secrets
    import time

    from tests.contract_world import Certbot, certbot_standing_in

    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as env:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir()
            env.setenv(var, str(tmp_path / sub))
        env.setenv('FLASK_ENV', 'testing')
        env.setenv('TESTING', 'true')
        env.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()
        settings = container.managers['settings']
        current = settings.load_settings()
        current['email'] = 'ops@example.com'
        settings.save_settings(current)
        assert container.managers['dns'].add_account('default', 'cloudflare', {'api_token': 'w' * 24})
        headers = {'Authorization': f'Bearer {token}'}
        certbot = Certbot()
        with certbot_standing_in(certbot):
            gate = certbot.hold_next()
            first = {}
            apex = threading.Thread(target=lambda: first.update(response=app.test_client().post(
                '/api/certificates/create', headers=headers,
                json={'domain': 'example.com', 'dns_provider': 'cloudflare'})))
            apex.start()
            try:
                deadline = time.monotonic() + 20
                while not certbot.commands:
                    assert time.monotonic() < deadline, 'the first issuance never reached certbot'
                    time.sleep(0.02)
                refused = app.test_client().post(
                    '/api/certificates/create', headers=headers,
                    json={'domain': '*.example.com', 'dns_provider': 'cloudflare'})
            finally:
                gate.set()
                apex.join(30)
        assert refused.status_code == 409, refused.get_json()
        body = refused.get_json()
        assert body['code'] == 'DOMAIN_OPERATION_IN_PROGRESS'
        assert '_acme-challenge.example.com' in body['error']
        assert 'retried' not in body['error']
        assert first['response'].status_code == 201, first['response'].get_json()
