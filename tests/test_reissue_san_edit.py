"""
Pins for #267: edit a certificate's configuration (extend/drop SANs) and
reissue in place, instead of delete + recreate.

The invariants that make the feature safe:

1. replace=True bypasses ONLY the already-exists guard and adds
   --renew-with-new-domains, so certbot deterministically replaces the
   lineage's domain set (expand and shrink) under the same --cert-name.
2. Key-shape amnesia guard: metadata does not record the key shape, so a
   reissue without explicit key options must NOT forward the global
   default_key_* settings as flags — no flags means certbot keeps the
   lineage key. An explicit option is a deliberate re-key.
3. A failed reissue leaves the served certificate and its metadata
   untouched (certbot writes into live/; the flat files are only copied
   after success).
4. prepare_reissue inherits unspecified config from the certificate's
   metadata (the DNS-alias re-typing pain in the issue), with explicit
   semantics: None=keep, ''=clear alias, []=drop all SANs.
"""
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from modules.core.cert_jobs import IssuanceExecutor
from modules.core.cert_service import CertificateService, DomainOutOfScope
from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.duckdns.org'


def _fake_issuance(shell, tmp_path, domain):
    from modules.core.constants import CERTIFICATE_FILES

    original_run = shell.run

    def run(cmd, **kwargs):
        result = original_run(cmd, **kwargs)
        if result.returncode == 0:
            live_dir = tmp_path / domain / 'live' / domain
            live_dir.mkdir(parents=True, exist_ok=True)
            for cert_file in CERTIFICATE_FILES:
                (live_dir / cert_file).write_bytes(b'new-pem-bytes\n')
        return result

    shell.run = run
    return shell


def _manager(tmp_path, shell, settings=None):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = settings or {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1},
        'default_key_type': 'rsa',
        'default_key_size': 2048,
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'

    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        {'api_token': 'duck-token'}, 'default'
    )

    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=None,
        shell_executor=shell,
    )


def _seed_existing_cert(tmp_path, domain=DOMAIN, metadata=None):
    domain_dir = tmp_path / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / 'cert.pem').write_bytes(b'old-pem-bytes\n')
    meta = metadata or {
        'domain': domain,
        'san_domains': ['api.example.duckdns.org'],
        'dns_provider': 'duckdns',
        'challenge_type': 'dns-01',
        'account_id': 'default',
        'ca_provider': 'letsencrypt',
        'email': 'a@b.it',
    }
    (domain_dir / 'metadata.json').write_text(json.dumps(meta))
    return meta


def _create(mgr, **kwargs):
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        return mgr.create_certificate(
            domain=DOMAIN, email='a@b.it', dns_provider='duckdns', **kwargs
        )


# ---------------------------------------------------------------------------
# 1. Manager: guard bypass + command shape
# ---------------------------------------------------------------------------

def test_create_without_replace_still_conflicts(tmp_path):
    _seed_existing_cert(tmp_path)
    mgr = _manager(tmp_path, MockShellExecutor())
    with pytest.raises(FileExistsError):
        _create(mgr)


def test_replace_bypasses_guard_and_pins_lineage_update_flags(tmp_path):
    _seed_existing_cert(tmp_path)
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)

    result = _create(mgr, replace=True,
                     san_domains=['api.example.duckdns.org', 'new.example.duckdns.org'])

    assert result['success'] is True
    cmd = shell.commands_executed[0].split()
    assert '--renew-with-new-domains' in cmd
    assert '--force-renewal' in cmd
    assert cmd[cmd.index('--cert-name') + 1] == DOMAIN
    # Full replacement -d set: primary + both SANs.
    d_values = [cmd[i + 1] for i, part in enumerate(cmd) if part == '-d']
    assert d_values == [DOMAIN, 'api.example.duckdns.org', 'new.example.duckdns.org']


def test_unchanged_set_reissue_still_forces_issuance(tmp_path):
    """Adversarial-review critical: with an UNCHANGED -d set certbot ignores
    --renew-with-new-domains, hits the identical-cert prompt and exits 0
    WITHOUT issuing outside the renewal window — and the pipeline would then
    rewrite metadata that was never applied. --force-renewal is what makes a
    config-only reissue (CA switch, provider change, same-type re-key)
    actually issue."""
    _seed_existing_cert(tmp_path)
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)

    # Same SAN set as the seeded metadata: a pure config-only reissue.
    _create(mgr, replace=True, san_domains=['api.example.duckdns.org'])

    cmd = shell.commands_executed[0].split()
    assert '--force-renewal' in cmd


# ---------------------------------------------------------------------------
# 2. Key-shape amnesia guard
# ---------------------------------------------------------------------------

def test_reissue_omits_key_flags_despite_settings_defaults(tmp_path):
    _seed_existing_cert(tmp_path)
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)

    _create(mgr, replace=True)

    cmd = shell.commands_executed[0].split()
    assert '--key-type' not in cmd, (
        'reissue forwarded the global key defaults - this silently '
        're-keys the lineage'
    )


def test_plain_create_still_applies_key_defaults(tmp_path):
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)

    _create(mgr)

    cmd = shell.commands_executed[0].split()
    assert cmd[cmd.index('--key-type') + 1] == 'rsa'


def test_reissue_explicit_key_options_rekey(tmp_path):
    _seed_existing_cert(tmp_path)
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)

    _create(mgr, replace=True, key_type='ecdsa', elliptic_curve='secp384r1')

    cmd = shell.commands_executed[0].split()
    assert cmd[cmd.index('--key-type') + 1] == 'ecdsa'
    assert cmd[cmd.index('--elliptic-curve') + 1] == 'secp384r1'


# ---------------------------------------------------------------------------
# 3. Failure leaves the old certificate untouched
# ---------------------------------------------------------------------------

def test_failed_reissue_preserves_old_cert_and_metadata(tmp_path):
    original_meta = _seed_existing_cert(tmp_path)
    shell = MockShellExecutor()
    shell.set_next_result(returncode=1, stderr='boom')
    mgr = _manager(tmp_path, shell)

    with pytest.raises(RuntimeError):
        _create(mgr, replace=True, san_domains=['new.example.duckdns.org'])

    assert (tmp_path / DOMAIN / 'cert.pem').read_bytes() == b'old-pem-bytes\n'
    assert json.loads((tmp_path / DOMAIN / 'metadata.json').read_text()) == original_meta


def test_successful_reissue_rewrites_files_and_metadata(tmp_path):
    _seed_existing_cert(tmp_path)
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)

    _create(mgr, replace=True, san_domains=['new.example.duckdns.org'])

    assert (tmp_path / DOMAIN / 'cert.pem').read_bytes() == b'new-pem-bytes\n'
    metadata = json.loads((tmp_path / DOMAIN / 'metadata.json').read_text())
    assert metadata['san_domains'] == ['new.example.duckdns.org']
    assert metadata['ca_provider'] == 'letsencrypt'


# ---------------------------------------------------------------------------
# 4. Service: inheritance and explicit semantics
# ---------------------------------------------------------------------------

def _service(tmp_path, mgr=None, scope_ok=True):
    mgr = mgr or _manager(tmp_path, MockShellExecutor())
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'email': 'a@b.it',
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_provider': 'duckdns',
    }
    auth = MagicMock()
    auth.user_can_access_domain.return_value = scope_ok
    return CertificateService(mgr, settings_mgr, auth), mgr


def test_prepare_reissue_missing_cert_raises_not_found(tmp_path):
    service, _ = _service(tmp_path)
    with pytest.raises(FileNotFoundError):
        service.prepare_reissue(domain=DOMAIN)


def test_prepare_reissue_inherits_issued_config(tmp_path):
    _seed_existing_cert(tmp_path, metadata={
        'domain': DOMAIN,
        'san_domains': ['api.example.duckdns.org'],
        'dns_provider': 'cloudflare',
        'challenge_type': 'dns-01',
        'account_id': 'prod',
        'ca_provider': 'letsencrypt_staging',
        'domain_alias': 'validation.example.net',
        'alias_dns_provider': 'cloudflare',
    })
    service, _ = _service(tmp_path)

    prepared = service.prepare_reissue(
        domain=DOMAIN,
        san_domains=['api.example.duckdns.org', 'new.example.duckdns.org'],
    )

    assert prepared['dns_provider'] == 'cloudflare'
    assert prepared['account_id'] == 'prod'
    assert prepared['ca_provider'] == 'letsencrypt_staging'
    assert prepared['domain_alias'] == 'validation.example.net'
    assert prepared['san_domains'] == ['api.example.duckdns.org', 'new.example.duckdns.org']
    # Key shape deliberately NOT inherited: no flags = certbot keeps it.
    assert prepared['key_type'] is None
    assert prepared['key_size'] is None
    assert prepared['elliptic_curve'] is None


def test_prepare_reissue_none_keeps_sans_empty_list_drops_them(tmp_path):
    _seed_existing_cert(tmp_path)
    service, _ = _service(tmp_path)

    kept = service.prepare_reissue(domain=DOMAIN)
    assert kept['san_domains'] == ['api.example.duckdns.org']

    dropped = service.prepare_reissue(domain=DOMAIN, san_domains=[])
    assert dropped['san_domains'] == []


def test_prepare_reissue_empty_string_clears_alias(tmp_path):
    _seed_existing_cert(tmp_path, metadata={
        'domain': DOMAIN,
        'san_domains': [],
        'dns_provider': 'duckdns',
        'domain_alias': 'validation.example.net',
    })
    service, _ = _service(tmp_path)

    kept = service.prepare_reissue(domain=DOMAIN)
    assert kept['domain_alias'] == 'validation.example.net'

    cleared = service.prepare_reissue(domain=DOMAIN, domain_alias='')
    assert cleared['domain_alias'] is None


def test_prepare_reissue_scope_covers_inherited_sans(tmp_path):
    """A scoped key must not keep another tenant's SAN alive through
    inheritance: the FINAL set is scope-checked, kept SANs included.

    The mock allows the PRIMARY and denies only the inherited SAN — a
    blanket deny would pass on the primary check alone and the test
    would still pass with the SAN scope loop deleted (mutation-verified
    by the adversarial review)."""
    _seed_existing_cert(tmp_path)
    service, _ = _service(tmp_path)
    service._auth.user_can_access_domain.side_effect = (
        lambda user, d: d == DOMAIN
    )
    with pytest.raises(DomainOutOfScope) as exc:
        service.prepare_reissue(domain=DOMAIN)
    assert exc.value.domain == 'api.example.duckdns.org'


def test_prepare_reissue_inherits_alias_dns_provider(tmp_path):
    """The alias zone may live with a DIFFERENT provider than the primary
    (set via PATCH, issue #129; renewals honour it). The reissue must
    inherit it and run the alias hook with that account, or it would
    attempt the challenge with the wrong provider."""
    _seed_existing_cert(tmp_path, metadata={
        'domain': DOMAIN,
        'san_domains': [],
        'dns_provider': 'duckdns',
        'domain_alias': 'validation.example.net',
        'alias_dns_provider': 'cloudflare',
    })
    service, _ = _service(tmp_path)

    prepared = service.prepare_reissue(domain=DOMAIN)
    assert prepared['alias_dns_provider'] == 'cloudflare'

    # Clearing the alias also clears the alias provider.
    cleared = service.prepare_reissue(domain=DOMAIN, domain_alias='')
    assert cleared['domain_alias'] is None
    assert cleared['alias_dns_provider'] is None


def test_reissue_alias_hook_runs_with_alias_provider(tmp_path):
    _seed_existing_cert(tmp_path, metadata={
        'domain': DOMAIN,
        'san_domains': [],
        'dns_provider': 'cloudflare',
        'domain_alias': 'validation.example.net',
        'alias_dns_provider': 'route53',
    })
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)

    def per_provider_config(provider, account_id=None, settings=None):
        return ({'provider': provider}, 'default')

    mgr.dns_manager.get_dns_provider_account_config.side_effect = per_provider_config

    captured = {}

    def capture_hook(provider, config, alias, propagation):
        captured['provider'] = provider
        captured['config'] = config
        return None  # no credentials file to clean up

    with patch.object(CertificateManager, '_create_dns_alias_hook_config',
                      side_effect=capture_hook), \
         patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        mgr.create_certificate(
            domain=DOMAIN, email='a@b.it', dns_provider='cloudflare',
            domain_alias='validation.example.net',
            alias_dns_provider='route53', replace=True,
        )

    assert captured['provider'] == 'route53'
    assert captured['config'] == {'provider': 'route53'}
    metadata = json.loads((tmp_path / DOMAIN / 'metadata.json').read_text())
    assert metadata['alias_dns_provider'] == 'route53'


def test_failed_reissue_never_touches_storage_backend(tmp_path):
    """The release notes claim storage is untouched on failure; pin it
    instead of relying on code order alone."""
    _seed_existing_cert(tmp_path)
    shell = MockShellExecutor()
    shell.set_next_result(returncode=1, stderr='boom')
    mgr = _manager(tmp_path, shell)
    mgr.storage_manager = MagicMock()

    with pytest.raises(RuntimeError), \
         patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        mgr.create_certificate(
            domain=DOMAIN, email='a@b.it', dns_provider='duckdns', replace=True,
        )

    mgr.storage_manager.store_certificate.assert_not_called()


def test_issue_reissue_end_to_end_replaces(tmp_path):
    _seed_existing_cert(tmp_path)
    shell = _fake_issuance(MockShellExecutor(), tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    mgr = _manager(tmp_path, shell)
    service, _ = _service(tmp_path, mgr=mgr)

    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = service.issue_reissue(service.prepare_reissue(
            domain=DOMAIN, san_domains=['new.example.duckdns.org'],
        ))

    assert result['success'] is True
    cmd = shell.commands_executed[0].split()
    assert '--renew-with-new-domains' in cmd


# ---------------------------------------------------------------------------
# 5. Async job kind
# ---------------------------------------------------------------------------

def _wait_terminal(executor, job_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = executor.get(job_id)
        if job and job['status'] in ('succeeded', 'failed'):
            return job
        time.sleep(0.02)
    raise AssertionError('job did not reach a terminal state')


def test_reissue_job_publishes_renewed_event():
    bus = MagicMock()
    executor = IssuanceExecutor(app=None, event_bus=bus)
    job_id = executor.submit('reissue', DOMAIN, lambda: {'success': True})
    job = _wait_terminal(executor, job_id)
    assert job['status'] == 'succeeded'
    bus.publish.assert_called_once_with('certificate_renewed', {'domain': DOMAIN})
    executor.shutdown()


def test_reissue_job_failure_publishes_failed_event():
    bus = MagicMock()
    executor = IssuanceExecutor(app=None, event_bus=bus)

    def boom():
        raise RuntimeError('certbot failed')

    job_id = executor.submit('reissue', DOMAIN, boom)
    job = _wait_terminal(executor, job_id)
    assert job['status'] == 'failed'
    bus.publish.assert_called_once_with(
        'certificate_failed', {'domain': DOMAIN, 'error': 'certbot failed'})
    executor.shutdown()
