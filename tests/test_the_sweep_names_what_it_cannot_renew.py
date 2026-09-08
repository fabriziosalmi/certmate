"""A certificate the renewal sweep cannot see must not be passed over in silence.

Reported as #759: a certificate issued from a private CA with a 31-day lifespan
and a 30-day threshold never auto-renewed, and — the detail that matters — the
log carried **nothing at all** for that domain. Not a failure, not a skip.

The threshold arithmetic was not the cause. Reproduced against the real code,
a registered certificate with those numbers is picked up from day zero
(`days_left` 30, `30 <= 30`), and `ca_provider` never enters the decision.

The cause is that `check_renewals` iterates `settings['domains']` and nothing
else, while the rest of the application answers "which certificates exist"
differently:

- `digest.py` takes the **union** of `settings['domains']` and the certificate
  directories, so the digest reports the certificate as expiring;
- `get_certificate_info` reads the disk, so the dashboard shows it, with
  `needs_renewal: true`.

A certificate present on disk and absent from settings is therefore visible
everywhere except in the one component whose job is to renew it — and that
component said nothing, which is why the report reads as a threshold bug.

The sweep now names every such certificate and counts it in `unmanaged`. It
does **not** adopt it: renewing a certificate the operator never registered
would issue against a CA for a domain CertMate was not asked to manage, and a
background sweep is not where that decision belongs.
"""
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

LOGGER = 'modules.core.certificates'


MARKER = 'exists on disk but no settings entry'


def _reported(caplog):
    """The certificate names the reconciliation warned about, exactly.

    A set of parsed names rather than `'domain' in message`: the substring
    form passes when the name appears anywhere in the log, including in an
    unrelated renewal-failure line, so it asserts less than it looks like it
    does. CodeQL flags it too, and it is right to.
    """
    return {re.search(r"Certificate '([^']+)'", record.getMessage()).group(1)
            for record in caplog.records if MARKER in record.getMessage()}


def _leaf(domain, lifespan_days, issued_days_ago):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Private CA')])
    issued = datetime.now(timezone.utc) - timedelta(days=issued_days_ago)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(issued)
            .not_valid_after(issued + timedelta(days=lifespan_days))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


@pytest.fixture
def instance(tmp_path):
    """A CertificateManager over a real directory, with a factory for putting
    certificates on disk and, separately, into settings — because the whole
    subject of this file is the two coming apart."""
    cert_dir = tmp_path / 'certificates'
    data_dir = tmp_path / 'data'
    for directory in (cert_dir, data_dir, tmp_path / 'backups', tmp_path / 'logs'):
        directory.mkdir()

    file_ops = FileOperations(cert_dir=cert_dir, data_dir=data_dir,
                              backup_dir=tmp_path / 'backups',
                              logs_dir=tmp_path / 'logs')
    settings = SettingsManager(file_ops=file_ops,
                               settings_file=data_dir / 'settings.json')
    manager = CertificateManager(cert_dir=cert_dir, settings_manager=settings,
                                 dns_manager=MagicMock(),
                                 shell_executor=MagicMock())

    def put_on_disk(domain, *, lifespan=31, issued_days_ago=25,
                    ca_provider='private_ca'):
        directory = cert_dir / domain
        directory.mkdir()
        cert_pem, key_pem = _leaf(domain, lifespan, issued_days_ago)
        for name in ('cert.pem', 'fullchain.pem', 'chain.pem'):
            (directory / name).write_bytes(cert_pem)
        (directory / 'privkey.pem').write_bytes(key_pem)
        (directory / 'metadata.json').write_text(json.dumps(
            {'domain': domain, 'ca_provider': ca_provider,
             'dns_provider': 'cloudflare'}))

    def register(*entries, threshold=30, auto_renew=True):
        def _seed(stored):
            stored['domains'] = list(entries)
            stored['auto_renew'] = auto_renew
            stored['renewal_threshold_days'] = threshold
        settings.update(_seed, reason='test')

    manager.put_on_disk = put_on_disk
    manager.register = register
    return manager


# --- the reported symptom, and that it is not the threshold --------------

def test_a_registered_private_ca_cert_is_picked_up_from_day_zero(instance):
    """The control that redirects the diagnosis. 31-day lifespan, 30-day
    threshold: `days_left` is 30 on the day it is issued and `30 <= 30`, so a
    REGISTERED certificate renews immediately. The reported numbers do not
    produce the reported symptom."""
    instance.put_on_disk('registered.example.com', issued_days_ago=0)
    instance.register({'domain': 'registered.example.com',
                       'dns_provider': 'cloudflare'})

    info = instance.get_certificate_info(
        'registered.example.com',
        settings=instance.settings_manager.load_settings(), use_cache=False)

    assert info['days_left'] == 30
    assert info['needs_renewal'] is True


def test_an_unregistered_certificate_is_never_checked(instance):
    """The actual mechanism. The certificate exists, needs renewal, and the
    sweep visits nothing."""
    instance.put_on_disk('orphan.example.com')
    instance.register()  # nothing registered

    info = instance.get_certificate_info(
        'orphan.example.com',
        settings=instance.settings_manager.load_settings(), use_cache=False)
    summary = instance.check_renewals()

    assert info['exists'] is True and info['needs_renewal'] is True, (
        'the fixture no longer reproduces the report')
    assert summary['checked'] == 0
    assert summary['renewed'] == 0 and summary['failed'] == 0


def test_the_sweep_now_names_it(instance, caplog):
    """THE fix. Previously this ran to completion emitting one line — "Checking
    0 certificate(s)" — and the operator, reading the log for their domain,
    found nothing and concluded renewal had been attempted and lost."""
    instance.put_on_disk('orphan.example.com')
    instance.register()

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        summary = instance.check_renewals()

    assert summary['unmanaged'] == 1
    assert _reported(caplog) == {'orphan.example.com'}, (
        'the sweep counted an unmanaged certificate without saying which')
    remedy = [record.getMessage() for record in caplog.records
              if MARKER in record.getMessage()][0]
    assert 'Add Domain' in remedy, (
        'the warning does not say what to do about it')


def test_a_registered_certificate_is_not_reported_as_unmanaged(instance):
    """CONTROL. Without this, a reconciliation that named every certificate on
    every run would pass the test above and be useless."""
    instance.put_on_disk('managed.example.com')
    instance.register({'domain': 'managed.example.com',
                       'dns_provider': 'cloudflare'})

    summary = instance.check_renewals()

    assert summary['unmanaged'] == 0


def test_only_the_unregistered_one_is_named_among_several(instance, caplog):
    """The insidious shape, and the one the pre-existing startup warning misses:
    it only fires when `domains` is EMPTY, so an instance with nine registered
    certificates and one orphan was told nothing at all."""
    for name in ('a.example.com', 'b.example.com'):
        instance.put_on_disk(name)
    instance.put_on_disk('orphan.example.com')
    instance.register({'domain': 'a.example.com'}, {'domain': 'b.example.com'})

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        summary = instance.check_renewals()

    # Exactly the orphan, and nothing else. a/b appear elsewhere in this log
    # because they are genuinely due and the stub executor fails them, which
    # is the fixture and not the subject — so the comparison is against the
    # parsed set, not against the whole log.
    assert summary['unmanaged'] == 1
    assert _reported(caplog) == {'orphan.example.com'}


def test_a_certificate_switched_off_on_purpose_is_not_called_unmanaged(instance):
    """`auto_renew: false` is the supported way to stop a certificate renewing.
    Reporting it as unmanaged would turn a deliberate choice into a warning on
    every sweep, and a warning that fires on a correct configuration is one
    people learn to skip."""
    instance.put_on_disk('paused.example.com')
    instance.register({'domain': 'paused.example.com', 'auto_renew': False})

    summary = instance.check_renewals()

    assert summary['skipped_disabled'] == 1
    assert summary['unmanaged'] == 0


def test_a_hand_edited_entry_that_is_dropped_at_load_is_now_recovered(instance,
                                                                       caplog):
    """A settings entry the load path cannot read is removed before the sweep
    ever sees it — measured, for both shapes: a dict with no `domain` key and a
    bare number both come back as `domains: []` from `load_settings`.

    That makes the sweep's own `skipped_invalid` branch unreachable through
    normal loading, and it means a typo in a hand-edited settings.json used to
    remove a certificate from renewal with nothing said anywhere. The
    reconciliation catches exactly this: the entry is gone, so the certificate
    is unmanaged, so it gets named.
    """
    import json as _json
    instance.put_on_disk('orphan.example.com')
    instance.register({'domain': 'orphan.example.com'})

    path = instance.settings_manager.settings_file
    stored = _json.loads(path.read_text())
    stored['domains'] = [{'dns_provider': 'cloudflare'}]  # typo: no `domain`
    path.write_text(_json.dumps(stored))

    assert instance.settings_manager.load_settings()['domains'] == [], (
        'the load path now keeps malformed entries, so this test is measuring '
        'something else')

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        summary = instance.check_renewals()

    assert summary['unmanaged'] == 1
    assert _reported(caplog) == {'orphan.example.com'}


# --- the reconciliation must not become a way to lose the sweep ----------

def test_an_unreadable_certificate_directory_does_not_fail_the_sweep(
        instance, monkeypatch, caplog):
    """CONTROL. Losing the warning is bad; losing the sweep that renews
    everything else is worse. The reconciliation runs after the work, and its
    failure must not discard it."""
    instance.put_on_disk('managed.example.com')
    instance.register({'domain': 'managed.example.com'})

    def _explode(_):
        raise OSError('permission denied')

    monkeypatch.setattr('modules.core.certificates.iter_cert_domain_dirs',
                        _explode)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        summary = instance.check_renewals()

    assert summary['checked'] == 1, 'the sweep lost its work to the check'
    assert summary['unmanaged'] == 0
    assert any('permission denied' in record.getMessage()
               for record in caplog.records)


def test_globally_disabled_renewal_still_returns_the_key(instance):
    """The early return is a different dict literal. A caller reading
    `summary['unmanaged']` must not have to know which one produced it."""
    instance.put_on_disk('orphan.example.com')
    instance.register(auto_renew=False)

    summary = instance.check_renewals()

    assert summary['auto_renew_disabled'] is True
    assert summary['unmanaged'] == 0


def test_the_completion_line_reports_the_count(instance, caplog):
    """The number belongs in the one line an operator greps for."""
    instance.put_on_disk('orphan.example.com')
    instance.register()

    with caplog.at_level(logging.INFO, logger=LOGGER):
        instance.check_renewals()

    completion = [record.getMessage() for record in caplog.records
                  if 'Renewal check complete' in record.getMessage()]
    assert completion, 'the sweep no longer logs a completion line'
    assert '1 unmanaged' in completion[0]
