"""Tests for CT-log monitoring (``modules/core/ct_monitor.py``), #470:

* config get/save round-trip,
* disabled / no-domains no-ops,
* a new CT certificate is fetched, parsed and recorded source=ct-log, unmanaged,
  with no endpoint,
* dedup by serial against an already-known (probed) cert avoids a DER fetch,
* only_valid skips expired entries,
* the per-run cap truncates and is reported (not silent),
* failure isolation: a search error or a DER-fetch error never aborts the poll,
* managed domains are polled when include_managed is on,
* factory job registration + settings writability.
"""

from datetime import datetime, timedelta, timezone

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modules.core.cert_inventory import CertInventory
from modules.core.ct_monitor import CTMonitorManager, CrtShError, DEFAULT_CT_CONFIG
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager, PUBLIC_SETTINGS_WRITABLE_KEYS

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _make_cert(serial_int, cn='example.com', not_after=None):
    """Build a self-signed cert with a chosen serial. Returns (der, entry_dict)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    not_after = not_after or (now + timedelta(days=90))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial_int)
        .not_valid_before(not_after - timedelta(days=90))
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    entry = {
        'id': serial_int,  # use serial as the fake crt.sh id for convenience
        'serial_number': format(serial_int, 'x'),
        'common_name': cn,
        'name_value': cn,
        'issuer_name': 'C=US, O=Test CA',
        'not_after': not_after.replace(tzinfo=None).replace(microsecond=0).isoformat(),
    }
    return der, entry, fingerprint


class _FakeClient:
    def __init__(self, entries_by_domain, der_by_id, fail_search=(), fail_fetch=()):
        self.entries_by_domain = entries_by_domain
        self.der_by_id = der_by_id
        self.fail_search = set(fail_search)
        self.fail_fetch = set(fail_fetch)
        self.search_calls = []
        self.fetch_calls = []

    def search(self, domain):
        self.search_calls.append(domain)
        if domain in self.fail_search:
            raise CrtShError(f"boom for {domain}")
        return self.entries_by_domain.get(domain, [])

    def fetch_certificate(self, crtsh_id):
        self.fetch_calls.append(crtsh_id)
        if crtsh_id in self.fail_fetch:
            raise CrtShError(f"fetch boom for {crtsh_id}")
        return self.der_by_id[crtsh_id]


@pytest.fixture
def settings_manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
    return SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")


@pytest.fixture
def inventory(tmp_path):
    return CertInventory(tmp_path / "inv-data")


def _enable(mgr, **overrides):
    cfg = {'enabled': True, 'domains': ['example.com'], 'include_managed': False}
    cfg.update(overrides)
    mgr.save_config(cfg)


# --------------------------------------------------------------------------- #
# config / no-ops
# --------------------------------------------------------------------------- #

def test_ct_monitoring_is_publicly_writable():
    assert 'ct_monitoring' in PUBLIC_SETTINGS_WRITABLE_KEYS


def test_default_config(settings_manager, inventory):
    mgr = CTMonitorManager(settings_manager, inventory)
    assert mgr.get_config() == DEFAULT_CT_CONFIG


def test_save_config_normalises(settings_manager, inventory):
    mgr = CTMonitorManager(settings_manager, inventory)
    saved = mgr.save_config({'enabled': True, 'domains': [' Example.COM ', ''],
                             'max_new_per_run': -5, 'min_request_interval': -1})
    assert saved['domains'] == ['example.com']
    assert saved['max_new_per_run'] == 0
    assert saved['min_request_interval'] == 0.0


def test_disabled_is_noop(settings_manager, inventory):
    mgr = CTMonitorManager(settings_manager, inventory, client=_FakeClient({}, {}))
    out = mgr.run_poll()
    assert out == {'skipped': True, 'reason': 'disabled'}


def test_no_domains_is_noop(settings_manager, inventory):
    client = _FakeClient({}, {})
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    mgr.save_config({'enabled': True, 'domains': [], 'include_managed': False})
    out = mgr.run_poll()
    assert out['skipped'] is True
    assert out['reason'] == 'no_domains'
    assert client.search_calls == []


# --------------------------------------------------------------------------- #
# ingestion
# --------------------------------------------------------------------------- #

def test_new_cert_ingested_as_ct_log_unmanaged(settings_manager, inventory):
    der, entry, fp = _make_cert(0x1234, cn='example.com')
    client = _FakeClient({'example.com': [entry]}, {entry['id']: der})
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    _enable(mgr)

    out = mgr.run_poll()
    assert out['new'] == 1
    assert out['known'] == 0
    rec = inventory.get(fp)
    assert rec is not None
    assert rec['source'] == 'ct-log'
    assert rec['managed'] is False
    assert rec['endpoints'] == []            # CT observation has no host:port
    assert rec['subject_cn'] == 'example.com'


def test_dedup_by_serial_skips_der_fetch(settings_manager, inventory):
    der, entry, fp = _make_cert(0xABCD, cn='example.com')
    # Pre-seed the inventory as if we had probed this exact cert (same serial).
    inventory.record_observation(
        fingerprint=fp, host='example.com', port=443, source='probed',
        serial=str(0xABCD),
    )
    client = _FakeClient({'example.com': [entry]}, {entry['id']: der})
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    _enable(mgr)

    out = mgr.run_poll()
    assert out['new'] == 0
    assert out['known'] == 1
    assert client.fetch_calls == []          # never fetched the DER
    # Still a single record, still source=probed (CT did not overwrite it).
    assert inventory.count() == 1
    assert inventory.get(fp)['source'] == 'probed'


def test_only_valid_skips_expired(settings_manager, inventory):
    past = datetime.now(timezone.utc) - timedelta(days=5)
    der, entry, fp = _make_cert(0x55, cn='example.com', not_after=past)
    client = _FakeClient({'example.com': [entry]}, {entry['id']: der})
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    _enable(mgr, only_valid=True)

    out = mgr.run_poll()
    assert out['new'] == 0
    assert client.fetch_calls == []
    assert inventory.count() == 0


def test_cap_truncates_and_reports(settings_manager, inventory):
    der1, e1, _ = _make_cert(0x01, cn='a.example.com')
    der2, e2, _ = _make_cert(0x02, cn='b.example.com')
    client = _FakeClient({'example.com': [e1, e2]},
                         {e1['id']: der1, e2['id']: der2})
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    _enable(mgr, max_new_per_run=1)

    out = mgr.run_poll()
    assert out['new'] == 1
    assert out['truncated'] is True
    assert inventory.count() == 1


# --------------------------------------------------------------------------- #
# failure isolation
# --------------------------------------------------------------------------- #

def test_search_error_isolated(settings_manager, inventory):
    der, entry, fp = _make_cert(0x77, cn='good.example.com')
    client = _FakeClient(
        {'bad.example.com': [], 'good.example.com': [entry]},
        {entry['id']: der}, fail_search=['bad.example.com'],
    )
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    mgr.save_config({'enabled': True,
                     'domains': ['bad.example.com', 'good.example.com'],
                     'include_managed': False})

    out = mgr.run_poll()
    assert len(out['errors']) == 1
    assert out['errors'][0]['domain'] == 'bad.example.com'
    assert out['new'] == 1                    # good domain still processed
    assert inventory.get(fp) is not None


def test_fetch_error_isolated(settings_manager, inventory):
    der_ok, e_ok, fp_ok = _make_cert(0x88, cn='ok.example.com')
    _, e_bad, _ = _make_cert(0x99, cn='bad.example.com')
    client = _FakeClient(
        {'example.com': [e_bad, e_ok]},
        {e_ok['id']: der_ok}, fail_fetch=[e_bad['id']],
    )
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    _enable(mgr)

    out = mgr.run_poll()
    assert out['new'] == 1                    # the good one landed
    assert inventory.get(fp_ok) is not None


# --------------------------------------------------------------------------- #
# managed domains + wiring
# --------------------------------------------------------------------------- #

def test_include_managed_polls_managed_domains(settings_manager, inventory):
    settings_manager.update(
        lambda s: s.__setitem__('domains', [
            {'domain': 'managed.example.com'}, {'domain': '*.wild.example.com'},
        ]),
        'seed',
    )
    der, entry, fp = _make_cert(0xAA, cn='managed.example.com')
    client = _FakeClient({'managed.example.com': [entry]}, {entry['id']: der})
    mgr = CTMonitorManager(settings_manager, inventory, client=client)
    mgr.save_config({'enabled': True, 'domains': [], 'include_managed': True})

    out = mgr.run_poll()
    assert 'managed.example.com' in client.search_calls
    assert '*.wild.example.com' not in client.search_calls
    assert inventory.get(fp)['source'] == 'ct-log'
    assert out['new'] == 1


def test_ct_job_registered_in_factory():
    from modules.core import factory
    assert callable(getattr(factory, '_ct_monitor_job', None))
