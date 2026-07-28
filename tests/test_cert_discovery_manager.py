"""Tests for CertDiscoveryManager and its factory/scheduler wiring (#469):

* config get/save round-trip through a real SettingsManager,
* save_config rejects a malformed endpoint spec,
* run_discovery is a no-op when disabled or when nothing is configured,
* an enabled sweep upserts probe results into the inventory,
* managed domains from settings['domains'] are probed and linked (wildcards
  skipped),
* the discovery job + manager are registered in the app factory.
"""

import pytest

from modules.core.cert_discovery import CertDiscoveryManager
from modules.core.cert_inventory import CertInventory
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager, PUBLIC_SETTINGS_WRITABLE_KEYS

pytestmark = [pytest.mark.unit]


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


def _ok(host, port=443, fingerprint='fp'):
    return {
        'host': host, 'port': port, 'status': 'ok', 'error': None,
        'certificate': {
            'subject_cn': host, 'subject': f'CN={host}', 'issuer_cn': 'CA',
            'issuer': 'CN=CA', 'serial_number': '1',
            'not_before': '2026-01-01T00:00:00Z',
            'not_after': '2026-04-01T00:00:00Z',
            'fingerprint_sha256': fingerprint,
            'key': {'type': 'RSA', 'size': 2048, 'curve': None},
            'signature_algorithm': 'sha256WithRSAEncryption',
            'san_dns': [host],
        },
        'validation': {}, 'chain': [],
    }


class _FakeProbe:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, host, port=443, timeout=None, allow_private=False):
        self.calls.append((host, port, allow_private))
        return self.mapping.get(host, {
            'host': host, 'port': port, 'status': 'unreachable',
            'error': 'no route', 'certificate': None,
        })


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #

def test_monitored_endpoints_is_publicly_writable():
    # The generic settings POST must be allowed to manage this pure-config key.
    assert 'monitored_endpoints' in PUBLIC_SETTINGS_WRITABLE_KEYS


def test_default_config(settings_manager, inventory):
    mgr = CertDiscoveryManager(settings_manager, inventory)
    cfg = mgr.get_config()
    assert cfg == {
        'enabled': False, 'endpoints': [], 'allow_private': False,
        'include_managed': True,
    }


def test_save_and_get_config(settings_manager, inventory):
    mgr = CertDiscoveryManager(settings_manager, inventory)
    saved = mgr.save_config({
        'enabled': True,
        'endpoints': ['  a.example.com  ', 'b.example.com:8443', ''],
        'allow_private': True,
        'include_managed': False,
    })
    assert saved['endpoints'] == ['a.example.com', 'b.example.com:8443']
    assert saved['enabled'] is True
    # Persisted and reloaded identically.
    assert mgr.get_config() == saved


def test_save_config_rejects_bad_endpoint(settings_manager, inventory):
    mgr = CertDiscoveryManager(settings_manager, inventory)
    with pytest.raises(ValueError):
        mgr.save_config({'enabled': True, 'endpoints': ['host:notaport']})


# --------------------------------------------------------------------------- #
# run_discovery
# --------------------------------------------------------------------------- #

def test_run_discovery_disabled_is_noop(settings_manager, inventory):
    probe = _FakeProbe({'a.example.com': _ok('a.example.com')})
    mgr = CertDiscoveryManager(settings_manager, inventory, probe=probe)
    mgr.save_config({'enabled': False, 'endpoints': ['a.example.com']})
    out = mgr.run_discovery()
    assert out['skipped'] is True
    assert out['reason'] == 'disabled'
    assert probe.calls == []
    assert inventory.count() == 0


def test_run_discovery_no_endpoints_is_noop(settings_manager, inventory):
    probe = _FakeProbe({})
    mgr = CertDiscoveryManager(settings_manager, inventory, probe=probe)
    mgr.save_config({'enabled': True, 'endpoints': [], 'include_managed': False})
    out = mgr.run_discovery()
    assert out['skipped'] is True
    assert out['reason'] == 'no_endpoints'


def test_run_discovery_probes_and_records(settings_manager, inventory):
    probe = _FakeProbe({
        'a.example.com': _ok('a.example.com', 443, 'fpA'),
        'b.example.com': _ok('b.example.com', 8443, 'fpB'),
    })
    mgr = CertDiscoveryManager(settings_manager, inventory, probe=probe)
    mgr.save_config({
        'enabled': True,
        'endpoints': ['a.example.com', 'b.example.com:8443'],
        'include_managed': False,
    })
    out = mgr.run_discovery()
    assert out['skipped'] is False
    assert out['summary']['ok'] == 2
    assert inventory.count() == 2
    assert inventory.get('fpA')['source'] == 'probed'


def test_run_discovery_includes_managed_domains(settings_manager, inventory):
    # Seed a managed domain in settings; it should be probed and linked.
    settings_manager.update(
        lambda s: s.__setitem__('domains', [
            {'domain': 'managed.example.com', 'dns_provider': 'cloudflare'},
            {'domain': '*.wild.example.com'},  # wildcard: not probe-able, skipped
        ]),
        'seed',
    )
    probe = _FakeProbe({'managed.example.com': _ok('managed.example.com', 443, 'fpM')})
    mgr = CertDiscoveryManager(settings_manager, inventory, probe=probe)
    mgr.save_config({'enabled': True, 'endpoints': [], 'include_managed': True})

    out = mgr.run_discovery()
    assert out['skipped'] is False
    rec = inventory.get('fpM')
    assert rec['managed'] is True
    assert rec['managed_domain'] == 'managed.example.com'
    # The wildcard domain was never probed.
    probed_hosts = {c[0] for c in probe.calls}
    assert '*.wild.example.com' not in probed_hosts
    assert 'wild.example.com' not in probed_hosts


def test_run_discovery_allow_private_propagates(settings_manager, inventory):
    probe = _FakeProbe({'a.example.com': _ok('a.example.com')})
    mgr = CertDiscoveryManager(settings_manager, inventory, probe=probe)
    mgr.save_config({'enabled': True, 'endpoints': ['a.example.com'],
                     'allow_private': True, 'include_managed': False})
    mgr.run_discovery()
    assert probe.calls[0][2] is True  # allow_private forwarded to the probe


# --------------------------------------------------------------------------- #
# factory wiring
# --------------------------------------------------------------------------- #

def test_discovery_job_registered_in_factory():
    from modules.core import factory
    # The picklable job wrapper exists (APScheduler requires a module-level fn).
    assert hasattr(factory, '_certificate_discovery_job')
    assert callable(factory._certificate_discovery_job)
