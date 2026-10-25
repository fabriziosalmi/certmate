"""Discovery calls a served certificate ``issued`` only when CertMate holds it.

The inventory's ``source`` says where a certificate came from, and ``issued``
means CertMate minted it (``cert_inventory.SOURCES``). The sweep used to decide
it from the host alone: whatever a managed host served was recorded as issued,
so a certificate from another CA still served after a renewal that was never
deployed, the case discovery exists to catch, read as one CertMate issued.

Now the fingerprint decides the source, from the certificates CertMate holds:
``issued`` for one it obtained, ``imported`` for one it was given, ``probed``
for anything else. ``managed`` and its link keep meaning what adoption also
makes them mean, that the host's domain is one CertMate manages, so a foreign
certificate on a managed host is not offered for adoption a second time.
"""

import secrets
from unittest import mock

import pytest

from modules.core.cert_discovery import CertDiscoveryManager, discover_endpoints
from modules.core.cert_inventory import CertInventory
from modules.core.certificates import CertificateManager
from modules.core.domain_paths import certificate_dir, lineage_archive_dir
from tests.tls_support import make_cert, pem

pytestmark = [pytest.mark.unit]


def _ok(host, fingerprint, port=443):
    return {
        'status': 'ok', 'host': host, 'port': port, 'error': None,
        'certificate': {
            'subject_cn': host, 'subject': f'CN={host}', 'issuer_cn': 'Some CA',
            'issuer': 'CN=Some CA', 'serial_number': '1',
            'not_before': '2026-01-01T00:00:00Z', 'not_after': '2027-01-01T00:00:00Z',
            'fingerprint_sha256': fingerprint,
            'key': {'type': 'RSA', 'size': 2048, 'curve': None},
            'signature_algorithm': 'sha256WithRSAEncryption', 'san_dns': [host],
        },
        'validation': {}, 'chain': [],
    }


def _probe_serving(served):
    def probe(host, port=443, timeout=None, allow_private=False, check_revocation=False):
        return _ok(host, served[host], port)
    return probe


@pytest.fixture
def inventory(tmp_path):
    return CertInventory(tmp_path / 'data')


# --------------------------------------------------------------------------- #
# The sweep: the fingerprint decides the source, the host decides managed
# --------------------------------------------------------------------------- #

def test_a_foreign_certificate_on_a_managed_host_is_probed_and_still_managed(inventory):
    discover_endpoints(
        ['shop.example.com'], inventory,
        probe=_probe_serving({'shop.example.com': 'f0reign'}),
        managed_domains={'shop.example.com': 'shop.example.com'},
        held_sources={'0urs': 'issued'},
    )
    record = inventory.get('f0reign')
    assert record['source'] == 'probed'
    assert record['managed'] is True
    assert record['managed_domain'] == 'shop.example.com'


def test_a_certificate_certmate_holds_is_issued_wherever_it_is_served(inventory):
    discover_endpoints(
        ['lb.internal:8443'], inventory,
        probe=_probe_serving({'lb.internal': '0urs'}),
        managed_domains={},
        held_sources={'0urs': 'issued'},
    )
    record = inventory.get('0urs')
    assert record['source'] == 'issued'
    assert record['managed'] is False


def test_a_certificate_certmate_was_given_is_imported(inventory):
    discover_endpoints(
        ['vendor.example.com'], inventory,
        probe=_probe_serving({'vendor.example.com': 'g1ven'}),
        managed_domains={'vendor.example.com': 'vendor.example.com'},
        held_sources={'g1ven': 'imported'},
    )
    record = inventory.get('g1ven')
    assert record['source'] == 'imported'
    assert record['managed'] is True


def test_without_what_certmate_holds_nothing_is_called_issued(inventory):
    discover_endpoints(
        ['shop.example.com'], inventory,
        probe=_probe_serving({'shop.example.com': 'anything'}),
        managed_domains={'shop.example.com': 'shop.example.com'},
    )
    assert inventory.get('anything')['source'] == 'probed'


# --------------------------------------------------------------------------- #
# What CertMate holds, read from its certificate directories
# --------------------------------------------------------------------------- #

def _fingerprint(certificate):
    from cryptography.hazmat.primitives import hashes
    return certificate.fingerprint(hashes.SHA256()).hex()


def _write(directory, filename, certificate):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_bytes(pem(certificate))


def _manager(cert_dir, settings=None):
    settings_manager = mock.MagicMock()
    settings_manager.load_settings.return_value = settings or {'domains': []}
    return CertificateManager(cert_dir, settings_manager, mock.MagicMock())


def _metadata(directory, **fields):
    import json
    (directory / 'metadata.json').write_text(json.dumps(fields))


def test_the_served_copy_and_every_lineage_generation_are_issued(tmp_path):
    first, _ = make_cert('shop.example.com')
    second, _ = make_cert('shop.example.com')
    directory = certificate_dir(tmp_path, 'shop.example.com')
    _write(directory, 'cert.pem', second)
    archive = lineage_archive_dir(directory, 'shop.example.com')
    _write(archive, 'cert1.pem', first)
    _write(archive, 'cert2.pem', second)

    held = _manager(tmp_path).held_certificate_sources()

    assert held == {_fingerprint(first): 'issued', _fingerprint(second): 'issued'}


def test_a_wildcard_certificate_is_held_under_its_own_name(tmp_path):
    wildcard, _ = make_cert('*.example.com')
    _write(certificate_dir(tmp_path, '*.example.com'), 'cert.pem', wildcard)

    assert _manager(tmp_path).held_certificate_sources() == {_fingerprint(wildcard): 'issued'}


def test_an_external_certificate_is_imported(tmp_path):
    external, _ = make_cert('vendor.example.com')
    directory = certificate_dir(tmp_path, 'vendor.example.com')
    _write(directory, 'cert.pem', external)
    _metadata(directory, domain='vendor.example.com', external=True)

    assert _manager(tmp_path).held_certificate_sources() == {_fingerprint(external): 'imported'}


def test_an_external_certificate_whose_metadata_is_lost_is_still_imported(tmp_path):
    """The settings entry carries the same marker, as for every other check of it."""
    external, _ = make_cert('vendor.example.com')
    _write(certificate_dir(tmp_path, 'vendor.example.com'), 'cert.pem', external)
    settings = {'domains': [{'domain': 'vendor.example.com', 'external': True}]}

    assert (_manager(tmp_path, settings).held_certificate_sources()
            == {_fingerprint(external): 'imported'})


def test_an_import_is_imported_until_its_first_renewal(tmp_path):
    """A renewal drops ``imported_at``; until then the served copy is the upload."""
    uploaded, _ = make_cert('app.example.com')
    renewed, _ = make_cert('app.example.com')
    directory = certificate_dir(tmp_path, 'app.example.com')
    _write(directory, 'cert.pem', uploaded)
    _metadata(directory, domain='app.example.com', imported_at='2026-10-01T00:00:00Z')
    assert _manager(tmp_path).held_certificate_sources() == {_fingerprint(uploaded): 'imported'}

    _write(directory, 'cert.pem', renewed)
    _write(lineage_archive_dir(directory, 'app.example.com'), 'cert1.pem', renewed)
    _metadata(directory, domain='app.example.com', renewed_at='2026-10-20T00:00:00Z')
    assert _manager(tmp_path).held_certificate_sources() == {_fingerprint(renewed): 'issued'}


def test_a_file_that_is_not_a_certificate_is_not_held(tmp_path):
    readable, _ = make_cert('a.example.com')
    _write(certificate_dir(tmp_path, 'a.example.com'), 'cert.pem', readable)
    torn = certificate_dir(tmp_path, 'b.example.com')
    torn.mkdir()
    (torn / 'cert.pem').write_bytes(b'-----BEGIN CERTIFICATE-----\ntorn')
    archive = lineage_archive_dir(torn, 'b.example.com')
    archive.mkdir(parents=True)
    (archive / 'cert1.pem').write_bytes(b'not a certificate')

    assert _manager(tmp_path).held_certificate_sources() == {_fingerprint(readable): 'issued'}


def test_a_generation_that_cannot_be_read_is_left_out(tmp_path):
    served, _ = make_cert('a.example.com')
    directory = certificate_dir(tmp_path, 'a.example.com')
    _write(directory, 'cert.pem', served)
    (lineage_archive_dir(directory, 'a.example.com') / 'cert1.pem').mkdir(parents=True)

    assert _manager(tmp_path).held_certificate_sources() == {_fingerprint(served): 'issued'}


@pytest.mark.parametrize('external', [True, False])
def test_metadata_that_cannot_be_read_leaves_the_settings_entry_to_say(tmp_path, external):
    served, _ = make_cert('vendor.example.com')
    _write(certificate_dir(tmp_path, 'vendor.example.com'), 'cert.pem', served)
    settings = {'domains': [{'domain': 'vendor.example.com', 'external': external}]}
    manager = _manager(tmp_path, settings)
    manager._load_metadata = mock.MagicMock(side_effect=PermissionError('metadata.json'))

    assert (manager.held_certificate_sources()
            == {_fingerprint(served): 'imported' if external else 'issued'})


# --------------------------------------------------------------------------- #
# The manager: what it is given, and a failure to read it
# --------------------------------------------------------------------------- #

def _settings_manager(endpoints, managed=()):
    settings_manager = mock.MagicMock()
    settings_manager.load_settings.return_value = {
        'monitored_endpoints': {'enabled': True, 'endpoints': list(endpoints),
                                'include_managed': True, 'check_revocation': False},
        'domains': [{'domain': name} for name in managed],
    }
    return settings_manager


def test_the_manager_asks_what_certmate_holds_once_per_sweep(inventory):
    held = mock.MagicMock(return_value={'0urs': 'issued'})
    manager = CertDiscoveryManager(
        _settings_manager(['lb.internal']), inventory,
        probe=_probe_serving({'lb.internal': '0urs'}), held_sources=held)

    manager.run_discovery()

    assert held.call_count == 1
    assert inventory.get('0urs')['source'] == 'issued'


@pytest.mark.parametrize('failure', [OSError('disk'), ValueError('settings')])
def test_a_failure_to_read_what_certmate_holds_calls_nothing_issued(inventory, failure):
    """The sweep still runs: a certificate it cannot place is probed, never issued."""
    manager = CertDiscoveryManager(
        _settings_manager([], managed=['shop.example.com']), inventory,
        probe=_probe_serving({'shop.example.com': '0urs'}),
        held_sources=mock.MagicMock(side_effect=failure))

    summary = manager.run_discovery()

    assert summary['skipped'] is False
    assert summary['summary']['ok'] == 1
    record = inventory.get('0urs')
    assert record['source'] == 'probed'
    assert record['managed'] is True


# --------------------------------------------------------------------------- #
# The application wires it
# --------------------------------------------------------------------------- #

@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    import os
    tmp = tmp_path_factory.mktemp('discovery-issued')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()
        yield app, container, tmp / 'certs'


def test_the_application_sweep_knows_what_certmate_holds(instance, monkeypatch):
    _app, container, cert_dir = instance
    ours, _ = make_cert('app.example.com')
    _write(certificate_dir(cert_dir, 'app.example.com'), 'cert.pem', ours)
    container.managers['settings'].update(
        lambda s: s.__setitem__('monitored_endpoints', {
            'enabled': True, 'endpoints': ['lb.internal'], 'include_managed': False,
            'check_revocation': False}),
        'test_discovery')
    discovery = container.managers['cert_discovery']
    monkeypatch.setattr(discovery, '_probe', _probe_serving({'lb.internal': _fingerprint(ours)}))

    discovery.run_discovery()

    assert container.managers['cert_inventory'].get(_fingerprint(ours))['source'] == 'issued'
