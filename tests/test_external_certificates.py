"""External certificates (#1159): imported with no CA, never issued for by CertMate.

A vendor's certificate is stored, deployed and watched like any other, and no
path may renew, reissue or re-create it, because no CA here can. Today a missing
``ca_provider`` means "use the default CA" on every issuing path, so these tests
care less about the happy path than about every way that default could still be
reached: each entry point, each record that says "external" lost on its own, and
each name another certificate already covers.
"""
import json
import secrets
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from modules.core.certificates import ExternalCertificate
from tests.test_certificate_import import make_bundle

pytestmark = pytest.mark.unit

EXT = 'ext.example.com'
EXT_SAN = 'ext-san.example.com'


@pytest.fixture
def instance(tmp_path, monkeypatch):
    for var, sub in (('CERTMATE_CERT_DIR', 'certificates'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(var, str(tmp_path / sub))
    token = secrets.token_urlsafe(48)
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    from modules.factory import create_app
    app, container = create_app()
    managers = container.managers
    managers['settings'].atomic_update({
        'email': 'ops@example.com', 'dns_provider': 'cloudflare',
        'ca_providers': {'sectigo': {'accounts': {'paid': {
            'email': 'ca@example.com', 'acme_url': 'https://acme.sectigo.com/v2/OV',
            'eab_kid': 'test-id', 'eab_hmac': 'test-secret'}}}},
        'dns_providers': {'cloudflare': {'accounts': {'dns-prod': {'api_token': 'test-token'}}}},
    })
    certs = managers['certificates']
    shell = MagicMock()
    certs.shell_executor = shell
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}'}

    published = []
    bus = app.config['EVENT_BUS']
    original_publish = bus.publish

    def recording_publish(event, data=None, *args, **kwargs):
        published.append((event, dict(data or {})))
        return original_publish(event, data, *args, **kwargs)

    bus.publish = recording_publish
    return SimpleNamespace(
        app=app, managers=managers, certs=certs, shell=shell, client=client,
        headers=headers, cert_root=tmp_path / 'certificates', published=published,
        post=lambda data: client.post('/api/certificates/import', json=data, headers=headers))


def external(bundle, **options):
    return {**bundle, 'external': True, **options}


def ordinary(bundle, domain, **options):
    """An import with a CA for its next renewal: the certificates CertMate manages."""
    return {**bundle, 'domain': domain, 'ca_provider': 'sectigo', 'ca_account_id': 'paid',
            'challenge_type': 'prevalidated', **options}


def settings_entry(instance, domain):
    for entry in instance.managers['settings'].load_settings(use_cache=False).get('domains', []):
        if isinstance(entry, dict) and entry.get('domain') == domain:
            return entry
    return None


def metadata(instance, domain):
    return json.loads((instance.cert_root / domain / 'metadata.json').read_text())


def import_external(instance, names=(EXT, EXT_SAN), **options):
    response = instance.post(external(make_bundle(names=names), **options))
    assert response.status_code == 201, response.get_json()
    return response


# --------------------------------------------------------------------------- #
# Import
# --------------------------------------------------------------------------- #

def test_an_external_import_is_stored_and_registered_with_no_ca(instance):
    response = import_external(instance)
    body = response.get_json()
    assert body['domain'] == EXT and body['external'] is True
    assert body['san_domains'] == [EXT_SAN]

    stored = metadata(instance, EXT)
    assert stored['external'] is True and stored['auto_renew'] is False
    assert stored['imported_at']
    for field in ('ca_provider', 'ca_account_id', 'challenge_type', 'dns_provider',
                  'account_id', 'email', 'acme_profile'):
        assert stored[field] is None, field
    entry = settings_entry(instance, EXT)
    assert entry['external'] is True and entry['auto_renew'] is False
    assert entry['dns_provider'] is None

    created = [data for event, data in instance.published if event == 'certificate_created']
    assert created and created[-1]['external'] is True and created[-1]['domain'] == EXT
    instance.shell.run.assert_not_called()


def test_an_external_certificate_reads_as_one(instance):
    import_external(instance)
    listing = instance.client.get('/api/certificates', headers=instance.headers).get_json()
    cert = next(c for c in listing if c['domain'] == EXT)
    assert cert['external'] is True
    assert cert['ca_provider'] is None
    # Not the global provider borrowed from settings: nothing validates it.
    assert cert['dns_provider'] is None
    assert cert['auto_renew'] is False


@pytest.mark.parametrize('field,value', [
    ('ca_provider', 'sectigo'), ('ca_account_id', 'paid'), ('challenge_type', 'dns-01'),
    ('dns_provider', 'cloudflare'), ('account_id', 'dns-prod'), ('domain_alias', 'alias.example.net'),
    ('alias_dns_provider', 'cloudflare'), ('acme_profile', 'tlsserver'),
])
def test_renewal_configuration_is_refused_with_external(instance, field, value):
    response = instance.post(external(make_bundle(names=(EXT,)), **{field: value}))
    assert response.status_code == 400
    assert field in response.get_json()['error']
    assert not (instance.cert_root / EXT).exists()


def test_auto_renew_on_is_refused_with_external_and_off_is_accepted(instance):
    refused = instance.post(external(make_bundle(names=(EXT,)), auto_renew=True))
    assert refused.status_code == 400
    assert not (instance.cert_root / EXT).exists()
    import_external(instance, names=(EXT,), auto_renew=False)


@pytest.mark.parametrize('case,accepted', [
    ('rsa-1024', False), ('ed25519', False), ('ip-san', False),
    ('rsa-4096', True), ('p-521', True), ('wildcard', True),
])
def test_what_an_external_certificate_may_be(instance, case, accepted):
    import ipaddress
    options = {
        'rsa-1024': {'key': rsa.generate_private_key(65537, 1024)},
        'ed25519': {'key': ed25519.Ed25519PrivateKey.generate()},
        'ip-san': {'san_names': [x509.DNSName(EXT), x509.IPAddress(ipaddress.ip_address('192.0.2.1'))]},
        'rsa-4096': {'key': rsa.generate_private_key(65537, 4096)},
        'p-521': {'key': ec.generate_private_key(ec.SECP521R1())},
        'wildcard': {'names': ('*.ext.example.com',)},
    }[case]
    options.setdefault('names', (EXT,))
    response = instance.post(external(make_bundle(**options)))
    assert (response.status_code == 201) is accepted, response.get_json()


# --------------------------------------------------------------------------- #
# Names another certificate already covers
# --------------------------------------------------------------------------- #

def _names_refused(body):
    """The names a NAMES_ALREADY_MANAGED refusal lists, after its colon."""
    return body['error'].rsplit(': ', 1)[1].split(', ')


def _managed(instance, names):
    response = instance.post(ordinary(make_bundle(names=names), names[0]))
    assert response.status_code == 201, response.get_json()


@pytest.mark.parametrize('managed,imported', [
    (('shared.example.com',), ('shared.example.com',)),                       # primary on primary
    (('shared.example.com',), (EXT, 'shared.example.com')),                   # SAN on primary
    (('owner.example.com', 'shared.example.com'), ('shared.example.com',)),  # primary on SAN
    (('owner.example.com', 'shared.example.com'), (EXT, 'shared.example.com')),  # SAN on SAN
    (('*.example.com',), ('*.example.com',)),                                 # the same wildcard
])
def test_a_name_already_covered_refuses_the_import(instance, managed, imported):
    _managed(instance, managed)
    response = instance.post(external(make_bundle(names=imported)))
    assert response.status_code == 409, response.get_json()
    body = response.get_json()
    assert body['code'] == 'NAMES_ALREADY_MANAGED'
    assert _names_refused(body) == [name for name in imported if name in managed]
    assert not (instance.cert_root / imported[0]).exists() or imported[0] == managed[0]


def test_the_refusal_names_only_the_imports_own_names(instance):
    """The other certificate may be outside a scoped key's domains."""
    _managed(instance, ('owner.example.com', 'shared.example.com'))
    body = instance.post(external(make_bundle(names=('shared.example.com',)))).get_json()
    assert _names_refused(body) == ['shared.example.com']
    assert 'owner.example.com' not in body['error']


def test_a_registered_name_with_nothing_on_disk_is_taken(instance):
    instance.managers['settings'].update(
        lambda s: s.update(domains=[{'domain': 'pending.example.com'}]))
    response = instance.post(external(make_bundle(names=(EXT, 'pending.example.com'))))
    assert response.status_code == 409


def test_names_are_compared_without_case(instance):
    _managed(instance, ('shared.example.com',))
    bundle = make_bundle(names=(EXT,), san_names=[x509.DNSName(EXT), x509.DNSName('SHARED.Example.COM')])
    assert instance.post(external(bundle)).status_code == 409


def test_a_wildcard_does_not_take_the_names_it_matches(instance):
    """A wildcard and a name it matches are two certificates today (#854)."""
    _managed(instance, ('a.example.com',))
    import_external(instance, names=('*.example.com',))


def test_a_certificate_whose_names_cannot_be_read_refuses_the_import(instance):
    broken = instance.cert_root / 'broken.example.com'
    broken.mkdir()
    (broken / 'cert.pem').write_text('not a certificate')
    response = instance.post(external(make_bundle(names=(EXT,))))
    assert response.status_code == 409
    assert 'could not read' in response.get_json()['error']
    assert 'broken.example.com' not in response.get_json()['error']


def test_two_imports_sharing_a_name_cannot_both_pass(instance, monkeypatch):
    """The check and the store run under one lock. Without it both checks
    would see the shared name free before either stored it."""
    service = instance.managers['cert_service']
    store = instance.certs.store_imported_certificate
    first_storing = threading.Event()

    def slow_store(*args, **kwargs):
        first_storing.set()
        threading.Event().wait(0.3)
        return store(*args, **kwargs)

    monkeypatch.setattr(instance.certs, 'store_imported_certificate', slow_store)
    results = []

    def run(names):
        bundle = make_bundle(names=names)
        try:
            service.import_certificate(certificate=bundle['certificate'], chain=bundle['chain'],
                                       private_key=bundle['private_key'], external=True,
                                       auto_renew=False, user={'username': 'admin'})
            results.append('imported')
        except ValueError as error:
            results.append(type(error).__name__)

    first = threading.Thread(target=run, args=(('one.example.com', 'shared.example.com'),))
    first.start()
    assert first_storing.wait(5)
    second = threading.Thread(target=run, args=(('two.example.com', 'shared.example.com'),))
    second.start()
    first.join(10)
    second.join(10)
    assert sorted(results) == ['CertificateNamesTaken', 'imported']


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

def test_a_scoped_key_must_cover_every_name(instance):
    ok, key = instance.managers['auth'].create_api_key('scoped', role='operator', allowed_domains=[EXT])
    assert ok
    response = instance.client.post(
        '/api/certificates/import', json=external(make_bundle(names=(EXT, 'elsewhere.example.org'))),
        headers={'Authorization': 'Bearer ' + key['token']})
    assert response.status_code == 403
    assert not (instance.cert_root / EXT).exists()


# --------------------------------------------------------------------------- #
# Nothing issues for it
# --------------------------------------------------------------------------- #

def _lose(instance, record):
    """Lose one of the two records that say "external"."""
    if record == 'metadata':
        # A metadata file that does not parse is quarantined and read back empty.
        (instance.cert_root / EXT / 'metadata.json').write_text('{not json')
    elif record == 'settings':
        instance.managers['settings'].update(
            lambda s: s.update(domains=[d for d in s.get('domains', [])
                                        if not (isinstance(d, dict) and d.get('domain') == EXT)]))


@pytest.mark.parametrize('lost', [None, 'metadata', 'settings'])
def test_every_issuing_route_refuses_it(instance, lost):
    import_external(instance)
    _lose(instance, lost)
    h = instance.headers
    answers = {
        'renew': instance.client.post(f'/api/certificates/{EXT}/renew', json={}, headers=h),
        'renew async': instance.client.post(f'/api/certificates/{EXT}/renew', json={'async': True}, headers=h),
        'force renew': instance.client.post(f'/api/certificates/{EXT}/renew', json={'force': True}, headers=h),
        'reissue': instance.client.post(f'/api/certificates/{EXT}/reissue', json={}, headers=h),
        'reissue async': instance.client.post(f'/api/certificates/{EXT}/reissue', json={'async': True}, headers=h),
        'create': instance.client.post('/api/certificates/create', json={'domain': EXT}, headers=h),
        'create async': instance.client.post('/api/certificates/create', json={'domain': EXT, 'async': True},
                                             headers=h),
        'web renew': instance.client.post(f'/api/web/certificates/{EXT}/renew', json={}, headers=h),
    }
    for route, response in answers.items():
        assert response.status_code == 409, (route, response.status_code, response.get_json())
        assert response.get_json()['code'] == 'EXTERNAL_CERTIFICATE', route
    instance.shell.run.assert_not_called()


@pytest.mark.parametrize('lost', [None, 'metadata', 'settings'])
def test_the_manager_refuses_it_whatever_calls_it(instance, lost):
    import_external(instance)
    _lose(instance, lost)
    with pytest.raises(ExternalCertificate):
        instance.certs.renew_certificate(EXT, force=True)
    with pytest.raises(ExternalCertificate):
        instance.certs.create_certificate(EXT, 'ops@example.com', replace=True)
    instance.shell.run.assert_not_called()


def test_the_first_import_renewal_refuses_it(instance):
    import_external(instance)
    with pytest.raises(ExternalCertificate):
        instance.certs.create_certificate(EXT, 'ops@example.com', imported_renewal_force=True)
    instance.shell.run.assert_not_called()


def test_auto_renew_cannot_be_turned_on(instance):
    import_external(instance)
    url = f'/api/certificates/{EXT}/auto-renew'
    on = instance.client.put(url, json={'enabled': True}, headers=instance.headers)
    assert on.status_code == 409 and on.get_json()['code'] == 'EXTERNAL_CERTIFICATE'
    assert settings_entry(instance, EXT)['auto_renew'] is False
    off = instance.client.put(url, json={'enabled': False}, headers=instance.headers)
    assert off.status_code == 200


def test_a_replacement_is_deleted_then_imported(instance):
    """What docs/api.md tells an operator to do until a replace endpoint exists."""
    import_external(instance)
    assert instance.post(external(make_bundle(names=(EXT, EXT_SAN)))).status_code == 409
    deleted = instance.client.delete(f'/api/certificates/{EXT}', headers=instance.headers)
    assert deleted.status_code == 200, deleted.get_json()
    assert settings_entry(instance, EXT) is None
    import_external(instance)


# --------------------------------------------------------------------------- #
# The sweep
# --------------------------------------------------------------------------- #

def test_the_sweep_leaves_it_and_counts_it(instance):
    instance.post(external(make_bundle(names=(EXT,), start=-60, end=1)))
    instance.certs.renew_certificate = MagicMock()
    summary = instance.certs.check_renewals()
    assert summary['external'] == 1
    assert summary['skipped_disabled'] == 0 and summary['failed'] == 0
    instance.certs.renew_certificate.assert_not_called()
    assert not [event for event, _ in instance.published if event == 'certificate_failed']


def test_the_sweep_leaves_it_when_only_its_files_remain(instance):
    instance.post(external(make_bundle(names=(EXT,), start=-60, end=1)))
    _lose(instance, 'settings')
    instance.certs.renew_certificate = MagicMock()
    summary = instance.certs.check_renewals()
    assert summary['external'] == 1
    assert summary['unmanaged'] == 0 and summary['reregistered'] == 0
    instance.certs.renew_certificate.assert_not_called()
    assert settings_entry(instance, EXT) is None


def test_no_ca_is_asked_about_it(instance):
    import_external(instance)
    asked = []

    class _Client:
        def now(self):
            import datetime
            return datetime.datetime.now(datetime.UTC)

        def lookup(self, directory_url, cert_id):
            asked.append(directory_url)
            return 'unavailable', None

    instance.certs._ari_client = _Client()
    info = instance.certs.get_certificate_info(EXT, use_cache=False)
    status = instance.certs._refresh_renewal_info(EXT, info, instance.managers['settings'].load_settings())
    assert status == 'external' and asked == []


# --------------------------------------------------------------------------- #
# What reads it
# --------------------------------------------------------------------------- #

def test_its_expiry_is_announced_as_nobody_renews_it_even_without_an_entry(tmp_path):
    """Without a settings entry the per-domain flag reads as on. Read as on, a
    certificate is announced only once it is late for its renewal; an external
    one has no renewal, so it is announced from the threshold."""
    from modules.core.cert_inventory import CertInventory
    from modules.core.expiry_watch import ExpiryWatch

    cert_dir = tmp_path / 'certs'
    (cert_dir / EXT).mkdir(parents=True)
    (cert_dir / EXT / 'cert.pem').write_text('present')
    published = []

    class _Certificates:
        def __init__(self, external):
            self.cert_dir = cert_dir
            self.external = external

        def get_certificate_info(self, domain, settings=None, use_cache=True):
            return {'exists': True, 'days_left': 20, 'expiry_date': '2099-01-01 00:00:00',
                    'expired': False, 'external': self.external}

    class _Bus:
        def publish(self, event, data):
            published.append((event, data))

    for is_external in (False, True):
        published.clear()
        settings_manager = MagicMock()
        settings_manager.load_settings.return_value = {'domains': []}
        inventory = CertInventory(tmp_path / f'data-{is_external}')
        watch = ExpiryWatch(settings_manager, _Certificates(is_external), inventory, _Bus())
        watch._certificates(settings_manager.load_settings())
        expiring = [data for event, data in published if event == 'certificate_expiring']
        if is_external:
            assert expiring and expiring[0]['auto_renew'] is False
        else:
            assert not expiring


def test_the_marker_survives_azure_key_vault_tags():
    from modules.core.storage_backends import _AzureKeyVaultCertificateImporter as importer
    tags = importer._build_tags({'domain': EXT, 'external': True,
                                 'imported_at': '2026-10-15T00:00:00Z'})
    assert tags['external'] == 'true'
    restored = importer._tags_to_metadata(tags)
    assert restored['external'] is True
    assert restored['imported_at'] == '2026-10-15T00:00:00Z'
    assert 'external' not in importer._tags_to_metadata(importer._build_tags({'domain': EXT}))
