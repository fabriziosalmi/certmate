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
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from modules.core.cert_service import CertificateNamesTaken
from modules.core.certificates import DomainOperationInProgress, ExternalCertificate
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


def test_an_external_certificate_is_never_due_for_a_renewal(instance):
    """A day from expiry a renewed certificate is long past its renewal
    instant. An external one has none: nothing renews it, and a client told
    "renews at" or "needs renewal" would wait for a renewal that never comes."""
    assert instance.post(external(make_bundle(names=(EXT,), start=-60, end=1))).status_code == 201
    cert = instance.client.get(f'/api/certificates/{EXT}', headers=instance.headers).get_json()
    assert cert['renews_at'] is None
    assert cert['needs_renewal'] is False
    assert cert['days_left'] <= 1


def test_a_missing_key_still_needs_attention(instance):
    import_external(instance)
    (instance.cert_root / EXT / 'privkey.pem').unlink()
    instance.certs._invalidate_certificate_info_cache(EXT)
    cert = instance.client.get(f'/api/certificates/{EXT}', headers=instance.headers).get_json()
    assert cert['renews_at'] is None
    assert cert['needs_renewal'] is True


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


def test_a_certificate_can_still_be_deleted_and_imported_again(instance):
    """The way to give an external certificate another primary name, which a
    replacement keeps."""
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
                                 'imported_at': '2026-10-15T00:00:00Z',
                                 'replaced_at': '2026-10-16T00:00:00Z'})
    assert tags['external'] == 'true'
    restored = importer._tags_to_metadata(tags)
    assert restored['external'] is True
    assert restored['imported_at'] == '2026-10-15T00:00:00Z'
    assert restored['replaced_at'] == '2026-10-16T00:00:00Z'
    assert 'external' not in importer._tags_to_metadata(importer._build_tags({'domain': EXT}))


# --------------------------------------------------------------------------- #
# Replacement by upload
# --------------------------------------------------------------------------- #

def replace(instance, bundle, domain=EXT, headers=None, **options):
    return instance.client.post(
        f'/api/certificates/{domain}/replace',
        json={'certificate': bundle['certificate'], 'chain': bundle['chain'],
              'private_key': bundle['private_key'], **options},
        headers=headers or instance.headers)


def served(instance, domain=EXT):
    return x509.load_pem_x509_certificate((instance.cert_root / domain / 'cert.pem').read_bytes())


def fingerprint_of(bundle):
    from cryptography.hazmat.primitives import hashes
    return x509.load_pem_x509_certificate(bundle['certificate'].encode()).fingerprint(hashes.SHA256())


def test_a_replacement_serves_the_new_bundle_and_is_announced_as_a_renewal(instance):
    from cryptography.hazmat.primitives import hashes
    import_external(instance)
    patched = instance.client.patch(f'/api/certificates/{EXT}', json={'notes': 'vendor portal'},
                                    headers=instance.headers)
    assert patched.status_code == 200, patched.get_json()
    before = metadata(instance, EXT)
    new = make_bundle(names=(EXT, EXT_SAN), end=200, key=rsa.generate_private_key(65537, 3072))

    response = replace(instance, new)

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body['domain'] == EXT and body['san_domains'] == [EXT_SAN] and body['replaced_at']
    assert served(instance).fingerprint(hashes.SHA256()) == fingerprint_of(new)
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key((instance.cert_root / EXT / 'privkey.pem').read_bytes(), None)
    assert key.public_key().public_numbers() == served(instance).public_key().public_numbers()
    stored = metadata(instance, EXT)
    assert stored['external'] is True and stored['auto_renew'] is False
    assert stored['key_type'] == 'rsa' and stored['key_size'] == 3072
    assert stored.get('elliptic_curve') is None
    assert stored['notes'] == 'vendor portal'
    assert stored['imported_at'] == before['imported_at']
    assert stored['created_at'] == before['created_at']
    from modules.api.timestamps import with_z
    assert with_z(stored['replaced_at']) == body['replaced_at']
    renewed = [data for event, data in instance.published if event == 'certificate_renewed']
    assert renewed == [{'domain': EXT, 'san_domains': [EXT_SAN], 'replaced': True, 'external': True}]
    read = instance.client.get(f'/api/certificates/{EXT}', headers=instance.headers).get_json()
    assert read['external'] is True and read['replaced_at']
    assert read['days_left'] > 150
    instance.shell.run.assert_not_called()


def test_a_replacement_may_change_the_other_names(instance):
    import_external(instance)
    response = replace(instance, make_bundle(names=(EXT, 'added.example.com'), end=200))
    assert response.status_code == 200, response.get_json()
    assert metadata(instance, EXT)['san_domains'] == ['added.example.com']
    # The name it no longer carries is free for another certificate.
    import_external(instance, names=(EXT_SAN,))


@pytest.mark.parametrize('case,code', [
    ('does not name it', 'INVALID_CERTIFICATE_IMPORT'),
    ('same certificate', 'REPLACEMENT_UNCHANGED'),
    ('expires earlier', 'REPLACEMENT_EXPIRES_EARLIER'),
    ('name taken', 'NAMES_ALREADY_MANAGED'),
    ('lineage', 'CERTIFICATE_HAS_LINEAGE'),
    ('not a bundle', 'INVALID_CERTIFICATE_IMPORT'),
    ('flag not a boolean', None),
])
def test_what_a_replacement_refuses(instance, case, code):
    first = make_bundle(names=(EXT, EXT_SAN), end=120)
    assert instance.post(external(first)).status_code == 201
    options = {}
    if case == 'does not name it':
        bundle = make_bundle(names=(EXT_SAN,), end=200)
    elif case == 'same certificate':
        bundle = first
    elif case == 'expires earlier':
        bundle = make_bundle(names=(EXT, EXT_SAN), end=60)
    elif case == 'name taken':
        _managed(instance, ('taken.example.com',))
        bundle = make_bundle(names=(EXT, 'taken.example.com'), end=200)
    elif case == 'lineage':
        (instance.cert_root / EXT / 'live').mkdir()
        bundle = make_bundle(names=(EXT, EXT_SAN), end=200)
    elif case == 'not a bundle':
        bundle = {**make_bundle(names=(EXT,), end=200), 'private_key': 'not a key'}
    else:
        bundle, options = make_bundle(names=(EXT,), end=200), {'allow_earlier_expiry': 'yes'}
    before = (instance.cert_root / EXT / 'cert.pem').read_bytes()

    response = replace(instance, bundle, **options)

    assert response.status_code in (400, 409), response.get_json()
    # A flag that is not a boolean is refused by the model, before the route.
    assert response.get_json().get('code') == code
    assert (instance.cert_root / EXT / 'cert.pem').read_bytes() == before
    assert not [event for event, _ in instance.published if event == 'certificate_renewed']


def test_an_earlier_expiry_is_accepted_when_asked_for(instance):
    import_external(instance)
    response = replace(instance, make_bundle(names=(EXT, EXT_SAN), end=60), allow_earlier_expiry=True)
    assert response.status_code == 200, response.get_json()
    assert instance.client.get(f'/api/certificates/{EXT}', headers=instance.headers).get_json()['days_left'] < 61


def test_only_an_external_certificate_is_replaced(instance):
    _managed(instance, ('renewed.example.com',))
    response = replace(instance, make_bundle(names=('renewed.example.com',), end=200),
                       domain='renewed.example.com')
    assert response.status_code == 409
    assert response.get_json()['code'] == 'CERTIFICATE_NOT_EXTERNAL'


@pytest.mark.parametrize('names', [('nothing.example.com',), (EXT,)])
def test_a_certificate_that_does_not_exist_is_not_found(instance, names):
    """Whatever the upload names: the certificate is looked for first."""
    response = replace(instance, make_bundle(names=names, end=200), domain='nothing.example.com')
    assert response.status_code == 404
    assert response.get_json()['code'] == 'CERTIFICATE_NOT_FOUND'
    assert not (instance.cert_root / 'nothing.example.com').exists()


def test_a_served_certificate_that_does_not_parse_is_replaced(instance):
    """The upload is how a broken certificate is repaired, so a served copy
    that cannot be read is not compared, and not kept."""
    import_external(instance)
    (instance.cert_root / EXT / 'cert.pem').write_text('not a certificate')
    response = replace(instance, make_bundle(names=(EXT, EXT_SAN), end=60))
    assert response.status_code == 200, response.get_json()


@pytest.mark.parametrize('lost', ['metadata', 'settings'])
def test_a_replacement_restores_the_marker_it_lost(instance, lost):
    import_external(instance)
    _lose(instance, lost)
    response = replace(instance, make_bundle(names=(EXT, EXT_SAN), end=200))
    assert response.status_code == 200, response.get_json()
    stored = metadata(instance, EXT)
    assert stored['external'] is True and stored['imported_at'] and stored['created_at']
    entry = settings_entry(instance, EXT)
    assert entry['external'] is True and entry['auto_renew'] is False


def test_a_scoped_key_must_cover_every_name_of_the_replacement(instance):
    import_external(instance, names=(EXT,))
    ok, key = instance.managers['auth'].create_api_key('scoped', role='operator', allowed_domains=[EXT])
    assert ok
    headers = {'Authorization': 'Bearer ' + key['token']}
    widened = replace(instance, make_bundle(names=(EXT, 'elsewhere.example.org'), end=200), headers=headers)
    assert widened.status_code == 403
    assert replace(instance, make_bundle(names=(EXT,), end=200), headers=headers).status_code == 200


def test_a_replacement_and_an_import_sharing_a_name_cannot_both_pass(instance, monkeypatch):
    """The replacement checks the names and writes under the lock the import
    takes, so the name both add ends up with one of them."""
    import_external(instance, names=(EXT,))
    service = instance.managers['cert_service']
    write = instance.certs.replace_external_certificate
    writing = threading.Event()

    def slow_write(*args, **kwargs):
        writing.set()
        threading.Event().wait(0.3)
        return write(*args, **kwargs)

    monkeypatch.setattr(instance.certs, 'replace_external_certificate', slow_write)
    results = []
    replacement = make_bundle(names=(EXT, 'shared.example.com'), end=200)
    other = make_bundle(names=('other.example.com', 'shared.example.com'))

    def run(call):
        try:
            call()
            results.append('done')
        except ValueError as error:
            results.append(type(error).__name__)

    first = threading.Thread(target=run, args=(lambda: service.replace_external(
        domain=EXT, certificate=replacement['certificate'], chain=replacement['chain'],
        private_key=replacement['private_key'], user={'username': 'admin'}),))
    first.start()
    assert writing.wait(5)
    second = threading.Thread(target=run, args=(lambda: service.import_certificate(
        certificate=other['certificate'], chain=other['chain'], private_key=other['private_key'],
        external=True, auto_renew=False, user={'username': 'admin'}),))
    second.start()
    first.join(10)
    second.join(10)
    assert sorted(results) == ['CertificateNamesTaken', 'done']



def test_a_replacement_request_too_large_is_refused_before_it_is_read(instance):
    import_external(instance)
    bundle = make_bundle(names=(EXT,), end=200)
    response = replace(instance, {**bundle, 'certificate': bundle['certificate'] + ' ' * (4 * 64 * 1024)})
    assert response.status_code == 413
    assert response.get_json()['code'] == 'REQUEST_TOO_LARGE'


def test_a_name_that_is_not_a_domain_is_refused(instance):
    response = replace(instance, make_bundle(names=(EXT,), end=200), domain='not_a_domain!')
    assert response.status_code == 400
    assert response.get_json()['code'] == 'INVALID_REQUEST'


def test_a_busy_certificate_is_not_replaced(instance, monkeypatch):
    import_external(instance)
    before = (instance.cert_root / EXT / 'cert.pem').read_bytes()

    @contextmanager
    def busy(domain):
        raise DomainOperationInProgress(domain)
        yield

    monkeypatch.setattr(instance.certs, 'domain_lock', busy)
    response = replace(instance, make_bundle(names=(EXT, EXT_SAN), end=200))
    assert response.status_code == 409
    assert response.get_json()['code'] == 'DOMAIN_OPERATION_IN_PROGRESS'
    assert (instance.cert_root / EXT / 'cert.pem').read_bytes() == before


def test_a_replacement_that_cannot_be_written_says_so_and_nothing_of_the_key(instance, monkeypatch, caplog):
    import_external(instance)
    new = make_bundle(names=(EXT, EXT_SAN), end=200)

    def unwritable(*args, **kwargs):
        raise OSError('disk full while writing ' + new['private_key'])

    monkeypatch.setattr(instance.certs, 'replace_external_certificate', unwritable)
    response = replace(instance, new)
    assert response.status_code == 500
    assert response.get_json()['code'] == 'CERTIFICATE_REPLACE_FAILED'
    assert 'PRIVATE KEY' not in response.get_data(as_text=True)
    assert 'PRIVATE KEY' not in caplog.text
    assert not [event for event, _ in instance.published if event == 'certificate_renewed']


def test_the_service_takes_only_a_boolean_for_an_earlier_expiry(instance):
    import_external(instance)
    bundle = make_bundle(names=(EXT, EXT_SAN), end=60)
    with pytest.raises(ValueError, match='allow_earlier_expiry must be a boolean'):
        instance.managers['cert_service'].replace_external(
            domain=EXT, certificate=bundle['certificate'], chain=bundle['chain'],
            private_key=bundle['private_key'], allow_earlier_expiry='yes', user={'username': 'admin'})


# --------------------------------------------------------------------------- #
# Names an external certificate covers: no issuance takes them
# --------------------------------------------------------------------------- #

def _prepare_create(instance, domain, sans=()):
    return instance.managers['cert_service'].prepare_create(
        domain=domain, san_domains=list(sans), dns_provider='cloudflare', account_id='dns-prod',
        user={'username': 'admin'})


def _create(instance, domain, sans=(), **options):
    return instance.client.post('/api/certificates/create', headers=instance.headers, json={
        'domain': domain, 'san_domains': list(sans), 'dns_provider': 'cloudflare',
        'account_id': 'dns-prod', **options})


@pytest.mark.parametrize('domain,sans,taken', [
    ('new.example.com', (EXT_SAN,), EXT_SAN),              # its SAN, as a SAN
    (EXT_SAN, ('new.example.com',), EXT_SAN),              # its SAN, as the primary
    ('new.example.com', (EXT,), EXT),                      # its primary, as a SAN
    ('new.example.com', ('EXT-SAN.Example.COM',), 'EXT-SAN.Example.COM'),  # without case
])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_a_create_cannot_take_a_name_an_external_certificate_covers(instance, domain, sans, taken, mode):
    import_external(instance)
    response = _create(instance, domain, sans, **({'async': True} if mode == 'async' else {}))
    assert response.status_code == 409, response.get_json()
    body = response.get_json()
    assert body['code'] == 'NAMES_ALREADY_MANAGED'
    assert _names_refused(body) == [taken]
    instance.shell.run.assert_not_called()


def test_the_refusal_does_not_name_the_external_certificate(instance):
    import_external(instance)
    body = _create(instance, 'new.example.com', (EXT_SAN,)).get_json()
    assert EXT not in body['error'].replace(EXT_SAN, '')


def test_a_wildcard_takes_only_the_same_wildcard(instance):
    import_external(instance, names=('*.wild.example.com',))
    _prepare_create(instance, 'a.wild.example.com')
    with pytest.raises(CertificateNamesTaken):
        _prepare_create(instance, 'other.example.com', ('*.wild.example.com',))


def test_two_certificates_certmate_issues_may_still_share_a_name(instance):
    """#854: only an external certificate keeps its names to itself."""
    _managed(instance, ('owner.example.com', 'shared.example.com'))
    _prepare_create(instance, 'new.example.com', ('shared.example.com',))


@pytest.mark.parametrize('lost', [None, 'metadata', 'settings'])
def test_either_record_of_the_marker_protects_its_names(instance, lost):
    import_external(instance)
    _lose(instance, lost)
    with pytest.raises(CertificateNamesTaken):
        _prepare_create(instance, 'new.example.com', (EXT_SAN,))


def test_an_unreadable_external_certificate_keeps_its_own_name_and_blocks_nothing_else(instance, caplog):
    import_external(instance)
    (instance.cert_root / EXT / 'cert.pem').write_text('not a certificate')
    stored = metadata(instance, EXT)
    stored.pop('san_domains')
    (instance.cert_root / EXT / 'metadata.json').write_text(json.dumps(stored))
    _prepare_create(instance, 'free.example.com')
    _prepare_create(instance, 'new.example.com', (EXT_SAN,))
    assert 'could not be read' in caplog.text
    with pytest.raises(CertificateNamesTaken):
        _prepare_create(instance, 'new.example.com', (EXT,))


def test_a_create_from_a_csr_cannot_take_one_either(instance):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    import_external(instance)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device.example.com')]))
           .add_extension(x509.SubjectAlternativeName(
               [x509.DNSName('device.example.com'), x509.DNSName(EXT_SAN)]), critical=False)
           .sign(key, hashes.SHA256()))
    response = _create(instance, 'device.example.com', csr=csr.public_bytes(serialization.Encoding.PEM).decode())
    assert response.status_code == 409, response.get_json()
    assert _names_refused(response.get_json()) == [EXT_SAN]


def test_the_dashboard_create_cannot_take_one(instance):
    import_external(instance)
    response = instance.client.post('/api/web/certificates/create', headers=instance.headers, json={
        'domain': 'new.example.com', 'san_domains': [EXT_SAN], 'dns_provider': 'cloudflare'})
    assert response.status_code == 409, response.get_json()
    assert response.get_json()['code'] == 'NAMES_ALREADY_MANAGED'
    instance.shell.run.assert_not_called()


def test_a_batch_refuses_the_one_that_takes_a_name(instance):
    import_external(instance)
    response = instance.client.post('/api/web/certificates/batch', headers=instance.headers, json={
        'domains': [EXT_SAN, EXT], 'dns_provider': 'cloudflare'})
    assert response.status_code == 200, response.get_json()
    results = {item['domain']: item for item in response.get_json()}
    for name in (EXT_SAN, EXT):
        assert results[name]['success'] is False
        assert results[name]['message'] == 'A name is covered by an external certificate'
    instance.shell.run.assert_not_called()


def test_a_reissue_cannot_add_one(instance):
    import_external(instance)
    _managed(instance, ('owner.example.com',))
    response = instance.client.post('/api/certificates/owner.example.com/reissue', headers=instance.headers,
                                    json={'san_domains': [EXT_SAN]})
    assert response.status_code == 409, response.get_json()
    assert response.get_json()['code'] == 'NAMES_ALREADY_MANAGED'
    assert _names_refused(response.get_json()) == [EXT_SAN]
    # Its own names are its own.
    instance.managers['cert_service'].prepare_reissue(domain='owner.example.com', user={'username': 'admin'})
    instance.shell.run.assert_not_called()


def test_an_import_renewed_through_a_ca_cannot_take_one(instance):
    import_external(instance)
    response = instance.post(ordinary(make_bundle(names=('owner.example.com', EXT_SAN)), 'owner.example.com'))
    assert response.status_code == 409, response.get_json()
    assert response.get_json()['code'] == 'NAMES_ALREADY_MANAGED'
    assert not (instance.cert_root / 'owner.example.com').exists()


def _discovered(instance, fingerprint, names):
    instance.managers['cert_inventory'].record_certificate(
        {'fingerprint_sha256': fingerprint, 'subject_cn': names[0], 'san_dns': list(names),
         'key': {'type': 'EC', 'curve': 'secp256r1'}, 'not_after': '2099-01-01T00:00:00Z'},
        source='ct-log')


def _adoption_plan(instance, fingerprint):
    return instance.client.get(f'/api/inventory/{fingerprint}/adopt', headers=instance.headers).get_json()


def test_an_adoption_plan_says_a_name_is_taken(instance):
    """The plan is what the dashboard offers Adopt from: it says so before the click."""
    _discovered(instance, 'fp-free', ('adopted.example.com',))
    assert _adoption_plan(instance, 'fp-free')['available'] is True
    import_external(instance)
    _discovered(instance, 'fp-adopt', ('adopted.example.com', EXT_SAN))
    plan = _adoption_plan(instance, 'fp-adopt')
    assert plan['available'] is False
    assert EXT_SAN in plan['reason']
    response = instance.client.post('/api/inventory/fp-adopt/adopt', headers=instance.headers)
    assert response.status_code == 400
    assert response.get_json()['code'] == 'ADOPTION_UNAVAILABLE'
    instance.shell.run.assert_not_called()


def test_an_adoption_plan_of_the_external_certificate_says_what_it_is(instance):
    import_external(instance, names=(EXT,))
    _discovered(instance, 'fp-self', (EXT,))
    plan = _adoption_plan(instance, 'fp-self')
    assert plan['available'] is False
    assert 'external certificate' in plan['reason']


def test_a_discovered_name_that_is_not_a_domain_is_left_to_the_checks_that_refuse_it(instance):
    """Discovery reads names from CT logs and remote hosts: the external check
    neither builds a path from one nor hides the refusal that follows."""
    _discovered(instance, 'fp-odd', ('../not a domain',))
    response = instance.client.get('/api/inventory/fp-odd/adopt', headers=instance.headers)
    assert response.status_code == 200
    adopted = instance.client.post('/api/inventory/fp-odd/adopt', headers=instance.headers)
    assert adopted.status_code == 400
    assert 'Invalid domain' in adopted.get_json()['error']


def test_an_adoption_that_meets_one_during_issuance_is_a_conflict(instance, monkeypatch):
    """An external import between the plan and the issuance: the service refuses."""
    import_external(instance)
    _discovered(instance, 'fp-race', ('adopted.example.com', EXT_SAN))
    monkeypatch.setattr(instance.managers['cert_service'], 'external_conflict', lambda *args: None)
    response = instance.client.post('/api/inventory/fp-race/adopt', headers=instance.headers)
    assert response.status_code == 409, response.get_json()
    assert response.get_json()['code'] == 'NAMES_ALREADY_MANAGED'
    instance.shell.run.assert_not_called()
