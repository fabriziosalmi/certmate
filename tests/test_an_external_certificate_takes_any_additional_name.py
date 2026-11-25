"""An external certificate takes single-label and IP names, filed under one CertMate can store (#1538).

A certificate migrated from a private CA (XCA, an internal PKI) often names a
host by its short name (``my-host-name``) and by its address, beside its fully
qualified name. No CA here renews it, so nothing asks whether CertMate could
issue those names: it only has to hold the certificate, file it under one name,
check scope against every name, and keep each name to one certificate. The
names a certificate is filed under are unchanged: a DNS name with a domain, or
an IPv4 address as ``ip-a-b-c-d``. A certificate renewed through a CA keeps
today's rule, DNS names with a domain only.
"""
import ipaddress
import json
import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509

from modules.core.auth import AuthManager
from modules.core.cert_import import (
    CertificateImportError,
    validate_external_identity,
    validate_import_bundle,
    validate_import_renewability,
)
from modules.core.cert_service import CertificateNamesTaken
from tests.test_certificate_import import make_bundle

pytestmark = pytest.mark.unit

FQDN = 'my-host-name.sub.internal'
SHORT = 'my-host-name'
IPV4 = '10.0.0.5'
IPV6 = '2001:db8::1'
NO_PRIMARY = ('An external certificate needs one name CertMate can file it under: '
              'a DNS name with a domain, or an IPv4 address')


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """The application on empty directories, as test_external_certificates sets it up."""
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
        'email': 'ops@example.com',
        'ca_providers': {'sectigo': {'accounts': {'paid': {
            'email': 'ca@example.com', 'acme_url': 'https://acme.sectigo.com/v2/OV',
            'eab_kid': 'test-id', 'eab_hmac': 'test-secret'}}}},
    })
    certs = managers['certificates']
    certs.shell_executor = MagicMock()
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}'}
    return SimpleNamespace(
        managers=managers, certs=certs, shell=certs.shell_executor, client=client, headers=headers,
        cert_root=tmp_path / 'certificates',
        post=lambda data: client.post('/api/certificates/import', json=data, headers=headers))


def dns(name):
    return x509.DNSName(name)


def ip(text):
    return x509.IPAddress(ipaddress.ip_address(text))


def bundle_for(*sans, common_name=SHORT):
    """A bundle as XCA issues one: the short name as CN, the SANs as given."""
    return make_bundle(names=(common_name,), san_names=list(sans))


def external(bundle, **options):
    return {**bundle, 'external': True, **options}


def identity(bundle):
    return validate_external_identity(
        validate_import_bundle(bundle['certificate'], bundle['chain'], bundle['private_key']))


def metadata(instance, name):
    return json.loads((instance.cert_root / name / 'metadata.json').read_text())


def import_external(instance, bundle, **options):
    response = instance.post(external(bundle, **options))
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def service_import(instance, bundle, **options):
    return instance.managers['cert_service'].import_certificate(
        certificate=bundle['certificate'], chain=bundle['chain'], private_key=bundle['private_key'],
        external=True, auto_renew=False, user={'username': 'admin'}, **options)


# --------------------------------------------------------------------------- #
# What is accepted
# --------------------------------------------------------------------------- #

def test_the_issues_certificate_is_filed_under_its_domain_with_its_short_name_beside_it(instance):
    body = import_external(instance, bundle_for(dns(SHORT), dns(FQDN)))
    assert body['domain'] == FQDN
    assert body['san_domains'] == [SHORT]
    stored = metadata(instance, FQDN)
    assert stored['domain'] == FQDN and stored['san_domains'] == [SHORT] and stored['external'] is True
    listing = instance.client.get('/api/certificates', headers=instance.headers).get_json()
    cert = next(c for c in listing if c['domain'] == FQDN)
    assert cert['external'] is True and cert['san_domains'] == [SHORT]
    detail = instance.client.get(f'/api/certificates/{FQDN}', headers=instance.headers)
    assert detail.status_code == 200 and detail.get_json()['san_domains'] == [SHORT]
    instance.shell.run.assert_not_called()


def test_dns_and_ip_names_are_accepted_and_normalised():
    names = identity(bundle_for(dns('My-Host-Name.Sub.Internal.'), ip(IPV4),
                                ip('2001:0DB8:0000:0000:0000:0000:0000:0001'), dns('MY-HOST-NAME'),
                                dns(SHORT)))['names']
    assert names == [FQDN, IPV4, IPV6, SHORT]


def test_an_fqdn_with_ipv4_and_ipv6_names_is_imported_with_them(instance):
    body = import_external(instance, bundle_for(dns(FQDN), ip(IPV4), ip(IPV6)))
    assert body['domain'] == FQDN and body['san_domains'] == [IPV4, IPV6]
    assert metadata(instance, FQDN)['san_domains'] == [IPV4, IPV6]


def test_the_default_primary_is_the_first_name_it_can_be_filed_under(instance):
    body = service_import(instance, bundle_for(dns(SHORT), ip(IPV6), dns(FQDN), ip(IPV4)))
    assert body['domain'] == FQDN
    assert body['san_domains'] == [SHORT, IPV6, IPV4]


def test_the_default_primary_is_a_dns_name_even_after_an_address(instance):
    """A certificate migrated from a private CA is looked for by its host
    name, so a DNS name with a domain is the primary wherever it stands; an
    IPv4 address is the primary only when there is no such name."""
    body = service_import(instance, bundle_for(ip(IPV4), dns(SHORT), dns(FQDN)))
    assert body['domain'] == FQDN
    assert body['san_domains'] == [IPV4, SHORT]


def test_only_an_ipv4_address_is_filed_as_its_ip_name(instance):
    body = import_external(instance, bundle_for(ip(IPV4), common_name=IPV4))
    assert body['domain'] == 'ip-10-0-0-5' and body['san_domains'] == []
    stored = metadata(instance, 'ip-10-0-0-5')
    assert stored['domain'] == 'ip-10-0-0-5' and stored['external'] is True
    detail = instance.client.get('/api/certificates/ip-10-0-0-5', headers=instance.headers).get_json()
    assert detail['external'] is True and detail['ip_address'] == IPV4


@pytest.mark.parametrize('requested,filed', [
    (FQDN, FQDN), (IPV4, 'ip-10-0-0-5'), ('ip-10-0-0-5', 'ip-10-0-0-5'),
])
def test_a_requested_primary_is_filed_as_its_name(instance, requested, filed):
    body = service_import(instance, bundle_for(dns(SHORT), dns(FQDN), ip(IPV4)), domain=requested)
    assert body['domain'] == filed
    assert filed not in body['san_domains'] and len(body['san_domains']) == 2


@pytest.mark.parametrize('requested', [SHORT, IPV6])
def test_a_requested_primary_it_cannot_be_filed_under_is_refused(instance, requested):
    with pytest.raises(ValueError, match='CertMate can file'):
        service_import(instance, bundle_for(dns(SHORT), dns(FQDN), ip(IPV6)), domain=requested)
    assert not any(instance.cert_root.iterdir())


# --------------------------------------------------------------------------- #
# What is refused
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('sans', [
    [dns(SHORT)], [dns(SHORT), dns('other-host')], [ip(IPV6)], [dns(SHORT), ip(IPV6)],
], ids=['one-short-name', 'two-short-names', 'only-ipv6', 'short-and-ipv6'])
def test_a_certificate_with_no_name_it_can_be_filed_under_is_refused(instance, sans):
    response = instance.post(external(bundle_for(*sans)))
    assert response.status_code == 400
    assert response.get_json()['error'] == NO_PRIMARY
    assert not any(instance.cert_root.iterdir())


@pytest.mark.parametrize('name', ['bad_label', '-leading', 'a..b', 'host.b@d', '*.short', 'x' * 64,
                                  '10.0.0.5', '167772165', '0x0a000005'])
def test_a_malformed_name_is_still_refused(name):
    """The last three are 10.0.0.5 written as a DNS name: inet_aton reads the
    two single labels as that address, so they would take it past the check
    that keeps an address to one certificate."""
    with pytest.raises(CertificateImportError, match='cannot use'):
        identity(bundle_for(dns(FQDN), dns(name)))


def test_a_name_that_is_neither_dns_nor_ip_is_still_refused():
    with pytest.raises(CertificateImportError, match='Only DNS names and IP addresses'):
        identity(bundle_for(dns(FQDN), x509.RFC822Name('ops@example.com')))


@pytest.mark.parametrize('sans,message', [
    ([dns(FQDN), dns(SHORT)], 'cannot renew'),
    ([dns(FQDN), ip(IPV4)], 'Only DNS names are supported for automatic renewal'),
])
def test_a_certificate_renewed_through_a_ca_still_takes_dns_names_with_a_domain_only(sans, message):
    data = bundle_for(*sans, common_name=FQDN)
    with pytest.raises(CertificateImportError, match=message):
        validate_import_renewability(
            validate_import_bundle(data['certificate'], data['chain'], data['private_key']))


def test_the_import_through_a_ca_refuses_a_short_name_over_http(instance):
    response = instance.post({**bundle_for(dns(FQDN), dns(SHORT), common_name=FQDN),
                              'ca_provider': 'sectigo', 'ca_account_id': 'paid',
                              'challenge_type': 'prevalidated'})
    assert response.status_code == 400
    assert 'cannot renew' in response.get_json()['error']


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('other', [dns(SHORT), ip(IPV4), ip(IPV6)], ids=['short', 'ipv4', 'ipv6'])
def test_a_scoped_key_cannot_import_a_name_outside_its_scope(instance, other):
    ok, key = instance.managers['auth'].create_api_key(
        'scoped', role='operator', allowed_domains=[FQDN, '*.sub.internal'])
    assert ok
    response = instance.client.post(
        '/api/certificates/import', json=external(bundle_for(dns(FQDN), other)),
        headers={'Authorization': 'Bearer ' + key['token']})
    assert response.status_code == 403
    assert not any(instance.cert_root.iterdir())


def test_a_scoped_key_cannot_import_an_ipv4_certificate(instance):
    ok, key = instance.managers['auth'].create_api_key('scoped', role='operator', allowed_domains=[FQDN])
    assert ok
    response = instance.client.post(
        '/api/certificates/import', json=external(bundle_for(ip(IPV4), common_name=IPV4)),
        headers={'Authorization': 'Bearer ' + key['token']})
    assert response.status_code == 403
    assert not any(instance.cert_root.iterdir())


@pytest.mark.parametrize('address,pattern', [
    ('10.0.0.5', '*.0.0.5'), ('10.0.0.5', '*.5'), ('::ffff:10.0.0.5', '*.0.5'),
])
def test_a_wildcard_scope_never_matches_an_address(address, pattern):
    """A scope pattern is a DNS name: an address is in scope only when the
    scope names it exactly. A pattern stored by hand that ends in digits must
    not take ``10.0.0.5`` for a subdomain of ``0.0.5``."""
    assert AuthManager.domain_matches_scope(address, [pattern]) is False
    assert AuthManager.domain_matches_scope(address, [address]) is True


# --------------------------------------------------------------------------- #
# One certificate per name
# --------------------------------------------------------------------------- #

def _managed_ip_certificate(instance, address, *, on_disk):
    """A certificate CertMate issued for an address, filed as ip-<dashed>."""
    name = 'ip-' + address.replace('.', '-')
    instance.managers['settings'].update(
        lambda s: s.update(domains=[*(s.get('domains') or []), {'domain': name}]))
    if on_disk:
        directory = instance.cert_root / name
        directory.mkdir()
        data = make_bundle(names=(address,), san_names=[ip(address)])
        (directory / 'cert.pem').write_text(data['certificate'])
        (directory / 'metadata.json').write_text(json.dumps({'domain': name, 'san_domains': []}))
    return name


@pytest.mark.parametrize('on_disk', [True, False], ids=['on-disk', 'registered-only'])
def test_an_address_an_ip_certificate_covers_refuses_the_import(instance, on_disk):
    _managed_ip_certificate(instance, IPV4, on_disk=on_disk)
    response = instance.post(external(bundle_for(dns(FQDN), ip(IPV4))))
    assert response.status_code == 409, response.get_json()
    body = response.get_json()
    assert body['code'] == 'NAMES_ALREADY_MANAGED'
    assert body['error'].rsplit(': ', 1)[1] == IPV4
    assert not (instance.cert_root / FQDN).exists()


@pytest.mark.parametrize('first,second,taken', [
    ([dns('a.sub.internal'), ip(IPV4)], [dns('b.sub.internal'), ip(IPV4)], True),
    ([dns('a.sub.internal'), ip(IPV6)], [dns('b.sub.internal'), ip('2001:db8:0::1')], True),
    ([dns('a.sub.internal'), dns(SHORT)], [dns('b.sub.internal'), dns('MY-HOST-NAME')], True),
    ([dns('a.sub.internal'), dns(SHORT)], [dns('b.sub.internal'), dns(SHORT + '2')], False),
    ([dns('a.sub.internal'), ip(IPV4)], [dns('b.sub.internal'), ip('10.0.0.50')], False),
    ([ip(IPV4)], [dns('b.sub.internal'), ip(IPV4)], True),
])
def test_two_external_certificates_never_share_a_short_name_or_an_address(instance, first, second, taken):
    import_external(instance, bundle_for(*first, common_name='first'))
    response = instance.post(external(bundle_for(*second, common_name='second')))
    assert (response.status_code == 409) is taken, response.get_json()


def test_a_managed_ip_certificate_cannot_take_an_address_an_external_one_covers(instance):
    import_external(instance, bundle_for(dns(FQDN), ip('8.8.8.8')))
    with pytest.raises(CertificateNamesTaken):
        instance.managers['cert_service'].prepare_create(
            domain='8.8.8.8', challenge_type='http-01', user={'username': 'admin'})


def test_an_ipv4_certificate_is_replaced_by_its_address(instance):
    import_external(instance, bundle_for(ip(IPV4), common_name=IPV4))
    replacement = make_bundle(names=(IPV4,), san_names=[ip(IPV4), dns(SHORT)], end=200)
    response = instance.client.post('/api/certificates/ip-10-0-0-5/replace',
                                    json=replacement, headers=instance.headers)
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['san_domains'] == [SHORT]
    assert metadata(instance, 'ip-10-0-0-5')['san_domains'] == [SHORT]


# --------------------------------------------------------------------------- #
# The preview agrees with the import
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('sans,accepted', [
    ([dns(SHORT), dns(FQDN)], True),
    ([dns(FQDN), ip(IPV4), ip(IPV6)], True),
    ([ip(IPV4)], True),
    ([dns(SHORT)], False),
    ([ip(IPV6)], False),
], ids=['issue', 'fqdn-ipv4-ipv6', 'ipv4', 'short', 'ipv6'])
def test_the_external_preview_answers_as_the_import_does(instance, sans, accepted):
    data = external(bundle_for(*sans))
    preview = instance.client.post('/api/web/certificates/import/preview', json=data,
                                   headers=instance.headers)
    imported = instance.post(data)
    assert (preview.status_code == 200) is accepted, preview.get_json()
    assert (imported.status_code == 201) is accepted, imported.get_json()
    if accepted:
        assert preview.get_json()['validated'] is True
    else:
        assert preview.get_json()['error'] == imported.get_json()['error'] == NO_PRIMARY


# --------------------------------------------------------------------------- #
# What reads the names afterwards
# --------------------------------------------------------------------------- #

def test_domain_health_checks_no_address_an_external_certificate_covers(instance):
    import_external(instance, bundle_for(dns(FQDN), ip(IPV4), ip(IPV6), dns(SHORT)))
    tracked = instance.managers['domain_health'].tracked_names()
    assert FQDN in tracked
    assert IPV4 not in tracked and IPV6 not in tracked


def test_the_names_covered_include_its_addresses_with_its_metadata_lost(instance):
    import_external(instance, bundle_for(dns(FQDN), ip(IPV4)))
    (instance.cert_root / FQDN / 'metadata.json').unlink()
    instance.certs._invalidate_certificate_info_cache(FQDN)
    assert IPV4 in instance.certs.names_covered(FQDN)
