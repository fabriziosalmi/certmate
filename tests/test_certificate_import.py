"""Import validates real PEMs, issues nothing, and makes the first renewal work."""
import datetime
import json
import secrets
import stat
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from modules.core.cert_import import MAX_IMPORT_PEM_BYTES, validate_import_bundle
from modules.core.domain_paths import lineage_live_dir, renewal_conf

pytestmark = pytest.mark.unit
DOMAIN = 'import.example.com'
SAN = 'other.example.com'
PEM = serialization.Encoding.PEM


def make_bundle(*, names=(DOMAIN, SAN), start=-1, end=120, rsa_key=False, ca=False,
                root_ca=True, root_end=365, intermediate=False, key_usage=None,
                root_extensions=(), intermediate_extensions=(), leaf_extensions=(),
                root_path_length=1, self_issued_intermediate=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    key = rsa.generate_private_key(65537, 2048) if rsa_key else ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Import test root')])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=root_end))
            .add_extension(x509.BasicConstraints(ca=root_ca, path_length=root_path_length if root_ca else None), critical=True))
    for extension in root_extensions:
        root = root.add_extension(extension, critical=True)
    root = root.sign(root_key, hashes.SHA256())
    issuer_name, issuer_key = root_name, root_key
    chain = root.public_bytes(PEM)
    if intermediate:
        issuer_name = (root_name if self_issued_intermediate else
                       x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Intermediate')]))
        issuer_key = ec.generate_private_key(ec.SECP256R1())
        issuer = (x509.CertificateBuilder().subject_name(issuer_name).issuer_name(root_name)
                  .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now - datetime.timedelta(days=1))
                  .not_valid_after(now + datetime.timedelta(days=180))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True))
        for extension in intermediate_extensions:
            issuer = issuer.add_extension(extension, critical=True)
        issuer = issuer.sign(root_key, hashes.SHA256())
        chain = issuer.public_bytes(PEM) + chain
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(issuer_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + datetime.timedelta(days=start))
            .not_valid_after(now + datetime.timedelta(days=end))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if key_usage is not None:
        cert = cert.add_extension(key_usage, critical=True)
    for extension in leaf_extensions:
        cert = cert.add_extension(extension, critical=True)
    cert = cert.sign(issuer_key, hashes.SHA256())
    return {'certificate': cert.public_bytes(PEM).decode(), 'chain': chain.decode(),
            'private_key': key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()).decode()}


@pytest.fixture
def bundle():
    return make_bundle()


@pytest.mark.parametrize('rsa_key', [False, True])
def test_accepts_matching_rsa_and_ecdsa_bundles(rsa_key):
    data = make_bundle(rsa_key=rsa_key)
    parsed = validate_import_bundle(**data)
    assert parsed['names'] == [DOMAIN, SAN]
    assert parsed['key_options']['key_type'] == ('rsa' if rsa_key else 'ecdsa')
    assert parsed['files']['fullchain.pem'] == parsed['files']['cert.pem'] + parsed['files']['chain.pem']


@pytest.mark.parametrize('field', ['certificate', 'chain', 'private_key'])
@pytest.mark.parametrize('bad', ['', None, 12, {}, 'garbage', 'x' * (MAX_IMPORT_PEM_BYTES + 1)])
def test_refuses_missing_malformed_or_oversized_inputs(bundle, field, bad):
    bundle[field] = bad
    with pytest.raises(ValueError):
        validate_import_bundle(**bundle)


@pytest.mark.parametrize('start,end', [(-10, -1), (1, 120)])
def test_refuses_expired_or_future_certificates(start, end):
    with pytest.raises(ValueError, match='expired or not yet valid'):
        validate_import_bundle(**make_bundle(start=start, end=end))


def test_refuses_mismatched_key_and_unrelated_chain(bundle):
    other = make_bundle()
    with pytest.raises(ValueError, match='does not match'):
        validate_import_bundle(**{**bundle, 'private_key': other['private_key']})
    with pytest.raises(ValueError, match='issuer order'):
        validate_import_bundle(**{**bundle, 'chain': other['chain']})


def test_refuses_encrypted_private_keys(bundle):
    key = serialization.load_pem_private_key(bundle['private_key'].encode(), None)
    bundle['private_key'] = key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.BestAvailableEncryption(b'secret')).decode()
    with pytest.raises(ValueError, match='unencrypted'):
        validate_import_bundle(**bundle)


@pytest.mark.parametrize('rsa_key,permission,accepted', [
    (False, 'digital_signature', True), (True, 'digital_signature', True),
    (True, 'key_encipherment', True), (False, 'key_agreement', True),
    (False, 'data_encipherment', False), (True, 'data_encipherment', False),
    (False, 'key_encipherment', False), (True, 'key_agreement', False),
])
def test_leaf_key_usage_must_permit_tls(rsa_key, permission, accepted):
    usage = x509.KeyUsage(
        digital_signature=permission == 'digital_signature', content_commitment=False,
        key_encipherment=permission == 'key_encipherment',
        data_encipherment=permission == 'data_encipherment',
        key_agreement=permission == 'key_agreement', key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False)
    data = make_bundle(rsa_key=rsa_key, key_usage=usage)
    if accepted:
        assert validate_import_bundle(**data)['names'] == [DOMAIN, SAN]
    else:
        with pytest.raises(ValueError, match='key usage'):
            validate_import_bundle(**data)


def test_refuses_leaf_in_chain_and_fullchain_as_leaf(bundle):
    with pytest.raises(ValueError, match='duplicate'):
        validate_import_bundle(**{**bundle, 'chain': bundle['certificate'] + bundle['chain']})
    with pytest.raises(ValueError, match='exactly one'):
        validate_import_bundle(**{**bundle, 'certificate': bundle['certificate'] + bundle['chain']})
    with pytest.raises(ValueError, match='not a CA'):
        validate_import_bundle(**make_bundle(ca=True))


def test_intermediate_chain_order_and_optional_root():
    data = make_bundle(intermediate=True)
    issuers = x509.load_pem_x509_certificates(data['chain'].encode())
    assert validate_import_bundle(**data)['names'] == [DOMAIN, SAN]
    assert validate_import_bundle(**{**data, 'chain': issuers[0].public_bytes(PEM)})['names'] == [DOMAIN, SAN]
    with pytest.raises(ValueError, match='issuer order'):
        validate_import_bundle(**{**data, 'chain': b''.join(c.public_bytes(PEM) for c in reversed(issuers))})


@pytest.mark.parametrize('self_issued', [False, True])
def test_path_length_excludes_self_issued_key_rollover(self_issued):
    data = make_bundle(intermediate=True, root_path_length=0,
                       self_issued_intermediate=self_issued)
    if self_issued:
        assert validate_import_bundle(**data)['names'] == [DOMAIN, SAN]
    else:
        with pytest.raises(ValueError, match='issuer order'):
            validate_import_bundle(**data)


@pytest.mark.parametrize('options', [{'root_ca': False}, {'root_end': -1}])
def test_chain_issuers_must_be_valid_cas(options):
    with pytest.raises(ValueError):
        validate_import_bundle(**make_bundle(**options))


@pytest.mark.parametrize('location', ['root_extensions', 'intermediate_extensions'])
@pytest.mark.parametrize('purpose,accepted', [
    (ExtendedKeyUsageOID.CLIENT_AUTH, False),
    (ExtendedKeyUsageOID.SERVER_AUTH, True),
    (ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE, False),
])
def test_issuer_purpose_must_allow_tls(location, purpose, accepted):
    data = make_bundle(intermediate=True, **{location: [x509.ExtendedKeyUsage([purpose])]})
    if accepted:
        assert validate_import_bundle(**data)['names'] == [DOMAIN, SAN]
    else:
        with pytest.raises(ValueError, match='TLS server authentication'):
            validate_import_bundle(**data)


@pytest.mark.parametrize('location', ['leaf_extensions', 'root_extensions', 'intermediate_extensions'])
@pytest.mark.parametrize('extension', [
    x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5.6.7'), b'\x05\x00'),
    x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None),
])
def test_unsupported_critical_extensions_are_rejected(location, extension):
    data = make_bundle(intermediate=True, **{location: [extension]})
    with pytest.raises(ValueError, match='unsupported critical extension'):
        validate_import_bundle(**data)


def test_any_usage_with_explicit_server_auth_is_allowed():
    data = make_bundle(root_extensions=[x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE, ExtendedKeyUsageOID.SERVER_AUTH])])
    assert validate_import_bundle(**data)['names'] == [DOMAIN, SAN]


@pytest.mark.parametrize('location', ['root_extensions', 'intermediate_extensions'])
@pytest.mark.parametrize('names,permitted,excluded,accepted', [
    ((DOMAIN, SAN), ['example.com'], None, True),
    ((DOMAIN, SAN), ['.EXAMPLE.COM'], None, True),
    (('example.com',), ['example.com'], None, True),
    (('example.com',), ['.example.com'], None, False),
    ((DOMAIN, SAN), ['allowed.example.com'], None, False),
    ((DOMAIN, SAN), [DOMAIN], None, False),
    (('badexample.com',), ['example.com'], None, False),
    ((DOMAIN, SAN), None, ['unrelated.example.com'], True),
    ((DOMAIN, SAN), ['example.com'], [SAN], False),
    ((DOMAIN, SAN), None, ['.example.com'], False),
    ((DOMAIN, SAN), ['com'], None, True),
])
def test_dns_name_constraints(location, names, permitted, excluded, accepted):
    constraints = x509.NameConstraints(
        [x509.DNSName(n) for n in permitted] if permitted else None,
        [x509.DNSName(n) for n in excluded] if excluded else None)
    data = make_bundle(names=names, intermediate=True, **{location: [constraints]})
    if accepted:
        assert validate_import_bundle(**data)['names'] == list(names)
    else:
        with pytest.raises(ValueError, match='name constraints'):
            validate_import_bundle(**data)


def test_root_constraints_also_apply_to_intermediate_dns_names():
    data = make_bundle(intermediate=True,
        root_extensions=[x509.NameConstraints([x509.DNSName('example.com')], None)],
        intermediate_extensions=[x509.SubjectAlternativeName([x509.DNSName('outside.test')])])
    with pytest.raises(ValueError, match='name constraints'):
        validate_import_bundle(**data)


@pytest.mark.parametrize('subtree', [x509.RFC822Name('example.com'),
                                    x509.DNSName('..example.com')])
def test_unsupported_name_constraints_fail_closed(subtree):
    data = make_bundle(root_extensions=[x509.NameConstraints([subtree], None)])
    with pytest.raises(ValueError, match='constraint'):
        validate_import_bundle(**data)


def test_constrained_wildcards_are_explicitly_refused():
    data = make_bundle(names=('*.example.com',), root_extensions=[
        x509.NameConstraints([x509.DNSName('example.com')], None)])
    with pytest.raises(ValueError, match='Wildcard certificates with name constraints'):
        validate_import_bundle(**data)


def test_intermediate_cannot_relax_root_name_constraints():
    data = make_bundle(intermediate=True,
        root_extensions=[x509.NameConstraints([x509.DNSName('allowed.example.com')], None)],
        intermediate_extensions=[x509.NameConstraints([x509.DNSName('example.com')], None)])
    with pytest.raises(ValueError, match='name constraints'):
        validate_import_bundle(**data)


@pytest.mark.parametrize('names', [('https://import.example.com/',), ('../outside',),
                                  tuple(f'host{i}.example.com' for i in range(101))])
def test_certificate_names_must_be_renewable_dns_names(names):
    with pytest.raises(ValueError):
        validate_import_bundle(**make_bundle(names=names))


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
    return SimpleNamespace(
        app=app, managers=managers, certs=certs, shell=shell,
        client=client, headers=headers, directory=tmp_path / 'certificates' / DOMAIN,
        post=lambda data: client.post('/api/certificates/import', json=data, headers=headers))


def import_payload(bundle, **options):
    return {**bundle, 'domain': DOMAIN, 'ca_provider': 'sectigo', 'ca_account_id': 'paid',
            'challenge_type': 'prevalidated', **options}


def test_import_is_listed_downloadable_and_never_issues(instance, bundle):
    response = instance.post(import_payload(bundle))
    assert response.status_code == 201, response.get_json()
    instance.shell.run.assert_not_called()
    stored = json.loads((instance.directory / 'metadata.json').read_text())
    assert stored['ca_provider'] == 'sectigo' and stored['ca_account_id'] == 'paid'
    assert stored['challenge_type'] == 'prevalidated' and stored['dns_provider'] is None
    assert stored['email'] == 'ca@example.com'
    assert stored['san_domains'] == [SAN]
    assert stored['key_type'] == 'ecdsa' and stored['imported_at']
    assert stat.S_IMODE((instance.directory / 'privkey.pem').stat().st_mode) == 0o600
    assert not renewal_conf(instance.directory, DOMAIN).exists()
    listing = instance.client.get('/api/certificates', headers=instance.headers).get_json()
    cert = next(c for c in listing if c['domain'] == DOMAIN)
    assert cert['exists'] and cert['usable'] and not cert['needs_renewal']
    assert cert['imported_at'] and cert['ca_account_id'] == 'paid'
    downloaded = instance.client.get(f'/api/certificates/{DOMAIN}/download/cert', headers=instance.headers)
    assert downloaded.status_code == 200
    assert bundle['certificate'].encode() in downloaded.data
    assert instance.certs.renew_certificate(DOMAIN)['renewed'] is False
    instance.shell.run.assert_not_called()


@pytest.mark.parametrize('options', [
    {'domain': '../escape'}, {'domain': 'wrong.example.com'},
    {'ca_account_id': 'missing'}, {'ca_provider': 'nonexistent'},
    {'challenge_type': 'unknown'}, {'challenge_type': 'prevalidated', 'ca_provider': 'letsencrypt'},
    {'challenge_type': 'dns-01', 'account_id': 'missing'},
])
def test_invalid_names_or_renewal_configuration_write_nothing(instance, bundle, options):
    response = instance.post(import_payload(bundle, **options))
    assert response.status_code == 400, response.get_json()
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


def test_dns_account_is_pinned_for_the_next_renewal(instance, bundle):
    response = instance.post(import_payload(bundle, challenge_type='dns-01',
                                            dns_provider='cloudflare', account_id='dns-prod'))
    assert response.status_code == 201, response.get_json()
    stored = json.loads((instance.directory / 'metadata.json').read_text())
    assert stored['dns_provider'] == 'cloudflare' and stored['account_id'] == 'dns-prod'
    entry = next(d for d in instance.managers['settings'].load_settings()['domains'] if d['domain'] == DOMAIN)
    assert entry['dns_account_id'] == 'dns-prod'


def test_unsupported_alias_provider_is_rejected_before_storage(instance, bundle):
    instance.managers['settings'].atomic_update({'dns_providers': {
        'cloudflare': {'accounts': {'dns-prod': {'api_token': 'test-token'}}},
        'hetzner': {'accounts': {'dns-prod': {'api_token': 'test-token'}}}}})
    response = instance.post(import_payload(
        bundle, challenge_type='dns-01', dns_provider='cloudflare',
        account_id='dns-prod', domain_alias='validation.example.com', alias_dns_provider='hetzner'))
    assert response.status_code == 400, response.get_json()
    assert 'does not support' in response.get_json()['error']
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


def test_alias_providers_keep_their_own_default_accounts_at_first_renewal(instance, bundle, monkeypatch):
    instance.managers['settings'].atomic_update({
        'default_accounts': {'cloudflare': 'dns-prod', 'route53': 'alias-prod'},
        'dns_providers': {
            'cloudflare': {'accounts': {'dns-prod': {'api_token': 'test-token'}}},
            'route53': {'accounts': {'alias-prod': {'auth_mode': 'iam_role'}}}}})
    response = instance.post(import_payload(
        bundle, challenge_type='dns-01', dns_provider='cloudflare',
        domain_alias='validation.example.com', alias_dns_provider='route53'))
    assert response.status_code == 201, response.get_json()
    stored = json.loads((instance.directory / 'metadata.json').read_text())
    assert stored['account_id'] is None
    hook = MagicMock()
    monkeypatch.setattr(instance.certs, '_answer_through_alias_hook', hook)
    instance.shell.run.return_value = SimpleNamespace(returncode=1, stdout='', stderr='CA refused')
    with pytest.raises(RuntimeError):
        instance.certs.renew_certificate(DOMAIN, force=True)
    assert hook.call_args.kwargs['dns_config']['auth_mode'] == 'iam_role'
    assert hook.call_args.kwargs['provider'] == 'route53'


@pytest.mark.parametrize('global_email,account_email,expected', [
    ('', 'ca@example.com', 'ca@example.com'),
    ('ops@example.com', '', 'ops@example.com'),
    ('', '', None),
])
def test_effective_ca_email_is_shared_by_import_create_and_reissue(
        instance, bundle, global_email, account_email, expected):
    settings = instance.managers['settings']

    def configure(stored):
        stored['email'] = global_email
        stored['ca_providers']['sectigo']['accounts']['paid']['email'] = account_email
    assert settings.update(configure)
    response = instance.post(import_payload(bundle))
    if expected is None:
        assert response.status_code == 400
        assert not instance.directory.exists()
        return
    assert response.status_code == 201, response.get_json()
    stored = json.loads((instance.directory / 'metadata.json').read_text())
    assert stored['email'] == expected
    from modules.core.cert_service import CertificateService
    service = CertificateService(instance.certs, settings, instance.managers['auth'])
    prepared = service.prepare_create(domain=DOMAIN, ca_provider='sectigo',
                                      ca_account_id='paid', challenge_type='prevalidated',
                                      user={'username': 'operator'})
    assert prepared['email'] == expected
    assert service.prepare_reissue(domain=DOMAIN, user={'username': 'operator'})['email'] == expected


def test_import_only_needs_the_three_pems_and_renewal_source(instance, bundle):
    payload = import_payload(bundle)
    del payload['domain']
    response = instance.post(payload)
    assert response.status_code == 201, response.get_json()
    assert response.get_json()['domain'] == DOMAIN
    assert response.get_json()['san_domains'] == [SAN]


@pytest.mark.parametrize('provider', ['letsencrypt', 'letsencrypt_staging'])
@pytest.mark.parametrize('account', [None, 'default'])
def test_letsencrypt_import_accepts_the_existing_global_email_default(instance, bundle, provider, account):
    payload = import_payload(bundle, ca_provider=provider, ca_account_id=account, challenge_type='http-01')
    if account is None:
        del payload['ca_account_id']
    response = instance.post(payload)
    assert response.status_code == 201, response.get_json()
    instance.shell.run.assert_not_called()


def test_import_never_overwrites_existing_material(instance, bundle):
    assert instance.post(import_payload(bundle)).status_code == 201
    before = {p.name: p.read_bytes() for p in instance.directory.iterdir()}
    assert instance.post(import_payload(make_bundle())).status_code == 409
    assert before == {p.name: p.read_bytes() for p in instance.directory.iterdir()}


def test_api_requires_operator_and_every_san_in_scope(instance, bundle):
    payload = import_payload(bundle)
    assert instance.client.post('/api/certificates/import', json=payload).status_code == 401
    for role, scope in [('viewer', None), ('operator', [DOMAIN])]:
        ok, key = instance.managers['auth'].create_api_key('import-' + role, role=role, allowed_domains=scope)
        assert ok
        response = instance.client.post('/api/certificates/import', json=payload,
                                        headers={'Authorization': 'Bearer ' + key['token']})
        assert response.status_code == 403, response.get_json()
    assert not instance.directory.exists()


def test_import_while_domain_busy_returns_conflict(instance, bundle, monkeypatch):
    monkeypatch.setattr(instance.certs, '_domain_lock_timeout', lambda: 0)
    with instance.certs.domain_lock(DOMAIN):
        assert instance.post(import_payload(bundle)).status_code == 409
    assert not instance.directory.exists()


def test_staging_failure_publishes_no_partial_bundle(instance, bundle, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError('Read-only storage')
    monkeypatch.setattr(instance.certs, '_atomic_json_write', fail)
    assert instance.post(import_payload(bundle)).status_code == 500
    assert not instance.directory.exists()
    assert not list(instance.directory.parent.glob('.import-*'))


@pytest.mark.parametrize('failure', ['false', 'exception'])
def test_failed_registration_preserves_bundle_and_sweep_recovers(instance, monkeypatch, failure):
    settings = instance.managers['settings']
    original_save = settings.save_settings

    def fail(*args, **kwargs):
        if failure == 'exception':
            raise OSError('secret-settings-error')
        return False
    monkeypatch.setattr(settings, 'save_settings', fail)
    response = instance.post(import_payload(make_bundle(start=-60, end=1)))
    assert response.status_code == 500, response.get_json()
    assert 'preserved' in response.get_json()['error']
    assert 'secret-settings-error' not in response.get_data(as_text=True)
    original = (instance.directory / 'cert.pem').read_bytes()
    assert not any(d.get('domain') == DOMAIN for d in settings.load_settings(use_cache=False)['domains'])
    monkeypatch.setattr(settings, 'save_settings', original_save)
    assert instance.certs._unregistered_is_renewable(DOMAIN, settings.load_settings()) == (True, None)
    fresh = validate_import_bundle(**make_bundle(end=180))['files']

    def run(command, **kwargs):
        assert command[1] == 'certonly'
        assert (instance.directory / 'cert.pem').read_bytes() == original
        live = lineage_live_dir(instance.directory, DOMAIN)
        live.mkdir(parents=True)
        for name, data in fresh.items():
            (live / name).write_bytes(data)
        return SimpleNamespace(returncode=0, stdout='renewed', stderr='')
    instance.shell.run.side_effect = run
    instance.shell.produces_artifacts = True
    summary = instance.certs.check_renewals()
    assert summary['renewed'] == 1 and summary['reregistered'] == 1
    assert any(d.get('domain') == DOMAIN for d in settings.load_settings(use_cache=False)['domains'])
    assert (instance.directory / 'cert.pem').read_bytes() == fresh['cert.pem']


def test_sweep_registration_failure_is_not_counted_as_success(instance, bundle, monkeypatch):
    assert instance.post(import_payload(bundle)).status_code == 201
    summary = {'reregistered': 0}
    monkeypatch.setattr(instance.managers['settings'], 'update', lambda *args, **kwargs: False)
    instance.certs._reregister_domain(DOMAIN, summary)
    assert summary['reregistered'] == 0


def test_disk_only_prevalidated_certificate_requires_sectigo(instance, bundle):
    assert instance.post(import_payload(bundle)).status_code == 201
    metadata = instance.certs._load_metadata(DOMAIN)
    metadata['ca_provider'] = 'letsencrypt'
    instance.certs._save_metadata(DOMAIN, metadata)
    renewable, reason = instance.certs._unregistered_is_renewable(
        DOMAIN, instance.managers['settings'].load_settings())
    assert not renewable and 'Sectigo' in reason


def test_existing_external_certificate_is_not_overwritten(instance, bundle):
    storage = MagicMock()
    storage.certificate_exists.return_value = True
    instance.certs.storage_manager = storage
    assert instance.post(import_payload(bundle)).status_code == 409
    storage.store_certificate.assert_not_called()
    assert not instance.directory.exists()


def test_unknown_backend_existence_fails_closed_without_exposing_secrets(instance, bundle, caplog):
    storage = MagicMock()
    storage.certificate_exists.side_effect = RuntimeError('secret-backend-credential')
    instance.certs.storage_manager = storage
    response = instance.post(import_payload(bundle))
    assert response.status_code == 500
    assert 'secret-backend-credential' not in response.get_data(as_text=True)
    assert 'secret-backend-credential' not in caplog.text
    storage.store_certificate.assert_not_called()
    assert not instance.directory.exists()


def test_external_storage_failure_is_reported_without_losing_local_bundle(instance, bundle):
    storage = MagicMock()
    storage.certificate_exists.return_value = False
    storage.store_certificate.return_value = False
    storage.get_backend_name.return_value = 'test-backend'
    instance.certs.storage_manager = storage
    response = instance.post(import_payload(bundle))
    assert response.status_code == 201
    assert response.get_json()['storage_warning']
    assert (instance.directory / 'privkey.pem').exists()


def test_http01_refuses_wildcards(instance):
    response = instance.post(import_payload(make_bundle(names=('*.example.com',)),
                                            domain='*.example.com', challenge_type='http-01'))
    assert response.status_code == 400
    instance.shell.run.assert_not_called()


def test_first_renewal_uses_selected_source_and_then_normal_certbot_renew(instance, bundle):
    assert instance.post(import_payload(bundle)).status_code == 201
    original = (instance.directory / 'cert.pem').read_bytes()
    fresh = make_bundle(end=180)
    def run(command, **kwargs):
        assert (instance.directory / 'cert.pem').read_bytes() == original
        assert command[1] == 'certonly'
        assert command[command.index('--server') + 1] == 'https://acme.sectigo.com/v2/OV'
        assert '--eab-kid' in command
        assert DOMAIN in command and SAN in command
        assert '--dns-cloudflare' not in command
        live = lineage_live_dir(instance.directory, DOMAIN)
        live.mkdir(parents=True)
        for name, data in validate_import_bundle(**fresh)['files'].items():
            (live / name).write_bytes(data)
        conf = renewal_conf(instance.directory, DOMAIN)
        conf.parent.mkdir()
        conf.write_text('[renewalparams]\nauthenticator = manual\n')
        return SimpleNamespace(returncode=0, stdout='renewed', stderr='')
    instance.shell.run.side_effect = run
    instance.shell.produces_artifacts = True
    assert instance.certs.renew_certificate(DOMAIN, force=True)['renewed'] is True
    stored = json.loads((instance.directory / 'metadata.json').read_text())
    assert stored['renewed_at'] and stored['ca_account_id'] == 'paid'
    assert 'imported_at' not in stored
    assert (instance.directory / 'cert.pem').read_bytes() != original
    instance.shell.run.side_effect = None
    instance.shell.run.return_value = SimpleNamespace(returncode=0, stdout='not yet due for renewal', stderr='')
    assert instance.certs.renew_certificate(DOMAIN)['renewed'] is False
    assert instance.shell.run.call_args.args[0][1] == 'renew'


@pytest.mark.parametrize('failure', ['publish', 'commit'])
@pytest.mark.parametrize('renewed_on_retry', [False, True])
def test_first_renewal_recovers_metadata_after_publication_failure(
        instance, bundle, monkeypatch, failure, renewed_on_retry):
    assert instance.post(import_payload(bundle)).status_code == 201
    original = (instance.directory / 'cert.pem').read_bytes()
    metadata = instance.certs._load_metadata(DOMAIN)
    metadata['notes'] = 'Keep this deployment'
    assert instance.certs._save_metadata(DOMAIN, metadata)
    fresh = validate_import_bundle(**make_bundle(end=180))['files']

    def issue(command, **kwargs):
        assert command[1] == 'certonly'
        live = lineage_live_dir(instance.directory, DOMAIN)
        live.mkdir(parents=True)
        for name, data in fresh.items():
            (live / name).write_bytes(data)
        conf = renewal_conf(instance.directory, DOMAIN)
        conf.parent.mkdir()
        conf.write_text('[renewalparams]\nauthenticator = manual\n')
        return SimpleNamespace(returncode=0, stdout='renewed', stderr='')

    method = '_publish_flat_files' if failure == 'publish' else '_commit_certificate'
    original_method = getattr(instance.certs, method)

    def fail(*args, **kwargs):
        raise OSError('Simulated publication failure')

    monkeypatch.setattr(instance.certs, method, fail)
    instance.shell.run.side_effect = issue
    instance.shell.produces_artifacts = True
    with pytest.raises(OSError, match='Simulated publication failure'):
        instance.certs.renew_certificate(DOMAIN, force=True)
    assert instance.certs._load_metadata(DOMAIN)['imported_at'] == metadata['imported_at']
    assert (instance.directory / 'cert.pem').read_bytes() == (
        original if failure == 'publish' else fresh['cert.pem'])

    monkeypatch.setattr(instance.certs, method, original_method)
    storage = MagicMock()
    storage.store_certificate.return_value = True
    instance.certs.storage_manager = storage
    replacement = validate_import_bundle(**make_bundle(end=200))['files'] if renewed_on_retry else fresh

    def retry(command, **kwargs):
        assert command[1] == 'renew'
        for name, data in replacement.items():
            (lineage_live_dir(instance.directory, DOMAIN) / name).write_bytes(data)
        return SimpleNamespace(returncode=0, stdout='renewed' if renewed_on_retry else 'not yet due for renewal',
                               stderr='')

    instance.shell.run.side_effect = retry
    assert instance.certs.renew_certificate(DOMAIN, force=True)['renewed'] is True
    stored = instance.certs._load_metadata(DOMAIN)
    assert 'imported_at' not in stored
    assert stored['renewed_at']
    assert stored['created_at'] == metadata['created_at']
    assert stored['notes'] == metadata['notes']
    assert (instance.directory / 'cert.pem').read_bytes() == replacement['cert.pem']
    backend_metadata = storage.store_certificate.call_args.args[2]
    assert 'imported_at' not in backend_metadata
    assert backend_metadata['renewed_at'] == stored['renewed_at']
    assert instance.shell.run.call_count == 2


def test_incomplete_lineage_does_not_clear_import_metadata(instance, bundle):
    assert instance.post(import_payload(bundle)).status_code == 201
    metadata = instance.certs._load_metadata(DOMAIN)
    live = lineage_live_dir(instance.directory, DOMAIN)
    live.mkdir(parents=True)
    (live / 'cert.pem').write_bytes((instance.directory / 'cert.pem').read_bytes())
    result = instance.certs._reconcile_without_renewal(DOMAIN, instance.directory, metadata)
    assert result['renewed'] is False
    stored = instance.certs._load_metadata(DOMAIN)
    assert stored['imported_at'] == metadata['imported_at']
    assert 'renewed_at' not in stored


def test_first_renewal_failure_preserves_the_imported_bundle(instance, bundle):
    assert instance.post(import_payload(bundle)).status_code == 201
    files = {p.name: p.read_bytes() for p in instance.directory.glob('*.pem')}
    instance.shell.run.return_value = SimpleNamespace(returncode=1, stdout='', stderr='CA refused')
    with pytest.raises(RuntimeError):
        instance.certs.renew_certificate(DOMAIN, force=True)
    assert files == {p.name: p.read_bytes() for p in instance.directory.glob('*.pem')}


@pytest.mark.parametrize('requested,expected', [(None, 'shortlived'), ('', None), ('classic', 'classic')])
def test_import_resolves_profile_and_first_renewal_uses_it(instance, bundle, monkeypatch, requested, expected):
    def configure(settings):
        settings['ca_providers']['sectigo']['accounts']['paid']['acme_profile'] = 'shortlived'
    assert instance.managers['settings'].update(configure)
    payload = import_payload(bundle)
    if requested is not None:
        payload['acme_profile'] = requested
    response = instance.post(payload)
    assert response.status_code == 201, response.get_json()
    assert instance.certs._load_metadata(DOMAIN)['acme_profile'] == expected
    instance.shell.run.assert_not_called()
    # Renew the imported selection even if the account default changes later.
    def change_default(settings):
        settings['ca_providers']['sectigo']['accounts']['paid']['acme_profile'] = 'tlsserver'
    assert instance.managers['settings'].update(change_default)
    monkeypatch.setattr(instance.certs, '_profile_still_offered', lambda *args: True)
    instance.shell.run.return_value = SimpleNamespace(returncode=1, stdout='', stderr='CA refused')
    with pytest.raises(RuntimeError):
        instance.certs.renew_certificate(DOMAIN, force=True)
    command = instance.shell.run.call_args.args[0]
    assert '--required-profile' not in command
    if expected:
        assert command[command.index('--preferred-profile') + 1] == expected
    else:
        assert '--preferred-profile' not in command


def test_invalid_account_profile_is_rejected_before_import(instance, bundle):
    def configure(settings):
        settings['ca_providers']['sectigo']['accounts']['paid']['acme_profile'] = 'bad profile!'
    assert instance.managers['settings'].update(configure)
    response = instance.post(import_payload(bundle))
    assert response.status_code == 400, response.get_json()
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


def test_chain_restriction_failure_publishes_nothing(instance):
    data = make_bundle(root_extensions=[
        x509.NameConstraints([x509.DNSName('allowed.example.com')], None)])
    response = instance.post(import_payload(data))
    assert response.status_code == 400, response.get_json()
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


def test_unsupported_critical_extension_publishes_nothing(instance):
    data = make_bundle(leaf_extensions=[
        x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5.6.7'), b'\x05\x00')])
    response = instance.post(import_payload(data))
    assert response.status_code == 400, response.get_json()
    assert 'unsupported critical extension' in response.get_json()['error']
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


def test_preview_reads_cn_and_sans_without_importing(instance, bundle):
    response = instance.client.post('/api/web/certificates/import/preview',
        json={'certificate': bundle['certificate']}, headers=instance.headers)
    assert response.status_code == 200
    assert response.get_json() == {'common_names': [DOMAIN], 'sans': [DOMAIN, SAN]}
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


@pytest.mark.parametrize('certificate', [None, '', 'bad PEM', 'x' * (MAX_IMPORT_PEM_BYTES + 1)])
def test_preview_rejects_invalid_certificate_without_importing(instance, certificate):
    response = instance.client.post('/api/web/certificates/import/preview',
        json={'certificate': certificate}, headers=instance.headers)
    assert response.status_code == 400
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


def test_preview_requires_operator(instance, bundle):
    url = '/api/web/certificates/import/preview'
    payload = {'certificate': bundle['certificate']}
    assert instance.client.post(url, json=payload).status_code == 401
    ok, key = instance.managers['auth'].create_api_key('preview-viewer', role='viewer')
    assert ok
    assert instance.client.post(url, json=payload,
        headers={'Authorization': 'Bearer ' + key['token']}).status_code == 403


def test_preview_supports_missing_sans_and_does_not_require_valid_dates():
    from modules.core.cert_import import preview_import_certificate
    expired = make_bundle(root_end=-1)
    assert preview_import_certificate(expired['chain']) == {'common_names': ['Import test root'], 'sans': []}


def test_preview_validates_complete_bundle_without_saving_or_issuing(instance, bundle):
    response = instance.client.post('/api/web/certificates/import/preview', json=bundle,
                                   headers=instance.headers)
    assert response.status_code == 200, response.get_json()
    assert response.get_json() == {'common_names': [DOMAIN], 'sans': [DOMAIN, SAN], 'validated': True}
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()


@pytest.mark.parametrize('invalid', ['key', 'chain', 'expired', 'missing'])
def test_preview_does_not_validate_mismatched_or_incomplete_bundle(instance, invalid):
    data = make_bundle(end=-1, start=-10) if invalid == 'expired' else make_bundle()
    if invalid == 'key':
        data['private_key'] = make_bundle()['private_key']
    elif invalid == 'chain':
        data['chain'] = make_bundle()['chain']
    elif invalid == 'missing':
        del data['private_key']
    response = instance.client.post('/api/web/certificates/import/preview', json=data,
                                   headers=instance.headers)
    assert response.status_code == 400, response.get_json()
    assert not response.get_json().get('validated')
    assert 'PRIVATE KEY' not in response.get_data(as_text=True)
    assert not instance.directory.exists()
    instance.shell.run.assert_not_called()
