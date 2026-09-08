"""A certificate whose private key CertMate never sees (#599).

Requested by a user with appliances that generate their key on the device and
cannot export it. They can produce a CSR and nothing else, so the workflow has
to be: the key stays on the device, CertMate submits the CSR, CertMate manages
the certificate and chain that come back.

Two facts about certbot's ``--csr`` mode shape everything here, and both were
measured against Let's Encrypt staging rather than read from the documentation:

* it writes cert.pem, chain.pem and fullchain.pem and **no private key**;
* it creates **no lineage** — no ``renewal/`` config, no ``live/`` tree.
  certbot says so itself on success: these "will not be renewed automatically
  by Certbot. You will need to renew the certificate before it expires, by
  running the same Certbot command again."

The second is why renewal here re-runs issuance instead of calling
`certbot renew`, and why the "did it actually renew" question cannot be
answered by looking at ``live/``.

The collision worth naming: #608 made a certificate with no private key report
`needs_renewal`, because a restored share-safe backup produces exactly that and
used to look healthy. A CSR-only certificate is *deliberately* keyless. Without
a fourth state it would be reissued on every sweep — burning CA rate limit for
a file that must not exist.
"""
import json
import threading
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from modules.core.certificates import (
    CertificateManager, _private_key_present, _usable,
)
from modules.core.csr_issuance import (
    CSRError, csr_domains, csr_fingerprint, read_csr, to_csr_command,
)

pytestmark = [pytest.mark.unit]


def _csr(common_name='api.example.com', sans=('api.example.com',
                                              'www.example.com'),
         key=None, sign_with=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    if common_name:
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
    else:
        builder = builder.subject_name(x509.Name([]))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False)
    csr = builder.sign(sign_with or key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Reading the CSR
# ---------------------------------------------------------------------------

def test_the_names_come_from_the_csr_primary_first():
    assert csr_domains(read_csr(_csr())) == ['api.example.com',
                                             'www.example.com']


def test_a_csr_with_only_sans_still_names_its_domains():
    """Increasingly the normal shape — CAs have deprecated the Common Name."""
    pem = _csr(common_name=None, sans=('a.example.com', 'b.example.com'))
    assert csr_domains(read_csr(pem)) == ['a.example.com', 'b.example.com']


def test_a_name_repeated_in_cn_and_san_appears_once():
    """The CN is almost always repeated as the first SAN. Passing it twice
    would put the primary domain in its own san_domains list."""
    assert csr_domains(read_csr(_csr())).count('api.example.com') == 1


@pytest.mark.parametrize('bad,message', [
    (b'', 'empty'),
    (b'-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----',
     'not a valid pem'),
    (b'just some text', 'not a valid pem'),
])
def test_what_is_not_a_usable_csr(bad, message):
    with pytest.raises(CSRError, match='(?i)' + message):
        read_csr(bad)


def test_a_csr_naming_nothing_is_refused():
    with pytest.raises(CSRError, match='names no domains'):
        read_csr(_csr(common_name=None, sans=()))


def test_a_csr_whose_signature_does_not_verify_is_refused():
    """Signed with a different key from the one inside it. The CA would reject
    it — after CertMate had created a directory, written metadata and reported
    progress. Catching it here costs one parse."""
    inner = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([
                   x509.NameAttribute(NameOID.COMMON_NAME, 'x.example.com')])))
    forged = builder.sign(inner, hashes.SHA256())
    tampered = bytearray(forged.public_bytes(serialization.Encoding.DER))
    tampered[-1] ^= 0xFF
    del other

    with pytest.raises(CSRError):
        read_csr(x509.load_der_x509_csr(bytes(tampered)).public_bytes(
            serialization.Encoding.PEM))


def test_the_fingerprint_ignores_how_the_pem_was_pasted():
    """Over the DER, not the text. The same request re-exported by an appliance
    can differ in line wrapping while being byte-identical once decoded."""
    pem = _csr()
    rewrapped = pem.replace(b'\n', b'\r\n')
    assert csr_fingerprint(pem) == csr_fingerprint(rewrapped)


def test_two_different_csrs_have_different_fingerprints():
    """CONTROL for the above: a fingerprint that ignored everything would
    satisfy it too."""
    assert csr_fingerprint(_csr()) != csr_fingerprint(
        _csr(common_name='other.example.com', sans=('other.example.com',)))


def test_an_rsa_csr_is_read_the_same_way():
    """The appliance chooses the key, so the shape is not ours to assume."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert csr_domains(read_csr(_csr(key=key))) == ['api.example.com',
                                                    'www.example.com']


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------

ORDINARY = [
    'certbot', 'certonly', '--non-interactive', '--agree-tos',
    '--email', 'a@b.com', '--cert-name', 'api.example.com',
    '--config-dir', '/c/api.example.com', '--work-dir', '/c/api.example.com/work',
    '--logs-dir', '/c/api.example.com/logs',
    '-d', 'api.example.com', '-d', 'www.example.com',
    '--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1',
    '--authenticator', 'dns-cloudflare',
    '--dns-cloudflare-credentials', '/tmp/cf.ini',
    '--dns-cloudflare-propagation-seconds', '30',
]


def test_the_csr_command_is_a_contract():
    """A golden master, for the same reason the ordinary one has one: the
    interesting failures are a flag that quietly stopped being passed."""
    assert to_csr_command(ORDINARY, '/c/api.example.com/csr.pem',
                          '/c/api.example.com/csr-out') == [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com',
        '--config-dir', '/c/api.example.com',
        '--work-dir', '/c/api.example.com/work',
        '--logs-dir', '/c/api.example.com/logs',
        '--authenticator', 'dns-cloudflare',
        '--dns-cloudflare-credentials', '/tmp/cf.ini',
        '--dns-cloudflare-propagation-seconds', '30',
        '--csr', '/c/api.example.com/csr.pem',
        '--cert-path', '/c/api.example.com/csr-out/cert.pem',
        '--chain-path', '/c/api.example.com/csr-out/chain.pem',
        '--fullchain-path', '/c/api.example.com/csr-out/fullchain.pem',
    ]


@pytest.mark.parametrize('flag', [
    '--key-type', '--elliptic-curve', '--rsa-key-size',
])
def test_the_key_shape_flags_are_dropped(flag):
    """certbot does not generate a key in this mode, so `--key-type ecdsa`
    describes nothing. Leaving it in would let an operator read it back from
    the logs and believe CertMate chose the key."""
    argv = to_csr_command(ORDINARY + [flag, 'whatever'], '/c/csr.pem', '/out')
    assert flag not in argv


def test_the_domain_flags_are_dropped():
    """The names come from the CSR; certbot ignores -d there. Leaving them
    would suggest the request's names won when they cannot."""
    argv = to_csr_command(ORDINARY, '/c/csr.pem', '/out')
    assert '-d' not in argv
    assert 'www.example.com' not in argv


def test_the_lineage_name_is_dropped():
    """There is no lineage to name."""
    assert '--cert-name' not in to_csr_command(ORDINARY, '/c/csr.pem', '/out')


def test_everything_that_reaches_the_ca_survives():
    """The half that matters more. The CA, the credentials and the DNS plugin
    are identical in both modes, and a transformation that dropped one of them
    would fail at issuance rather than obviously here."""
    argv = to_csr_command(ORDINARY, '/c/csr.pem', '/out')
    for kept in ('--authenticator', 'dns-cloudflare',
                 '--dns-cloudflare-credentials', '/tmp/cf.ini',
                 '--dns-cloudflare-propagation-seconds', '30',
                 '--email', 'a@b.com', '--config-dir'):
        assert kept in argv, f'{kept} was dropped from the CSR command'


def test_the_original_command_is_not_modified():
    before = list(ORDINARY)
    to_csr_command(ORDINARY, '/c/csr.pem', '/out')
    assert ORDINARY == before


def test_an_eab_credential_is_carried_through():
    """A CA that needs external account binding needs it in CSR mode too, and
    the flag takes an argument that must not be mistaken for one to drop."""
    argv = to_csr_command(
        ORDINARY + ['--eab-kid', 'kid-1', '--eab-hmac-key', 'secret'],
        '/c/csr.pem', '/out')
    assert argv[argv.index('--eab-kid') + 1] == 'kid-1'
    assert argv[argv.index('--eab-hmac-key') + 1] == 'secret'


# ---------------------------------------------------------------------------
# The health of a deliberately keyless certificate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('state,present,usable', [
    ('present', True, True),
    ('missing', False, False),
    ('mismatched', True, False),
    ('unknown', None, None),
    ('external', False, None),
])
def test_what_each_key_state_reports(state, present, usable):
    """Four questions, five states, written out because each row is a
    decision. `external` is the new one: no key here, and `usable` is null
    rather than false because the certificate IS usable — on the appliance
    that holds the key.
    """
    assert _private_key_present(state) is present
    assert _usable(state) is usable


def _manager(tmp_path):
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=MagicMock(),
        dns_manager=MagicMock(), storage_manager=None, ca_manager=None,
        shell_executor=MagicMock())


def test_a_csr_only_certificate_is_external_not_missing(tmp_path):
    manager = _manager(tmp_path)
    (tmp_path / 'api.example.com').mkdir()

    assert manager.private_key_state(
        'api.example.com', None, {'key_management': 'external'}) == 'external'


def test_a_certificate_with_a_genuinely_lost_key_is_still_missing(tmp_path):
    """CONTROL: the new state must not become a way for #608's finding to come
    back. A restored share-safe backup has no marker and stays 'missing'."""
    manager = _manager(tmp_path)
    (tmp_path / 'api.example.com').mkdir()

    assert manager.private_key_state('api.example.com', None, {}) == 'missing'
    assert manager.private_key_state('api.example.com') == 'missing'


def test_a_key_that_turns_up_beside_a_csr_certificate_is_not_excused(tmp_path):
    """An anomaly worth reporting rather than hiding: something wrote a key for
    a certificate whose key was supposed to live elsewhere."""
    manager = _manager(tmp_path)
    domain_dir = tmp_path / 'api.example.com'
    domain_dir.mkdir()
    (domain_dir / 'privkey.pem').write_bytes(b'not really a key')

    assert manager.private_key_state(
        'api.example.com', None, {'key_management': 'external'}) == 'present'


def test_a_keyless_csr_certificate_does_not_ask_to_be_renewed(tmp_path):
    """The one that would cost money. #608 forces needs_renewal on a missing
    key; a CSR-only certificate would then be reissued on every sweep, burning
    CA rate limit for a file that must not exist.
    """
    manager = _manager(tmp_path)
    manager.settings_manager.load_settings.return_value = {}
    cert_pem = _self_signed('api.example.com')

    info = manager._parse_certificate_info(
        'api.example.com', cert_pem, {'key_management': 'external'},
        settings={}, key_state='external')

    assert info['needs_renewal'] is False
    assert info['private_key_state'] == 'external'
    assert info['usable'] is None
    assert info['private_key_present'] is False


def test_a_keyless_certificate_with_no_marker_still_asks_to_be_renewed(tmp_path):
    """CONTROL for the above, and the whole of #608."""
    manager = _manager(tmp_path)
    manager.settings_manager.load_settings.return_value = {}

    info = manager._parse_certificate_info(
        'api.example.com', _self_signed('api.example.com'), {},
        settings={}, key_state='missing')

    assert info['needs_renewal'] is True
    assert info['usable'] is False


def _self_signed(common_name, days=90):
    import datetime
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Storing the CSR, and what is refused
# ---------------------------------------------------------------------------

def _store(tmp_path, domain, csr_pem):
    manager = _manager(tmp_path)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    return manager, manager._store_csr(domain, tmp_path / domain, csr_pem)


def test_the_csr_is_written_where_renewal_can_find_it(tmp_path):
    pem = _csr()
    _manager_, (csr_path, all_domains) = _store(
        tmp_path, 'api.example.com', pem)

    assert csr_path == tmp_path / 'api.example.com' / 'csr.pem'
    assert csr_path.read_bytes() == pem
    assert all_domains == ['api.example.com', 'www.example.com']


def test_the_primary_domain_comes_first_whatever_the_csr_order(tmp_path):
    """metadata's san_domains is all_domains[1:] everywhere, so a primary that
    sorted second would file itself as its own SAN."""
    pem = _csr(common_name=None,
               sans=('www.example.com', 'api.example.com'))
    _manager_, (_path, all_domains) = _store(tmp_path, 'api.example.com', pem)

    assert all_domains[0] == 'api.example.com'
    assert set(all_domains[1:]) == {'www.example.com'}


def test_a_csr_that_does_not_cover_the_requested_domain_is_refused(tmp_path):
    """The directory is named for `domain`, and renewal, the health check and
    every deploy hook find it by that name. A certificate filed under a domain
    it does not cover would be unreachable and wrong."""
    with pytest.raises(RuntimeError, match='does not cover'):
        _store(tmp_path, 'other.example.com', _csr())


def test_converting_a_key_managed_certificate_is_refused(tmp_path):
    """It would leave the old privkey.pem beside a certificate it cannot
    serve — the unusable pair the staged publish exists to prevent, reported
    as 'mismatched' forever afterwards."""
    domain_dir = tmp_path / 'api.example.com'
    domain_dir.mkdir()
    (domain_dir / 'privkey.pem').write_bytes(b'existing key')

    with pytest.raises(RuntimeError, match='already has a private key'):
        _store(tmp_path, 'api.example.com', _csr())


def test_an_unusable_csr_fails_before_anything_is_written(tmp_path):
    with pytest.raises(RuntimeError, match='(?i)not a valid pem'):
        _store(tmp_path, 'api.example.com', b'garbage')
    assert not (tmp_path / 'api.example.com' / 'csr.pem').exists()


# ---------------------------------------------------------------------------
# Renewal re-runs issuance, because certbot renew never will
# ---------------------------------------------------------------------------

def _renewable(tmp_path, metadata=None, csr=True):
    manager = _manager(tmp_path)
    domain_dir = tmp_path / 'api.example.com'
    domain_dir.mkdir(parents=True)
    (domain_dir / 'cert.pem').write_bytes(_self_signed('api.example.com'))
    (domain_dir / 'metadata.json').write_text(json.dumps(
        metadata if metadata is not None else {
            'key_management': 'external', 'dns_provider': 'cloudflare',
            'email': 'a@b.com', 'ca_provider': 'letsencrypt'}))
    if csr:
        (domain_dir / 'csr.pem').write_bytes(_csr())
    return manager


def test_a_csr_certificate_renews_by_reissuing(tmp_path):
    manager = _renewable(tmp_path)
    calls = []

    def _create(**kwargs):
        calls.append(kwargs)
        (tmp_path / 'api.example.com' / 'cert.pem').write_bytes(
            _self_signed('api.example.com', days=89))
        return {'success': True}
    manager.create_certificate = _create

    ok, message = manager.renew_certificate('api.example.com')

    assert ok, message
    assert len(calls) == 1
    assert calls[0]['csr_pem'] == (
        tmp_path / 'api.example.com' / 'csr.pem').read_bytes()
    assert calls[0]['dns_provider'] == 'cloudflare'
    assert calls[0]['ca_provider'] == 'letsencrypt'


def test_an_ordinary_certificate_still_goes_through_certbot_renew(tmp_path):
    """CONTROL: the branch must be taken only for CSR certificates. Sending
    every renewal through reissue would drop `certbot renew`'s not-yet-due
    check and reissue everything on every sweep."""
    manager = _renewable(tmp_path, metadata={'dns_provider': 'cloudflare'},
                         csr=False)
    manager.create_certificate = lambda **kw: pytest.fail(
        'an ordinary renewal was sent through the CSR reissue path')

    assert manager._csr_renewal_request('api.example.com') is None


def test_a_csr_certificate_whose_csr_is_gone_says_so(tmp_path):
    """Falling through to `certbot renew` would report a clean no-op every
    night — there is no lineage for it to renew — while the certificate marched
    to expiry."""
    manager = _renewable(tmp_path, csr=False)

    with pytest.raises(RuntimeError, match='no longer has'):
        manager.renew_certificate('api.example.com')


def test_an_unchanged_certificate_is_not_reported_as_renewed(tmp_path):
    """A CA that returns the same certificate for an unchanged CSR — which is
    what a repeat request inside its reuse window produces — must not advance
    renewed_at while the expiry stands still."""
    manager = _renewable(tmp_path)
    manager.create_certificate = lambda **kw: {'success': True}

    ok, message = manager.renew_certificate('api.example.com')

    assert ok
    assert 'did not change' in message


def test_a_failed_reissue_is_reported_as_a_failed_renewal(tmp_path):
    manager = _renewable(tmp_path)
    manager.create_certificate = lambda **kw: (False, 'the CA said no')

    ok, message = manager.renew_certificate('api.example.com')

    assert ok is False
    assert 'the CA said no' in message


def test_the_renewal_branch_is_taken_before_the_domain_lock(tmp_path):
    """The per-domain lock is a plain Lock, not an RLock, and
    create_certificate takes it too. Acquiring first and delegating second
    would deadlock every CSR renewal — and surface as
    DomainOperationInProgress against no other operation.
    """
    manager = _renewable(tmp_path)
    held = manager._get_domain_lock('api.example.com')
    assert held.acquire(timeout=1)
    try:
        manager.create_certificate = lambda **kw: {'success': True}
        # The branch runs even though the lock is held by "someone else",
        # which is exactly what proves it is taken before the acquire.
        ok, _message = manager.renew_certificate('api.example.com')
        assert ok
    finally:
        held.release()


# ---------------------------------------------------------------------------
# Deploying a certificate whose key is somewhere else
# ---------------------------------------------------------------------------

def _deployer(tmp_path, domain='api.example.com', with_key=False):
    from modules.core.deployer import DeployManager
    domain_dir = tmp_path / 'certs' / domain
    domain_dir.mkdir(parents=True)
    (domain_dir / 'cert.pem').write_bytes(b'cert')
    (domain_dir / 'fullchain.pem').write_bytes(b'fullchain')
    (domain_dir / 'chain.pem').write_bytes(b'chain')
    if with_key:
        (domain_dir / 'privkey.pem').write_bytes(b'key')
    return DeployManager(
        settings_manager=MagicMock(), shell_executor=MagicMock(),
        audit_logger=MagicMock(), event_bus=MagicMock(),
        cert_dir=tmp_path / 'certs', data_dir=str(tmp_path / 'data'))


def test_a_shell_hook_gets_no_key_path_when_there_is_no_key(tmp_path):
    """Unset, not pointed at a file that does not exist. A hook doing
    `cp "$CERTMATE_KEY_PATH" ...` then fails visibly instead of silently
    copying nothing, and a hook that never touches the key is unaffected."""
    manager = _deployer(tmp_path)
    seen = {}
    manager.shell_executor.run.side_effect = lambda *a, **kw: (
        seen.update(kw.get('env') or {}) or MagicMock(returncode=0, stdout='', stderr=''))

    manager._run_hook({'id': 'h', 'name': 'h', 'command': 'true', 'timeout': 5},
                      'api.example.com', 'renewed')

    assert 'CERTMATE_KEY_PATH' not in seen
    assert seen['CERTMATE_CERT_PATH'].endswith('api.example.com/cert.pem')


def test_a_shell_hook_still_gets_the_key_path_when_there_is_one(tmp_path):
    """CONTROL: every existing hook depends on this variable."""
    manager = _deployer(tmp_path, with_key=True)
    seen = {}
    manager.shell_executor.run.side_effect = lambda *a, **kw: (
        seen.update(kw.get('env') or {}) or MagicMock(returncode=0, stdout='', stderr=''))

    manager._run_hook({'id': 'h', 'name': 'h', 'command': 'true', 'timeout': 5},
                      'api.example.com', 'renewed')

    assert seen['CERTMATE_KEY_PATH'].endswith('api.example.com/privkey.pem')


def test_a_typed_target_explains_why_it_cannot_serve_a_csr_certificate(tmp_path):
    """Every typed target publishes the key with the certificate, so none can
    serve one whose key is on a device. The generic "certificate files
    unreadable" this used to produce fired on every renewal and read as a
    broken instance rather than an incompatible pairing."""
    manager = _deployer(tmp_path)
    target = {'name': 'k8s', 'type': 'kubernetes-secret', 'enabled': True,
              'config': {'secret_name': 's', 'in_cluster': True}}

    results = manager._execute_targets(
        'api.example.com', 'renewed',
        {'enabled': True, 'targets': [target]}, targets=[target])

    assert len(results) == 1
    assert results[0]['success'] is False
    assert 'issued from a CSR' in results[0]['message']
    assert 'shell hook' in results[0]['message'], (
        'the message does not say what to do instead'
    )


# ---------------------------------------------------------------------------
# The storage branch answers the same question
# ---------------------------------------------------------------------------

def test_a_csr_certificate_read_through_storage_is_still_external(tmp_path):
    """Found by the real-CA E2E, not by any unit test above.

    `get_certificate_info` asks the storage backend first, and the local
    backend is a storage backend — so on a real instance that branch runs, not
    the filesystem one every other test here exercises. It reported 'unknown',
    which is the honest answer for a secrets backend that deliberately does not
    fetch keys, and the wrong one when the metadata says there is no key to
    fetch anywhere.
    """
    manager = _manager(tmp_path)
    manager.settings_manager.load_settings.return_value = {}
    cert_pem = _self_signed('api.example.com')
    metadata = {'key_management': 'external', 'dns_provider': 'cloudflare'}

    storage = MagicMock()
    storage.retrieve_certificate_info.return_value = (
        {'cert.pem': cert_pem}, metadata)
    manager.storage_manager = storage

    info = manager.get_certificate_info('api.example.com', use_cache=False)

    assert info['private_key_state'] == 'external', info
    assert info['needs_renewal'] is False, (
        f'a CSR-only certificate read through storage is asking to be '
        f'reissued on every sweep: {info}'
    )


def test_an_ordinary_storage_certificate_is_still_unknown(tmp_path):
    """CONTROL: the whole point of 'unknown' on this path is that a secrets
    backend does not pull private keys for a listing view. Answering 'missing'
    there would mark every storage-backed certificate as needing renewal —
    which is what #608 explicitly avoided."""
    manager = _manager(tmp_path)
    manager.settings_manager.load_settings.return_value = {}

    storage = MagicMock()
    storage.retrieve_certificate_info.return_value = (
        {'cert.pem': _self_signed('api.example.com')}, {'dns_provider': 'cf'})
    manager.storage_manager = storage

    info = manager.get_certificate_info('api.example.com', use_cache=False)

    assert info['private_key_state'] == 'unknown', info
    assert info['usable'] is None


@pytest.mark.parametrize('flag', ['--renew-with-new-domains', '--force-renewal'])
def test_the_lineage_flags_are_dropped_too(flag):
    """A CSR renewal goes through create_certificate with `replace=True`,
    purely to get past its "already exists" guard — and that adds these. There
    is no lineage here to renew with new domains and no renewal window to force
    past: certbot in --csr mode always issues. Dropping them keeps the renewal
    command byte-identical to the issuance command, which is the one proven
    against a real CA.
    """
    assert flag not in to_csr_command(ORDINARY + [flag], '/c/csr.pem', '/out')


def test_dropping_a_valueless_flag_does_not_eat_the_next_argument():
    """CONTROL: --force-renewal takes no argument. Treating it like `-d` would
    silently swallow whatever follows — in a real command, the authenticator."""
    argv = to_csr_command(
        ['certbot', 'certonly', '--force-renewal', '--authenticator',
         'dns-cloudflare'], '/c/csr.pem', '/out')
    assert '--authenticator' in argv
    assert argv[argv.index('--authenticator') + 1] == 'dns-cloudflare'


def test_the_renewal_reissues_over_the_existing_certificate(tmp_path):
    """create_certificate refuses a domain that already has one, and a renewal
    by definition does. Without `replace=True` every CSR renewal was a 500 —
    which is how the real-CA E2E found it, after the unit tests passed."""
    manager = _renewable(tmp_path)
    calls = []
    manager.create_certificate = lambda **kw: (
        calls.append(kw) or {'success': True})

    manager.renew_certificate('api.example.com')

    assert calls and calls[0].get('replace') is True, (
        'the CSR renewal does not reissue over the existing certificate, so '
        'create_certificate will refuse it with FileExistsError'
    )
