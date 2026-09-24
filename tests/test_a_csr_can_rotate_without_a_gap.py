"""Rotating a CSR-only certificate's key does not require deleting it first.

Item 6 of #876. `docs/csr-only-certificates.md` and the UI hint said to submit
the new CSR the same way, same domain. Measured: `create` refuses a domain that
already has `cert.pem` with `409 CERTIFICATE_ALREADY_EXISTS`, and its hint
points at reissue — which took no CSR at all. `prepare_reissue` had no
`csr_pem` parameter.

So the only path was delete, then create, with **no certificate in between**.
On the feature people choose precisely because they keep the private key
somewhere else.

Reissue takes one now. Two things about it are worth stating, because both are
decisions rather than consequences:

* **The validation is not copied.** Create's CSR checks — type, size bound, no
  SANs, no key options, parseable, every name in scope — moved into
  `_check_csr` and both callers use it. A second copy of a scope check is the
  one that stops being updated.
* **Named SANs are refused; inherited ones are replaced.** Reissue inherits the
  current SAN set when the caller names none. A CSR carries its own names, so
  adding the inherited set to them would issue something nobody asked for —
  and refusing on the inherited set would make every CSR rotation of a
  multi-name certificate an error. The distinction is recorded before
  inheritance runs.
"""
import pathlib

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
DOMAIN = 'csr.example.com'


def _csr(*names):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([
                   x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
               .add_extension(x509.SubjectAlternativeName(
                   [x509.DNSName(n) for n in names]), critical=False))
    return builder.sign(key, hashes.SHA256()).public_bytes(
        serialization.Encoding.PEM).decode('ascii')


@pytest.fixture
def service(tmp_path, monkeypatch):
    """A CertificateService over a temporary tree with one existing
    CSR-only certificate, and certbot replaced by a recorder."""
    from modules.core.cert_service import CertificateService

    cert_dir = tmp_path / 'certs'
    (cert_dir / DOMAIN).mkdir(parents=True)
    (cert_dir / DOMAIN / 'cert.pem').write_text('existing certificate')

    class _Certs:
        def __init__(self):
            self.cert_dir = cert_dir
            self.calls = []

        def _load_metadata(self, domain):
            return {'dns_provider': 'cloudflare', 'challenge_type': 'dns-01',
                    'san_domains': ['inherited.example.com'],
                    'ca_provider': 'letsencrypt'}

        def create_certificate(self, **kwargs):
            self.calls.append(kwargs)
            return {'success': True}

    class _Settings:
        def load_settings(self):
            return {'email': 'ops@example.com', 'dns_provider': 'cloudflare',
                    'default_ca': 'letsencrypt'}

        def update(self, *a, **k):
            return True

    instance = CertificateService.__new__(CertificateService)
    instance._certs = _Certs()
    instance._settings = _Settings()
    monkeypatch.setattr(instance, '_enforce_scope',
                        lambda *a, **k: None, raising=False)
    monkeypatch.setattr(instance, '_audit_emit',
                        lambda *a, **k: None, raising=False)
    return instance


def test_the_certificate_exists_so_create_is_not_the_path(service):
    """Guard the guard: if the fixture had no certificate, reissue would
    raise FileNotFoundError and every test below would be about that."""
    assert (service._certs.cert_dir / DOMAIN / 'cert.pem').exists()


def test_reissue_accepts_a_csr(service):
    prepared = service.prepare_reissue(domain=DOMAIN, csr_pem=_csr(DOMAIN))
    assert prepared['csr_pem']
    assert prepared['domain'] == DOMAIN


def test_the_csr_reaches_certbot(service):
    """A parameter that is validated and then dropped would pass every
    check above and rotate nothing."""
    prepared = service.prepare_reissue(domain=DOMAIN, csr_pem=_csr(DOMAIN))
    service.issue_reissue(prepared)

    assert service._certs.calls, 'certbot was never asked to run'
    assert service._certs.calls[0]['csr_pem'] == prepared['csr_pem']
    assert service._certs.calls[0]['replace'] is True


def test_inherited_sans_are_replaced_not_added(service):
    """The certificate has a SAN today. The CSR names only the primary, and
    that is what must be issued — inheriting would add a name the CSR does
    not cover, which the CA would refuse and the operator never asked for."""
    prepared = service.prepare_reissue(domain=DOMAIN, csr_pem=_csr(DOMAIN))
    assert prepared['san_domains'] == []


def test_naming_sans_alongside_a_csr_is_refused(service):
    """Different from inheriting: this one the caller said out loud, and it
    contradicts the CSR."""
    with pytest.raises(ValueError, match='(?i)san_domains cannot be combined'):
        service.prepare_reissue(domain=DOMAIN, csr_pem=_csr(DOMAIN),
                                san_domains=['other.example.com'])


def test_an_empty_san_list_is_still_a_statement(service):
    """`san_domains=[]` means "drop every SAN" on a normal reissue. With a
    CSR it is redundant rather than contradictory, and must not be read as
    "the caller named nothing"."""
    prepared = service.prepare_reissue(domain=DOMAIN, csr_pem=_csr(DOMAIN),
                                       san_domains=[])
    assert prepared['san_domains'] == []


@pytest.mark.parametrize('option', [
    {'key_type': 'rsa'}, {'key_size': 4096}, {'elliptic_curve': 'secp384r1'},
])
def test_key_options_alongside_a_csr_are_refused(service, option):
    """The key belongs to whatever produced the CSR. Asking CertMate to
    choose one is asking for a certificate that will not match it."""
    with pytest.raises(ValueError, match='(?i)key options cannot be combined'):
        service.prepare_reissue(domain=DOMAIN, csr_pem=_csr(DOMAIN), **option)


def test_a_csr_that_does_not_parse_is_refused(service):
    with pytest.raises(ValueError, match='(?i)invalid csr'):
        service.prepare_reissue(domain=DOMAIN, csr_pem='not a csr')


def test_a_reissue_without_a_csr_still_inherits(service):
    """The ordinary path must be untouched: no CSR, and the SAN set comes
    from the certificate as it always did."""
    prepared = service.prepare_reissue(domain=DOMAIN)
    assert prepared['san_domains'] == ['inherited.example.com']
    assert prepared['csr_pem'] is None


def test_both_paths_share_one_validation():
    """Create and reissue check a CSR the same way because it is the same
    code. Two copies of a scope check is how the second one goes stale."""
    import inspect

    from modules.core.cert_service import CertificateService

    for method in (CertificateService.prepare_create,
                   CertificateService.prepare_reissue):
        assert '_check_csr(' in inspect.getsource(method), method.__name__


def test_the_page_names_the_endpoint_that_works():
    """The sentence that started this said "the same way", which reads as
    create — and create refuses. A page that still said so would send the
    next operator down the delete-then-create path."""
    page = (REPO / 'docs' / 'csr-only-certificates.md').read_text(encoding='utf-8')
    rotation = page[page.index('## Key rotation'):]
    rotation = rotation[:rotation.index('## ', 3)]
    assert '/reissue' in rotation
    assert 'CERTIFICATE_ALREADY_EXISTS' in rotation, (
        'the page no longer says why create is not the path, which is the '
        'thing a reader has to know to stop reaching for it'
    )


def test_the_api_field_is_spelled_the_way_create_spells_it():
    """`csr`, not `csr_pem`. The route reads the request body, and a second
    spelling for one field is a support question forever."""
    route = (REPO / 'modules' / 'api' / 'resources_lifecycle.py').read_text(
        encoding='utf-8')
    assert "data.get('csr_pem')" not in route
    assert route.count("csr_pem=data.get('csr')") == 3
