"""A certificate request's ceiling should not be the backup upload's ceiling.

One `MAX_CONTENT_LENGTH` of 50 MB applied to every endpoint. It exists for the
backup upload, which needs it. Applied to certificate creation it meant the
limit on `san_domains` was *"however many names fit in fifty megabytes"* and
the limit on `csr` was *"however large a PEM fits in fifty megabytes"* —
neither of which is a limit anyone chose, and neither of which any endpoint
stated.

The bounds here are not arbitrary:

* **100 names** is Let's Encrypt's own cap per certificate. A request naming
  more cannot be satisfied by the CA regardless of what CertMate does with it,
  so refusing it at the boundary says so — instead of building a certbot
  command line with thousands of `-d` flags and letting the CA reject it after
  the DNS challenges have been set up, which costs an ACME order and a set of
  DNS writes to learn nothing.
* **64 KB** for a CSR is generous by more than an order of magnitude: a PEM
  request for a 4096-bit key carrying a hundred names is a few kilobytes. It
  refuses long before anything reaches the parser.

The global limit is deliberately left alone. Lowering it would break the backup
upload, which is the one endpoint that genuinely receives megabytes.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.cert_service import (
    MAX_CSR_BYTES, MAX_SAN_DOMAINS, CertificateService,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def service():
    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': 'ops@example.com',
        'dns_provider': 'cloudflare',
        'dns_providers': {'cloudflare': {'default': {'api_token': 'x'}}},
    }
    auth = MagicMock()
    auth.user_can_access_domain.return_value = True
    return CertificateService(MagicMock(), settings, auth, MagicMock())


def _create(service, **kwargs):
    return service.prepare_create(domain='example.com', **kwargs)


# --- how many names ------------------------------------------------------

def test_a_request_at_the_limit_is_accepted(service):
    """CONTROL: the bound must be reachable. An off-by-one here would refuse
    a certificate Let's Encrypt would happily issue."""
    names = [f'n{i}.example.com' for i in range(MAX_SAN_DOMAINS)]
    _create(service, san_domains=names)          # no raise


def test_a_request_past_the_limit_is_refused_with_the_number(service):
    names = [f'n{i}.example.com' for i in range(MAX_SAN_DOMAINS + 1)]
    with pytest.raises(ValueError) as caught:
        _create(service, san_domains=names)

    message = str(caught.value)
    assert str(MAX_SAN_DOMAINS) in message, (
        f'the refusal does not say what the limit is: {message}'
    )
    assert str(len(names)) in message, (
        f'the refusal does not say what was sent: {message}'
    )


def test_an_absurd_request_is_refused_rather_than_built_into_a_command(service):
    """The case the global 50 MB limit permitted: a request that would have
    become a certbot command line with thousands of -d flags."""
    with pytest.raises(ValueError):
        _create(service, san_domains=[f'n{i}.example.com'
                                      for i in range(20_000)])


def test_no_sans_at_all_is_still_fine(service):
    _create(service)
    _create(service, san_domains=[])


def test_the_shape_check_still_runs(service):
    """CONTROL: the new length bound must not shadow the type check that was
    already there — `san_domains` as a string has a length too."""
    with pytest.raises(ValueError, match='Invalid san_domains format'):
        _create(service, san_domains='not-a-list.example.com')


# --- how large a CSR -----------------------------------------------------

def test_an_oversized_csr_is_refused_before_it_reaches_the_parser(service):
    with pytest.raises(ValueError) as caught:
        _create(service, csr_pem='-' * (MAX_CSR_BYTES + 1))

    message = str(caught.value)
    assert 'CSR too large' in message
    assert str(MAX_CSR_BYTES) in message, (
        f'the refusal does not say what the limit is: {message}'
    )


def test_a_csr_of_a_plausible_size_reaches_the_parser(service):
    """CONTROL: the bound must not refuse a real CSR. This one is nonsense,
    so it fails at the PARSER — which is the proof it got that far."""
    with pytest.raises(ValueError, match='Invalid CSR'):
        _create(service, csr_pem='-----BEGIN CERTIFICATE REQUEST-----\nx\n'
                                 '-----END CERTIFICATE REQUEST-----\n')


def test_a_csr_that_is_not_text_is_refused_as_such(service):
    """A dict or a list has no meaningful length, and `len()` on one would
    pass the size check and then confuse the parser's error."""
    with pytest.raises(ValueError, match='expected PEM text'):
        _create(service, csr_pem={'pem': 'nope'})


def test_bytes_are_accepted_as_a_csr(service):
    """CONTROL: the type check must not refuse the other legitimate shape.
    Nonsense bytes, so this reaches the parser and fails there."""
    with pytest.raises(ValueError, match='Invalid CSR'):
        _create(service, csr_pem=b'-----BEGIN CERTIFICATE REQUEST-----\n')


# --- what must not change ------------------------------------------------

def test_the_global_body_limit_is_left_alone():
    """The backup upload is the one endpoint that genuinely receives
    megabytes. Lowering the global limit to fix the certificate endpoints
    would break it."""
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
              / 'core' / 'factory.py').read_text()
    assert "app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024" in source, (
        'the global body limit changed; the backup upload needs it'
    )


def test_the_limits_are_named_constants_not_literals():
    """So an operator reading the refusal can find where the number is
    decided, and so the tests and the code cannot disagree about it."""
    assert MAX_SAN_DOMAINS == 100
    assert MAX_CSR_BYTES == 64 * 1024
