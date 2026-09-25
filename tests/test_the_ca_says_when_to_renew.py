"""Renewal timing from the CA, not only from a number we picked (#393).

CertMate renews at `days_left <= renewal_threshold_days`, default 30. That is
CertMate's opinion, identical for every certificate and every CA. Since
RFC 9773 the CA publishes its own, per certificate: a `renewalInfo` endpoint
answering a window during which it wants that certificate replaced. The window
matters most when it moves *earlier* — a batch replacement, a compromised
intermediate, a ruling — which a fixed 30-day rule finds out about when the
certificate stops working.

**What is asserted here, and what is deliberately not.** ARI can only bring a
renewal forward: the configured threshold stays the backstop. So a CA that is
down, slow, or wrong cannot delay a renewal that would otherwise have
happened, and there is a control below for exactly that. Letting ARI defer a
renewal past the threshold is the half that matters for short-lived
certificates, and it waits on #395.

**The encoding was verified against the real endpoint**, not against my
reading of the RFC. `certificate_id` on the certificate `letsencrypt.org`
served on 2026-09-24, asked of `https://acme-v02.api.letsencrypt.org`:

    certID : uVnyjs8i8IbTN0j_dhQYuoLYVYc.BUOTO-OGs6KzrdU08hA7yLZf
    status : 200
    body   : {"suggestedWindow": {"start": "2026-11-02T17:18:36Z",
                                  "end":   "2026-11-04T12:29:25Z"}}

for a certificate expiring 2026-12-03. The first thing that probe produced was
a 404 on an expired certificate of ours, which says nothing — a wrong
identifier and a pruned certificate look identical from here. That is why the
positive control above exists, and why `test_the_encoding_matches_a_real_ca`
below re-runs it rather than trusting this docstring.
"""
import json
import os
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from modules.core import ari

pytestmark = [pytest.mark.unit]

NOW = datetime(2026, 9, 24, 12, 0, 0)
DIRECTORY = 'https://ca.example.test/directory'
ARI_BASE = 'https://ca.example.test/acme/renewal-info'


def _cert(serial=12345, aki=b'\x01\x02\x03\x04', not_after_days=60):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ari.example.test')])
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(serial)
               .not_valid_before(NOW - timedelta(days=30))
               .not_valid_after(NOW + timedelta(days=not_after_days)))
    if aki is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(key_identifier=aki,
                                        authority_cert_issuer=None,
                                        authority_cert_serial_number=None),
            critical=False)
    return builder.sign(key, hashes.SHA256()), key


def _transport(answers):
    """A `get` that serves a scripted {url: (status, body)} and records calls."""
    calls = []

    def get(url, timeout):
        calls.append(url)
        if url not in answers:
            return 404, b'{"detail": "not found"}'
        status, payload = answers[url]
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return status, body

    get.calls = calls
    return get


def _window(start_offset_hours, end_offset_hours):
    def stamp(hours):
        return (NOW + timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return {'suggestedWindow': {'start': stamp(start_offset_hours),
                                'end': stamp(end_offset_hours)}}


# --- the identifier --------------------------------------------------------

def test_the_identifier_has_the_shape_the_rfc_specifies():
    cert, _ = _cert(serial=0x1234, aki=b'\xab\xcd')

    cert_id = ari.certificate_id(cert)

    left, _, right = cert_id.partition('.')
    assert left and right
    assert '=' not in cert_id, 'base64url in ARI is unpadded'
    assert '+' not in cert_id and '/' not in cert_id, 'that is base64, not base64url'


@pytest.mark.parametrize('serial,expected', [
    (1, b'\x01'),
    (127, b'\x7f'),
    # The sign bit. A DER INTEGER is signed, so 128 and 255 carry a leading
    # zero byte and 127 does not. `serial.to_bytes(byte_length, 'big')` gets
    # this wrong for exactly the serials whose top bit is set — which is half
    # of them, and every one would 404.
    (128, b'\x00\x80'),
    (255, b'\x00\xff'),
    (256, b'\x01\x00'),
    (0, b'\x00'),
])
def test_the_serial_is_encoded_as_a_der_integer(serial, expected):
    assert ari._serial_octets(serial) == expected


def test_a_certificate_with_no_authority_key_identifier_cannot_be_named():
    """A self-signed certificate from a hand-rolled private CA may carry no
    AKI. ARI has no way to refer to it, so the caller must fall back rather
    than send a malformed identifier."""
    cert, _ = _cert(aki=None)

    with pytest.raises(ValueError):
        ari.certificate_id(cert)


# --- the window ------------------------------------------------------------

def test_a_window_that_has_passed_is_due():
    """A window entirely behind us: whatever point in it this certificate
    drew, that point is past."""
    assert ari.is_due('aa.bb', _window(-48, -24), NOW) is True


def test_a_window_that_has_not_opened_is_not_due():
    assert ari.is_due('aa.bb', _window(24, 48), NOW) is False


def test_a_window_that_has_opened_is_not_due_by_itself():
    """The first draft of this file asserted that an open window means renew
    now, and it failed — correctly. RFC 9773 §4.2 says the client picks a
    point *inside* the window and renews at that point; a window that opened
    an hour ago whose point falls tomorrow is not due yet. Asserting
    otherwise would make every client of a CA renew at the same instant,
    which is the thing the window exists to prevent.

    Computed rather than hardcoded, so this states the rule instead of
    memorising one identifier's hash.
    """
    payload = _window(-24, 24)
    start, end = ari.parse_window(payload)
    chosen = ari.due_at('aa.bb', start, end)

    assert start < NOW < end, 'this window does not straddle now'
    assert ari.is_due('aa.bb', payload, NOW) is (NOW >= chosen)
    assert ari.is_due('aa.bb', payload, chosen) is True
    assert ari.is_due('aa.bb', payload, chosen - timedelta(seconds=1)) is False


def test_the_point_in_the_window_is_stable_across_sweeps():
    """RFC 9773 asks for a random point so a CA's clients do not all renew at
    once. Drawn from the id rather than from `random`: a nightly re-roll
    would fire on the first night that happened to roll low, which is not
    randomness but a race against the sweep."""
    start, end = NOW, NOW + timedelta(days=2)

    first = ari.due_at('aa.bb', start, end)
    second = ari.due_at('aa.bb', start, end)

    assert first == second
    assert start <= first < end


def test_two_certificates_do_not_land_on_the_same_point():
    """The property the RFC actually asks for: spread. Same window, different
    identifiers."""
    start, end = NOW, NOW + timedelta(days=2)

    points = {ari.due_at(f'cert{i}.serial', start, end) for i in range(50)}

    assert len(points) == 50


@pytest.mark.parametrize('payload', [
    None,
    {},
    {'suggestedWindow': {}},
    {'suggestedWindow': {'start': 'not-a-date', 'end': 'nor-this'}},
    # end before start
    {'suggestedWindow': {'start': '2026-09-25T00:00:00Z',
                         'end': '2026-09-24T00:00:00Z'}},
    # a window longer than a year is not an answer about this certificate
    {'suggestedWindow': {'start': '2026-09-24T00:00:00Z',
                         'end': '2030-09-24T00:00:00Z'}},
])
def test_an_answer_that_is_not_a_window_yields_nothing(payload):
    """None, not a default. A malformed answer is not evidence about the
    certificate, and a window invented from one would be CertMate's opinion
    wearing the CA's name."""
    assert ari.parse_window(payload) is None
    assert ari.is_due('aa.bb', payload, NOW) is False


# --- the client ------------------------------------------------------------

def test_the_url_comes_from_the_directory_not_from_a_guess():
    """Let's Encrypt serves `/acme/renewal-info` while its directory is at
    `/directory`. Nothing relates the two, so the base has to be read."""
    assert ari.renewal_info_url({'renewalInfo': ARI_BASE}, 'aa.bb') == \
        ARI_BASE + '/aa.bb'
    assert ari.renewal_info_url({'newOrder': 'x'}, 'aa.bb') is None
    assert ari.renewal_info_url({}, 'aa.bb') is None


def test_a_ca_that_does_not_speak_ari_is_asked_once():
    """CONTROL on cost. A directory without `renewalInfo` must not produce a
    request per certificate — and must not produce a per-certificate request
    to a URL built by guessing."""
    get = _transport({DIRECTORY: (200, {'newOrder': 'https://ca/new-order'})})
    client = ari.RenewalInfoClient(get=get, clock=lambda: NOW)

    for i in range(5):
        assert client.says_renew_now(DIRECTORY, f'cert{i}.serial') is False

    assert get.calls == [DIRECTORY], get.calls


def test_the_directory_is_fetched_once_for_many_certificates():
    get = _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        **{f'{ARI_BASE}/cert{i}.serial': (200, _window(-48, -24)) for i in range(5)},
    })
    client = ari.RenewalInfoClient(get=get, clock=lambda: NOW)

    for i in range(5):
        assert client.says_renew_now(DIRECTORY, f'cert{i}.serial') is True

    assert get.calls.count(DIRECTORY) == 1
    assert len(get.calls) == 6


def test_a_ca_that_is_down_is_not_asked_once_per_certificate():
    """A failed directory is cached too. Otherwise an unreachable CA costs
    one timeout per certificate, every sweep — the sweep would take
    `domains × timeout` longer for no information."""
    def get(url, timeout):
        get.calls.append(url)
        raise OSError('connection refused')
    get.calls = []
    client = ari.RenewalInfoClient(get=get, clock=lambda: NOW)

    for i in range(5):
        assert client.says_renew_now(DIRECTORY, f'cert{i}.serial') is False

    assert get.calls == [DIRECTORY]


def test_a_stale_directory_is_fetched_again():
    """CONTROL on the cache: a CA that turns ARI on must not need a restart
    to be noticed."""
    clock = {'now': NOW}
    get = _transport({DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
                      f'{ARI_BASE}/aa.bb': (200, _window(-48, -24))})
    client = ari.RenewalInfoClient(get=get, clock=lambda: clock['now'])

    client.says_renew_now(DIRECTORY, 'aa.bb')
    clock['now'] = NOW + timedelta(seconds=ari.DIRECTORY_TTL_SECONDS + 1)
    client.says_renew_now(DIRECTORY, 'aa.bb')

    assert get.calls.count(DIRECTORY) == 2


@pytest.mark.parametrize('status,body', [
    (404, b'{"detail": "Requested certificate was not found"}'),
    (500, b'server error'),
    (200, b'this is not json'),
    (200, b'[]'),
])
def test_an_answer_that_is_not_an_answer_is_not_a_renewal(status, body):
    """Every one of these is an absence of information, and the caller falls
    back to the threshold. None of them may read as "renew now"."""
    get = _transport({DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
                      f'{ARI_BASE}/aa.bb': (status, body)})
    client = ari.RenewalInfoClient(get=get, clock=lambda: NOW)

    assert client.says_renew_now(DIRECTORY, 'aa.bb') is False


# --- what the sweep does with it ------------------------------------------

class _Manager:
    """The three methods `_ari_says_renew` uses, and nothing else."""

    def __init__(self, tmp_path, directory=DIRECTORY):
        from modules.core.certificates import CertificateManager

        self.real = CertificateManager.__new__(CertificateManager)
        self.real.cert_dir = tmp_path
        self.real.ca_manager = self
        self._directory = directory

    def get_ca_config(self, provider, account_id):
        return {}, account_id

    def get_acme_server_url(self, provider, staging=False, account_config=None):
        if self._directory is None:
            raise ValueError(f'Unsupported CA provider: {provider}')
        return self._directory


@pytest.fixture
def swept(tmp_path):
    """A certificate on disk plus the manager methods the hook needs."""
    cert, _key = _cert()
    domain = 'ari.example.test'
    (tmp_path / domain).mkdir()
    (tmp_path / domain / 'cert.pem').write_bytes(
        cert.public_bytes(serialization.Encoding.PEM))
    manager = _Manager(tmp_path)
    return manager.real, domain, ari.certificate_id(cert)


def _with_client(manager, get):
    manager._ari_client = ari.RenewalInfoClient(get=get, clock=lambda: NOW)
    return manager


def test_the_sweep_renews_when_the_ca_says_so(swept):
    """THE regression: the threshold has not fired, and the certificate
    renews anyway because its CA asked for it."""
    manager, domain, cert_id = swept
    _with_client(manager, _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        f'{ARI_BASE}/{cert_id}': (200, _window(-48, -24)),
    }))

    assert manager._ari_says_renew(domain, {'ca_provider': 'letsencrypt'},
                                   {}, now=NOW) is True


def test_the_sweep_waits_when_the_ca_says_wait(swept):
    manager, domain, cert_id = swept
    _with_client(manager, _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        f'{ARI_BASE}/{cert_id}': (200, _window(48, 72)),
    }))

    assert manager._ari_says_renew(domain, {'ca_provider': 'letsencrypt'},
                                   {}, now=NOW) is False


def test_a_setting_turns_it_off(swept):
    """And it is checked before anything is fetched: an operator who switched
    it off must not see the request in their egress log."""
    manager, domain, cert_id = swept
    get = _transport({DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
                      f'{ARI_BASE}/{cert_id}': (200, _window(-48, -24))})
    _with_client(manager, get)

    assert manager._ari_says_renew(domain, {'ca_provider': 'letsencrypt'},
                                   {'ari_enabled': False}, now=NOW) is False
    assert get.calls == []


def test_an_unreadable_certificate_is_not_a_renewal(tmp_path):
    """Every absence answers False. That asymmetry is the safety property:
    this can only make a renewal happen SOONER than the threshold would."""
    manager = _Manager(tmp_path).real
    _with_client(manager, _transport({DIRECTORY: (200, {'renewalInfo': ARI_BASE})}))

    assert manager._ari_says_renew('not-on-disk.example.test',
                                   {'ca_provider': 'letsencrypt'},
                                   {}, now=NOW) is False


def test_a_ca_with_no_directory_is_not_a_renewal(tmp_path):
    manager = _Manager(tmp_path, directory=None).real
    _with_client(manager, _transport({}))

    assert manager._ari_says_renew('anything.example.test',
                                   {'ca_provider': 'nonsense'},
                                   {}, now=NOW) is False


def test_without_a_ca_manager_nothing_is_asked(tmp_path):
    from modules.core.certificates import CertificateManager

    manager = CertificateManager.__new__(CertificateManager)
    manager.cert_dir = tmp_path
    manager.ca_manager = None

    assert manager._ari_says_renew('x.example.test', {}, {}, now=NOW) is False


def test_the_threshold_still_decides_on_its_own():
    """THE control, and the one that matters. ARI is consulted only for a
    certificate the threshold did NOT already call due, so nothing here can
    delay a renewal. Read off the call site, because that ordering is the
    whole safety argument and an edit could reverse it without failing any
    of the tests above."""
    import inspect

    from modules.core.certificates import CertificateManager

    source = inspect.getsource(CertificateManager._renew_if_due)
    guard = source.index("if not cert_info.get('needs_renewal')")
    ask = source.index('_ari_says_renew')

    assert guard < ask, (
        'ARI is consulted before the threshold, so it can now delay a '
        'renewal as well as advance one')


def test_the_sweep_counts_what_the_ca_brought_forward():
    """A renewal that happened for a reason the operator's configuration does
    not explain has to be attributable, or the next question is "why did this
    renew 40 days early" with nothing to answer it."""
    import inspect

    from modules.core.certificates import CertificateManager

    source = inspect.getsource(CertificateManager._check_renewals)

    assert "'ari_advanced': 0" in source, (
        'the counter is not in the summary shape, so a caller has to know '
        'which early return produced the dict')


# --- the measurement this was built on ------------------------------------

@pytest.mark.network
def test_the_encoding_matches_a_real_ca():
    """The identifier, against Let's Encrypt production.

    Marked `network` and excluded from the everyday run, because the suite
    does not reach out. It is here because the offline tests above cannot
    tell a correct encoding from a plausible one: a wrong identifier and a
    certificate the CA has pruned both answer 404. Only a 200 with a window
    proves the encoding, and only a live certificate can produce one.

    It is also not sufficient on its own, which the mutation showed: drop the
    DER sign byte from the serial and this test still passes, because the
    certificate it happens to fetch has a serial whose top bit is clear. One
    live certificate exercises one serial. The parametrised encoding test
    above is what covers the other half of them.
    """
    import ssl

    pem = ssl.get_server_certificate(('letsencrypt.org', 443))
    cert = x509.load_pem_x509_certificate(pem.encode())
    cert_id = ari.certificate_id(cert)

    client = ari.RenewalInfoClient(timeout=15)
    payload = client.renewal_info(
        'https://acme-v02.api.letsencrypt.org/directory', cert_id)

    assert payload is not None, (
        f'Let\'s Encrypt did not answer for {cert_id}; either the encoding '
        f'is wrong or this host stopped using Let\'s Encrypt')
    window = ari.parse_window(payload)
    assert window is not None, payload
    start, end = window
    assert start < end
    assert start < cert.not_valid_after_utc.replace(tzinfo=None), (
        'the CA suggests renewing after the certificate expires')
    assert os.environ is not None  # keeps the import honest
