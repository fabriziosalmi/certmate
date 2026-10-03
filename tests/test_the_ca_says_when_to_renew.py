"""Renewal timing from the CA, not only from a number we picked (#393).

CertMate renews at `days_left <= renewal_threshold_days`, default 30. That is
CertMate's opinion, identical for every certificate and every CA. Since
RFC 9773 the CA publishes its own, per certificate: a `renewalInfo` endpoint
answering a window during which it wants that certificate replaced. The window
matters most when it moves *earlier* — a batch replacement, a compromised
intermediate, a ruling — which a fixed 30-day rule finds out about when the
certificate stops working.

**What is asserted here.** Since #393 the CA's window decides in both directions: it brings a
renewal forward, and it postpones one, through the one rule of modules/core/renewal_policy.py.
The safety property is the floor: a window can postpone a renewal only until a sixth of the
lifetime is left, never past the window's end, and every absence (switched off, no identifier,
a CA without ARI, a CA that did not answer) leaves no window, so the threshold decides. There
are controls below for each.

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

from modules.core import ari, renewal_policy

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
    """The three methods `_refresh_renewal_info` uses, and nothing else."""

    def __init__(self, tmp_path, directory=DIRECTORY):
        from modules.core.certificates import CertificateManager

        self.real = CertificateManager.__new__(CertificateManager)
        self.real.cert_dir = tmp_path
        self.real.ca_manager = self
        # The real one: recording an ARI answer invalidates it (#962).
        from modules.core.utils import DeploymentStatusCache
        self.real._certificate_info_cache = DeploymentStatusCache()
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


def _decided(manager, domain, settings=None, threshold=30):
    """Ask the CA as the sweep does, then the decision renewal_policy takes on what was recorded:
    is the certificate due at NOW?"""
    manager._refresh_renewal_info(domain, {'ca_provider': 'letsencrypt'}, settings or {}, now=NOW)
    cert = x509.load_pem_x509_certificate((manager.cert_dir / domain / 'cert.pem').read_bytes())
    instant, _ = renewal_policy.renews_at(
        cert.not_valid_before_utc.replace(tzinfo=None), cert.not_valid_after_utc.replace(tzinfo=None),
        threshold, _record(manager, domain))
    return NOW >= instant


def test_the_sweep_renews_when_the_ca_says_so(swept):
    """THE regression: the threshold has not fired, and the certificate
    renews anyway because its CA asked for it."""
    manager, domain, cert_id = swept
    _with_client(manager, _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        f'{ARI_BASE}/{cert_id}': (200, _window(-48, -24)),
    }))

    assert _decided(manager, domain) is True


def test_the_sweep_waits_when_the_ca_says_wait(swept):
    manager, domain, cert_id = swept
    _with_client(manager, _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        f'{ARI_BASE}/{cert_id}': (200, _window(48, 72)),
    }))

    assert _decided(manager, domain) is False


def test_a_setting_turns_it_off(swept):
    """And it is checked before anything is fetched: an operator who switched
    it off must not see the request in their egress log."""
    manager, domain, cert_id = swept
    get = _transport({DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
                      f'{ARI_BASE}/{cert_id}': (200, _window(-48, -24))})
    _with_client(manager, get)

    assert _decided(manager, domain, settings={'ari_enabled': False}) is False
    assert get.calls == []
    assert _record(manager, domain) is None


def test_an_unreadable_certificate_leaves_no_window(tmp_path):
    """Every absence leaves no window, so the threshold decides: a CA, or a certificate, that
    cannot be asked cannot move a renewal in either direction."""
    manager = _Manager(tmp_path).real
    _with_client(manager, _transport({DIRECTORY: (200, {'renewalInfo': ARI_BASE})}))

    assert manager._refresh_renewal_info('not-on-disk.example.test',
                                         {'ca_provider': 'letsencrypt'},
                                         {}, now=NOW) == ari.STATUS_NO_IDENTIFIER


def test_a_ca_with_no_directory_leaves_no_window(swept):
    manager, domain, _cert_id = swept
    manager.ca_manager._directory = None
    _with_client(manager, _transport({}))

    assert manager._refresh_renewal_info(domain, {'ca_provider': 'nonsense'},
                                         {}, now=NOW) == ari.STATUS_UNSUPPORTED
    assert _decided(manager, domain) is False


def test_without_a_ca_manager_nothing_is_asked(tmp_path):
    from modules.core.certificates import CertificateManager

    manager = CertificateManager.__new__(CertificateManager)
    manager.cert_dir = tmp_path
    manager.ca_manager = None

    assert manager._refresh_renewal_info('x.example.test', {}, {}, now=NOW) != ari.STATUS_WINDOW


def test_a_window_postpones_only_down_to_the_floor():
    """THE control, now that a window can postpone (#393). The window of a 90-day certificate
    says renew in 300 days; the threshold would renew it now, 20 days before expiry. It waits,
    but only until a sixth of the lifetime (15 days) is left, and from there it is due whatever
    the window says. Before #393 the control was that ARI could not postpone at all."""
    not_before = NOW - timedelta(days=70)
    not_after = NOW + timedelta(days=20)
    far = {'status': 'window', 'renew_at': renewal_policy.stamp(NOW + timedelta(days=300)),
           'window_end': renewal_policy.stamp(NOW + timedelta(days=301))}

    instant, reason = renewal_policy.renews_at(not_before, not_after, 30, far)

    assert reason == renewal_policy.REASON_ARI_FLOOR
    assert instant == not_after - timedelta(days=15)
    assert NOW < instant <= NOW + timedelta(days=5)


def test_a_window_that_has_ended_is_due():
    """Never after the window's end: a window that closed without the sweep acting (an instance
    that was down) does not leave the certificate waiting for the floor."""
    not_before = NOW - timedelta(days=30)
    not_after = NOW + timedelta(days=60)
    ended = {'status': 'window', 'renew_at': renewal_policy.stamp(NOW + timedelta(days=50)),
             'window_end': renewal_policy.stamp(NOW - timedelta(hours=1))}

    instant, reason = renewal_policy.renews_at(not_before, not_after, 30, ended)

    assert reason == renewal_policy.REASON_ARI_ENDED and instant <= NOW


def test_the_sweep_counts_what_the_ca_brought_forward():
    """A renewal that happened for a reason the operator's configuration does
    not explain has to be attributable, or the next question is "why did this
    renew 40 days early" with nothing to answer it."""
    import inspect

    from modules.core.certificates import CertificateManager

    source = inspect.getsource(CertificateManager._check_renewals)

    assert "'ari_advanced': 0" in source and "'ari_postponed': 0" in source, (
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


# --- what the CA said, kept where an operator can see it (#962) -------------

def _record(manager, domain):
    from modules.core.certificates import RENEWAL_INFO_FILE

    path = manager.cert_dir / domain / RENEWAL_INFO_FILE
    return json.loads(path.read_text()) if path.exists() else None


def test_the_sweep_keeps_the_window_it_acted_on(swept):
    """THE point of the step. The instant shown is the one `due_at` picks —
    not re-derived later — so what an operator reads is what the sweep does."""
    manager, domain, cert_id = swept
    payload = _window(24, 48)
    payload['explanationURL'] = 'https://ca.example.test/incident/42'
    _with_client(manager, _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        f'{ARI_BASE}/{cert_id}': (200, payload),
    }))

    assert manager._refresh_renewal_info(domain, {}, {}, now=NOW) == ari.STATUS_WINDOW
    record = _record(manager, domain)

    start, end = ari.parse_window(payload)
    assert record['status'] == ari.STATUS_WINDOW
    assert record['cert_id'] == cert_id
    assert record['checked_at'] == '2026-09-24T12:00:00Z'
    assert record['window_start'] == start.isoformat() + 'Z'
    assert record['window_end'] == end.isoformat() + 'Z'
    assert record['renew_at'] == \
        ari.due_at(cert_id, start, end).replace(microsecond=0).isoformat() + 'Z'
    assert record['explanation_url'] == 'https://ca.example.test/incident/42'


@pytest.mark.parametrize('directory_answer, ari_answer, expected', [
    # The CA does not speak ARI: a fact about the CA.
    ((200, {'newOrder': 'x'}), None, ari.STATUS_UNSUPPORTED),
    # It does, and did not answer tonight: an incident.
    ((200, {'renewalInfo': ARI_BASE}), (500, b'oops'), ari.STATUS_UNAVAILABLE),
    ((200, {'renewalInfo': ARI_BASE}), (200, b'not json'), ari.STATUS_UNAVAILABLE),
    ((200, {'renewalInfo': ARI_BASE}), (200, {'suggestedWindow': {}}),
     ari.STATUS_UNAVAILABLE),
    # The directory itself is down.
    ((503, b''), None, ari.STATUS_UNAVAILABLE),
])
def test_each_kind_of_absence_is_recorded_as_itself(
        swept, directory_answer, ari_answer, expected):
    """The renewal decision needs only "no". An operator needs to know which
    no: `unsupported` never changes, `unavailable` should not last."""
    manager, domain, cert_id = swept
    answers = {DIRECTORY: directory_answer}
    if ari_answer is not None:
        answers[f'{ARI_BASE}/{cert_id}'] = ari_answer
    _with_client(manager, _transport(answers))

    assert manager._refresh_renewal_info(domain, {}, {}, now=NOW) == expected
    record = _record(manager, domain)
    assert record['status'] == expected
    assert record['window_start'] is None and record['renew_at'] is None


def test_a_certificate_that_cannot_be_named_is_recorded(tmp_path):
    cert, _key = _cert(aki=None)
    domain = 'ari.example.test'
    (tmp_path / domain).mkdir()
    (tmp_path / domain / 'cert.pem').write_bytes(
        cert.public_bytes(serialization.Encoding.PEM))
    manager = _with_client(_Manager(tmp_path).real, _transport({}))

    assert manager._refresh_renewal_info(domain, {}, {}, now=NOW) == ari.STATUS_NO_IDENTIFIER
    assert _record(manager, domain)['status'] == ari.STATUS_NO_IDENTIFIER


@pytest.mark.parametrize('url', [
    'javascript:alert(1)',
    'http://ca.example.test/incident',
    'https://',
    'https://ca.example.test/' + 'a' * 3000,
    42,
])
def test_only_an_https_explanation_is_kept(url):
    """It is rendered as a link, and the CA's answer arrives over the
    network: a `javascript:` URL here would be a script in the dashboard."""
    assert ari.explanation_url({'explanationURL': url}) is None


def test_a_record_that_cannot_be_written_does_not_fail_the_sweep(swept):
    manager, domain, cert_id = swept
    _with_client(manager, _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        f'{ARI_BASE}/{cert_id}': (200, _window(-48, -24)),
    }))

    def refuse(path, data):
        raise PermissionError(13, 'Permission denied', str(path))

    manager._atomic_json_write = refuse

    # Nothing raised, and with no record there is no window: the threshold decides.
    assert manager._refresh_renewal_info(domain, {}, {}, now=NOW) == ari.STATUS_WINDOW
    assert _record(manager, domain) is None


# --- and read back, without asking the CA ----------------------------------

def _parsed(manager, domain, settings=None):
    raw = (manager.cert_dir / domain / 'cert.pem').read_bytes()
    return manager._parse_certificate_info(
        domain, raw, {'dns_provider': 'cloudflare'},
        settings=settings if settings is not None else {})


def _forbidden_transport(url, timeout):
    raise AssertionError(f'asked the CA from a read path: {url}')


def test_the_response_carries_the_recorded_window(swept):
    manager, domain, cert_id = swept
    _with_client(manager, _transport({
        DIRECTORY: (200, {'renewalInfo': ARI_BASE}),
        f'{ARI_BASE}/{cert_id}': (200, _window(24, 48)),
    }))
    manager._refresh_renewal_info(domain, {}, {}, now=NOW)
    # Every read below must be served from the record.
    _with_client(manager, _forbidden_transport)

    info = _parsed(manager, domain)['renewal_info']

    assert info['status'] == ari.STATUS_WINDOW
    assert info['renew_at'] == _record(manager, domain)['renew_at']
    assert 'cert_id' not in info, 'an on-disk key leaked into the API'


def test_a_record_about_the_previous_certificate_is_not_shown(swept):
    """After a renewal the serial changes; until the next sweep asks again
    the file on disk describes a certificate that is no longer served."""
    manager, domain, _cert_id = swept
    from modules.core.certificates import RENEWAL_INFO_FILE

    predecessor = ari.certificate_id(_cert(serial=54321)[0])
    assert predecessor != _cert_id
    stale = ari.observation(predecessor, ari.STATUS_WINDOW, _window(24, 48), NOW)
    (manager.cert_dir / domain / RENEWAL_INFO_FILE).write_text(json.dumps(stale))

    assert _parsed(manager, domain)['renewal_info'] is None


def test_switched_off_says_so(swept):
    manager, domain, _cert_id = swept
    info = _parsed(manager, domain, settings={'ari_enabled': False})
    assert info['renewal_info']['status'] == 'disabled'
    assert info['renewal_info']['renew_at'] is None


def test_the_list_endpoint_keeps_the_field():
    """The dashboard reads GET /api/certificates, which marshals through
    the model: a field the model does not declare is silently dropped."""
    from flask_restx import Api, marshal

    from flask import Flask
    from modules.api.models import create_api_models

    api = Api(Flask(__name__))
    model = create_api_models(api)['certificate_model']
    record = ari.observation('aa.bb', ari.STATUS_WINDOW, _window(24, 48), NOW)
    shown = {k: v for k, v in record.items() if k != 'cert_id'}

    out = marshal({'domain': 'a.example', 'renewal_info': shown}, model)
    assert out['renewal_info'] == shown
    assert marshal({'domain': 'a.example', 'renewal_info': None},
                   model)['renewal_info'] is None


def test_no_record_yet_is_null(swept):
    manager, domain, _cert_id = swept
    assert _parsed(manager, domain)['renewal_info'] is None


def test_a_broken_record_never_becomes_a_renewal(swept):
    """THE control on the read path. `_parse_certificate_info` answers any
    exception inside it with "unparseable, needs_renewal: True". A defect in
    a display field must not reach that branch."""
    manager, domain, _cert_id = swept

    def explode(*args, **kwargs):
        raise KeyError('a bug in the reader')

    manager._read_renewal_info = explode
    info = _parsed(manager, domain)

    assert info['renewal_info'] is None
    assert info['expiry_date'] is not None
    assert info['needs_renewal'] is False


def test_a_link_on_disk_is_filtered_again_on_the_way_out(swept):
    """The record can come from a restored backup rather than from the sweep,
    and API clients other than the dashboard may render it as a link."""
    manager, domain, cert_id = swept
    from modules.core.certificates import RENEWAL_INFO_FILE

    record = ari.observation(cert_id, ari.STATUS_WINDOW, _window(24, 48), NOW)
    record['explanation_url'] = 'javascript:alert(document.domain)'
    (manager.cert_dir / domain / RENEWAL_INFO_FILE).write_text(json.dumps(record))

    info = _parsed(manager, domain)['renewal_info']
    assert info['status'] == ari.STATUS_WINDOW
    assert info['explanation_url'] is None


@pytest.mark.parametrize('cert_id', ['aa.bb', 'cc.dd', 'uVnyjs8i8Ib.BUOTO'])
def test_the_instant_shown_is_the_instant_acted_on(cert_id):
    """Found by the LE-staging E2E, not by these tests (#962). The record
    showed `renew_at` to the second while the sweep compared against the
    point to the microsecond, so a sweep at the shown instant did not renew.
    Staging's windows carry fractional seconds, so the start has one here."""
    payload = {'suggestedWindow': {'start': '2026-11-25T12:06:10.412Z',
                                   'end': '2026-11-27T07:16:59.907Z'}}
    record = ari.observation(cert_id, ari.STATUS_WINDOW, payload, NOW)
    shown = datetime.fromisoformat(record['renew_at'].replace('Z', ''))

    assert ari.is_due(cert_id, payload, shown) is True
    assert ari.is_due(cert_id, payload, shown - timedelta(seconds=1)) is False
    start, end = ari.parse_window(payload)
    assert start <= shown <= end


# --- what the sweep does with the decision (#962, #393) ----------------------

def _sweep_manager(days_left, window=None, threshold_hint=30):
    """The sweep around one certificate of 90 days with `days_left` left, a recorded window or
    none, and certbot replaced by a recorder. get_certificate_info answers what renewal_policy
    decides, as the real one does."""
    from unittest.mock import MagicMock

    from modules.core.certificates import CertificateManager
    from modules.core.utils import utc_now

    now = utc_now()
    not_after = now + timedelta(days=days_left)
    not_before = not_after - timedelta(days=90)
    record = None
    if window is not None:
        start, end = window
        record = {'status': 'window', 'renew_at': renewal_policy.stamp(now + timedelta(days=start)),
                  'window_end': renewal_policy.stamp(now + timedelta(days=end))}

    def info(domain, settings=None, use_cache=True):
        threshold = CertificateManager._coerce_renewal_threshold_days(settings)
        instant, _ = renewal_policy.renews_at(not_before, not_after, threshold, record)
        return {'exists': True, 'days_left': days_left, 'renewal_info': record,
                'renews_at': renewal_policy.stamp(instant),
                'needs_renewal': utc_now() >= instant}

    manager = CertificateManager.__new__(CertificateManager)
    manager.get_certificate_info = MagicMock(side_effect=info)
    manager._served_validity = MagicMock(return_value=(not_before, not_after))
    manager._refresh_renewal_info = MagicMock(return_value='window' if window else None)
    manager.renew_certificate = MagicMock(
        side_effect=lambda domain, force=False: {'success': True, 'renewed': True, 'domain': domain})
    manager._audit_scheduled_renew = MagicMock()
    manager._record_renewal_metrics = MagicMock()
    manager._publish_failed_event = MagicMock()
    manager._publish_renewed_event = MagicMock()
    return manager


def _summary():
    return {'checked': 0, 'renewed': 0, 'failed': 0, 'skipped_busy': 0,
            'skipped_not_due': 0, 'ari_advanced': 0, 'ari_postponed': 0,
            'early_forced': 0, 'early_deferred': 0}


def test_a_renewal_the_ca_asked_for_actually_happens():
    """THE regression of #962. A mass revocation moves the window to now on a certificate with
    60 days left. The threshold says no, the CA says yes, and certbot must be forced, or its
    own gate answers "not yet due" and renews nothing."""
    manager = _sweep_manager(days_left=60, window=(-2, -1))
    summary = _summary()

    assert manager._renew_if_due('ari.example.test', {}, summary) is True
    assert summary['renewed'] == 1 and summary['ari_advanced'] == 1
    manager.renew_certificate.assert_called_once_with('ari.example.test', force=True)


def test_the_counter_says_what_happened_not_what_was_tried():
    """`ari_advanced` is what makes an early renewal attributable. Counted
    before the attempt, it reported renewals that never happened — and still
    would, for a renewal that fails."""
    manager = _sweep_manager(days_left=60, window=(-2, -1))
    manager.renew_certificate.side_effect = RuntimeError('certbot exited 1')
    summary = _summary()

    assert manager._renew_if_due('ari.example.test', {}, summary) is False
    assert summary['failed'] == 1
    assert summary['ari_advanced'] == 0


def test_a_renewal_decided_by_the_threshold_is_forced_too():
    """#393: CertMate decides and certbot executes, so the threshold path is forced as well.
    Before, it was left to certbot's own gate, which is how certbot's rule came to decide."""
    manager = _sweep_manager(days_left=20)
    summary = _summary()

    assert manager._renew_if_due('ari.example.test', {}, summary) is True
    manager.renew_certificate.assert_called_once_with('ari.example.test', force=True)
    manager._refresh_renewal_info.assert_called_once()
    assert summary['ari_advanced'] == 0


def test_the_ca_postpones_a_renewal_the_threshold_would_have_made():
    """The other direction (#393). 25 days left of 90 and a threshold of 30: due by the
    threshold, but the CA's window opens in 5 days, 20 days before expiry, above the floor of
    15. The sweep waits, and says why."""
    manager = _sweep_manager(days_left=25, window=(5, 6))
    summary = _summary()

    assert manager._renew_if_due('ari.example.test', {}, summary) is False
    manager.renew_certificate.assert_not_called()
    assert summary['ari_postponed'] == 1


def test_the_floor_ends_a_postponement():
    """14 days left of 90: below the floor of 15, so a window that still says later does not
    hold the certificate. It renews, forced."""
    manager = _sweep_manager(days_left=14, window=(30, 31))
    summary = _summary()

    assert manager._renew_if_due('ari.example.test', {}, summary) is True
    manager.renew_certificate.assert_called_once_with('ari.example.test', force=True)
    assert summary['ari_postponed'] == 0


@pytest.mark.parametrize('days_left, window', [(25, (5, 6)), (60, None), (20, None)])
def test_the_ca_is_asked_before_the_decision_is_read(days_left, window):
    """The decision reads the recorded window, so the sweep asks the CA first, for every
    certificate, and reads the certificate's answer again after. Asked only for a certificate
    the threshold had not called due (the order before #393), a postponement would act on last
    night's window, and the certificate the CA wants renewed now would wait for the threshold."""
    manager = _sweep_manager(days_left=days_left, window=window)
    order = []
    ask, read = manager._refresh_renewal_info.side_effect, manager.get_certificate_info.side_effect
    manager._refresh_renewal_info.side_effect = lambda *a, **k: order.append('ask') or (ask and ask(*a, **k))
    manager.get_certificate_info.side_effect = lambda *a, **k: order.append('read') or read(*a, **k)

    manager._renew_if_due('ari.example.test', {}, _summary())

    assert order[-2:] == ['ask', 'read'] and order.count('ask') == 1
