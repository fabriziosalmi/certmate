"""Three operations that had a budget and no measurement.

Exactly one performance property in this project was under test: that `/health`
stays responsive while certificates are being issued
(`test_concurrent_async_creates_keep_health_responsive`). Everything else had a
budget people reasoned about in comments — "iterates 100s of domains", "which
under a CPU-throttled container makes the listing crawl" — and no number, so
"it feels slower" could not be turned into a comparison.

These are the three operations with a natural budget: the certificate listing at
a stated domain count, a listing served from a remote storage backend, and a
renewal sweep.

**What is asserted is deterministic; what is timed is only reported.** A
wall-clock ceiling measures the machine as much as the code — one GC pause on a
loaded runner fails it with nothing wrong, and the reliable response to that is
to raise the ceiling until it never fires. So each test asserts a *count* that
does not vary with the hardware: settings loads per listing, backend
round-trips per domain, settings loads per sweep. Those are the numbers that
actually decide whether these operations scale, and they are the ones that
regress silently.

The timings are printed with `-s` and recorded in the docstrings below as
measured on one machine, so a later run has something to compare against
instead of an impression.
"""
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

# Big enough that a per-domain cost is visible above the fixed setup, small
# enough that generating the certificates does not dominate the test run.
DOMAIN_COUNT = 120


def _certificate(days_left, key_kind='rsa'):
    """One self-signed certificate and its key.

    The key matters twice over. Since #608 a certificate with no private key is
    reported as needing attention regardless of expiry, so a sweep over key-less
    certs would measure the renewal path rather than the skip path. And the KIND
    of key decides most of the per-domain cost: reading a certificate's
    information compares the key against the certificate, and loading a private
    key is where OpenSSL validates it — measured on one machine, 51.6 ms for
    RSA-2048 against 0.020 ms for EC P-256.

    This file used to generate EC keys only. CertMate's default key shape is
    `rsa`/2048, so the per-domain figure it recorded described an estate almost
    nobody runs; both are measured now, and the RSA row is the default one.
    """
    key = (rsa.generate_private_key(public_exponent=65537, key_size=2048)
           if key_kind == 'rsa' else ec.generate_private_key(ec.SECP256R1()))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days_left))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


class _CountingSettings(SettingsManager):
    """A real SettingsManager that counts how often it is asked to load.

    Counting the real one rather than stubbing it: the property under test is
    that callers thread an already-loaded settings dict through, and a stub
    would pass whether or not the real load path is reachable.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.loads = 0

    def load_settings(self, *args, **kwargs):
        self.loads += 1
        return super().load_settings(*args, **kwargs)


@pytest.fixture(scope='module', params=['rsa', 'ec'])
def populated(request, tmp_path_factory):
    """One instance with DOMAIN_COUNT complete certificates on disk.

    Module-scoped: generating the keys is the slow part and it is setup, not
    the thing being measured. Parametrised over the two key shapes CertMate
    issues, because the counts asserted below are the same for both and the
    timings are not — see `_certificate`.
    """
    root = tmp_path_factory.mktemp(f'perf-{request.param}')
    cert_dir = root / 'certificates'
    data_dir = root / 'data'
    for directory in (cert_dir, data_dir, root / 'backups', root / 'logs'):
        directory.mkdir()

    file_ops = FileOperations(cert_dir=cert_dir, data_dir=data_dir,
                              backup_dir=root / 'backups',
                              logs_dir=root / 'logs')
    settings = _CountingSettings(file_ops=file_ops,
                                 settings_file=data_dir / 'settings.json')

    # One key pair reused across domains: the certificates differ only in what
    # they are named, and generating 120 distinct keys would double the setup
    # for a property that does not depend on them being distinct.
    cert_pem, key_pem = _certificate(days_left=60, key_kind=request.param)
    domains = [f'perf-{index}.example.com' for index in range(DOMAIN_COUNT)]
    for domain in domains:
        directory = cert_dir / domain
        directory.mkdir()
        (directory / 'cert.pem').write_bytes(cert_pem)
        (directory / 'privkey.pem').write_bytes(key_pem)
        (directory / 'fullchain.pem').write_bytes(cert_pem)
        (directory / 'chain.pem').write_bytes(cert_pem)

    manager = CertificateManager(cert_dir=cert_dir, settings_manager=settings,
                                 dns_manager=MagicMock(),
                                 shell_executor=MagicMock())
    return manager, settings, domains, request.param


# --- 1. the listing at a stated domain count -----------------------------

def test_a_listing_loads_settings_once_not_once_per_domain(populated):
    """Measured at 120 domains on an M-series laptop: **0 settings loads**,
    and the wall clock depends on the key shape and on whether the key states
    are already known:

        rsa  cold 5631 ms (46.93 ms/domain)  repeat 9 ms (0.08 ms/domain)
        ec   cold   13 ms ( 0.11 ms/domain)  repeat 8 ms (0.06 ms/domain)

    The RSA row is the default installation, and the gap between its two
    columns is `private_key_state` remembering an answer whose inputs have not
    changed rather than re-validating the key on every read.

    This test is the settings-load property: workers have no Flask request
    context, so the request-scoped settings cache does not apply to them, and a
    per-domain load means reading settings.json off disk once per domain — 120
    reads for one page.
    """
    manager, settings, domains, key_kind = populated
    loaded = settings.load_settings()
    settings.loads = 0

    started = time.perf_counter()
    infos = [manager.get_certificate_info(domain, settings=loaded)
             for domain in domains]
    elapsed = time.perf_counter() - started

    started = time.perf_counter()
    for domain in domains:
        manager.get_certificate_info(domain, settings=loaded)
    repeat = time.perf_counter() - started

    print(f'\nlisting {len(domains)} {key_kind} domains: '
          f'cold {elapsed * 1000:.0f} ms ({elapsed / len(domains) * 1000:.2f} '
          f'ms/domain), repeat {repeat * 1000:.0f} ms '
          f'({repeat / len(domains) * 1000:.2f} ms/domain), '
          f'{settings.loads} settings loads')

    assert all(info and info['exists'] for info in infos)
    assert settings.loads == 0, (
        f'{settings.loads} settings loads for {len(domains)} domains — the '
        f'listing is reading settings.json per domain again')


def test_the_listing_reads_each_certificate_once(populated):
    """CONTROL for the count above: a listing that loaded no settings because
    it also did no work would pass it. Every domain has to come back parsed."""
    manager, settings, domains, key_kind = populated
    loaded = settings.load_settings()

    infos = [manager.get_certificate_info(domain, settings=loaded)
             for domain in domains]

    assert len({info['domain'] for info in infos}) == len(domains)
    assert all(info['days_left'] in (59, 60) for info in infos)


# --- 2. a listing served from a remote storage backend -------------------

class _CountingBackend:
    """A storage backend that counts round-trips and charges for them.

    The latency is what makes the count matter: against the local filesystem an
    extra fetch per domain is invisible, and against Vault or Azure Key Vault
    over a network it is the whole page load.
    """

    LATENCY_SECONDS = 0.001

    def __init__(self, cert_pem, metadata):
        self.cert_pem = cert_pem
        self.metadata = metadata
        self.round_trips = 0

    def retrieve_certificate_info(self, domain):
        self.round_trips += 1
        time.sleep(self.LATENCY_SECONDS)
        return {'cert.pem': self.cert_pem}, dict(self.metadata, domain=domain)

    def retrieve_certificate(self, domain):  # pragma: no cover - not the path
        raise AssertionError(
            'the listing pulled a FULL certificate, private key included, out '
            'of the secrets backend for a view that only needs cert.pem')


def test_a_remote_backed_listing_costs_one_round_trip_per_domain(populated):
    """Measured at 120 domains against a backend charging 1 ms per call, four
    runs: **120 round-trips** cold and **0** warm; 155-168 ms cold, 1-4 ms
    warm. The cold figure is the 120 ms of simulated network plus the parse.

    One per domain is the floor for a backend with no bulk read. What this
    pins is that it is not *more* than one — and that the 60-second cert-info
    cache actually removes them on the next load, which is what makes a
    remote-backed dashboard usable at all.
    """
    manager, settings, domains, key_kind = populated
    cert_pem = (manager.cert_dir / domains[0] / 'cert.pem').read_bytes()
    backend = _CountingBackend(cert_pem, {'dns_provider': 'cloudflare'})
    manager.storage_manager = backend
    manager._certificate_info_cache.clear()
    loaded = settings.load_settings()
    try:
        started = time.perf_counter()
        for domain in domains:
            manager.get_certificate_info(domain, settings=loaded)
        cold = time.perf_counter() - started
        cold_trips = backend.round_trips

        started = time.perf_counter()
        for domain in domains:
            manager.get_certificate_info(domain, settings=loaded)
        warm = time.perf_counter() - started
        warm_trips = backend.round_trips - cold_trips
    finally:
        manager.storage_manager = None
        manager._certificate_info_cache.clear()

    print(f'\nremote-backed listing of {len(domains)} domains: '
          f'{cold * 1000:.0f} ms cold / {cold_trips} round-trips, '
          f'{warm * 1000:.0f} ms warm / {warm_trips} round-trips')

    assert cold_trips == len(domains), (
        f'{cold_trips} round-trips for {len(domains)} domains — the listing '
        f'fetches a domain more than once per load')
    assert warm_trips == 0, (
        f'{warm_trips} round-trips on the second load — the cert-info cache '
        f'is not serving the dashboard, so every refresh pays the network '
        f'again')


# --- 3. the renewal sweep ------------------------------------------------

def test_a_sweep_loads_settings_a_fixed_number_of_times(populated):
    """Measured at 120 certificates, none due: **1 settings load** for the
    whole sweep, 13-20 ms. One, not 120 — the count does not move with the
    number of certificates, which is the whole property.

    The wall clock here is not comparable to a cold listing: this runs after
    the listing test in the same module, against the same manager, so every
    key state is already known. A sweep on a freshly started process pays the
    per-domain cost of the listing's cold column once.

    The sweep is the one caller that visits every domain in a background
    thread, outside any request context, so nothing else is holding a cached
    settings dict for it. A per-domain load here is 120 disk reads on a timer,
    every sweep, forever.
    """
    manager, settings, domains, key_kind = populated
    def _register(stored):
        stored['domains'] = [{'domain': domain, 'dns_provider': 'cloudflare'}
                             for domain in domains]
        stored['auto_renew'] = True

    settings.update(_register, reason='perf-baseline')
    settings.loads = 0

    started = time.perf_counter()
    manager.check_renewals()
    elapsed = time.perf_counter() - started

    print(f'\nrenewal sweep over {len(domains)} certificates: '
          f'{elapsed * 1000:.0f} ms, {settings.loads} settings loads')

    # 3, not 1: a legitimate refactor may add a load, and pinning the exact
    # measured value would fail on a change that is not a regression. What must
    # never happen is a count that tracks the domain count.
    assert settings.loads <= 3, (
        f'{settings.loads} settings loads for a sweep over {len(domains)} '
        f'certificates — the sweep is loading settings per domain')


def test_the_sweep_renewed_nothing(populated):
    """CONTROL: the count above is the cost of the SKIP path. A sweep that
    tried to renew would shell out to certbot, and the number would be
    measuring a MagicMock rather than the loop."""
    manager, _, _, _ = populated
    manager.shell_executor.run.assert_not_called()
