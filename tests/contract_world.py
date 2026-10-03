"""The world the route walk runs in: sealed from outside the process, with a certificate in it.

`tests/contract_routes.py` calls every route of the API on the real application. Some of
those routes, called for real, would reach outside the process: issue a certificate with
certbot, ask a DNS server, open a TLS connection to a host the caller names, send a message
to a webhook. The walk must be able to call them anyway, because it is their ANSWERS it
records. Two things make that safe, and they are here so that they can be tested on their own:

  * `sealed()`: while it is open, a connection to anything but the loopback interface, a DNS
    query, and the launch of any program raise. The refusal is recorded (`Seal.attempts`), so
    a walk that tried to leave the process says so, and the code under the walk sees an
    ordinary failure ("could not resolve") and answers the way it answers in production when
    the network is down.
  * `Certbot`: a stand-in for the one program the application launches. It is not a mock that
    returns canned text; it honours what the caller depends on, the way certbot does, by
    writing `live/<name>/{cert,chain,fullchain,privkey}.pem` under the `--config-dir` it was
    given. A double that only answered "exit 0" made the issuance path fail on its own check
    that the files exist, and a walk that stopped there would never have seen the success
    answer of create, renew and reissue, which are the answers callers depend on most.

`seed()` puts a certificate on disk in the shape an issuance leaves it, and the settings that
make an issuance possible (a contact e-mail, a DNS account).
"""
import contextlib
import datetime as dt
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import threading
from pathlib import Path
from unittest import mock

from tests.tls_support import TLSServer, handler, key_pem, make_cert, pem

DOMAIN = 'shop.example.test'
SAN = 'www.shop.example.test'
EMAIL = 'ops@example.test'

_LOOPBACK = ('localhost', '127.0.0.1', '::1', '0.0.0.0', '')   # compared with, never bound


class Escaped(AssertionError):
    """The walk tried to reach outside the process. An AssertionError so that a
    handler that catches `Exception` still shows the refusal in its answer, and a
    handler that catches nothing fails the walk loudly."""


class Seal:
    """What the seal refused, in order. `attempts` is the proof that the walk touched
    the boundary and was stopped there, not that it never came near it."""

    def __init__(self):
        self.attempts = []

    def refuse(self, what):
        self.attempts.append(what)
        raise Escaped(f'refused by the walk: {what}')


def _is_address(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_loopback(host):
    if host in _LOOPBACK:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def warm_up():
    """Ask the questions the application asks of the machine, before the seal goes up.

    `platform.uname()` reads `uname -p` the first time its `processor` is read and remembers
    the answer for the life of the process, and `GET /api/diagnostics/snapshot` asks it. Under the seal the first ask fails
    (a program may not be launched) and every later one succeeds from the cache, so the answer
    depended on whether any test had asked before: an `errors.collect_runtime` entry and no
    runtime fields in a fresh process, the reverse in the full suite. The full suite is where
    this was found; the walk run alone, and twice, agreed with itself.
    """
    import platform
    _ = platform.uname().processor      # a lazy attribute: `uname -p` runs when it is first read, not in uname()
    platform.platform()


@contextlib.contextmanager
def sealed():
    """No network beyond the loopback, no child process. Yields the `Seal`."""
    seal = Seal()
    real_getaddrinfo = socket.getaddrinfo
    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def getaddrinfo(host, *args, **kwargs):
        # An address needs no resolver: it passes, and is refused where a real one would be, at
        # the connection, so that the code sees a connection error and not a DNS one.
        if host is None or (isinstance(host, str) and (_is_loopback(host) or _is_address(host))):
            return real_getaddrinfo(host, *args, **kwargs)
        try:
            seal.refuse(f'resolve {host}')
        except Escaped as exc:
            # What an unreachable resolver looks like to the caller, which is the
            # situation the code is written for.
            raise socket.gaierror(socket.EAI_NONAME, str(exc)) from exc

    def connect(sock, address):
        host = address[0] if isinstance(address, tuple) else address
        if sock.family != socket.AF_UNIX and not _is_loopback(host):
            try:
                seal.refuse(f'connect {host}')
            except Escaped as exc:
                raise OSError(str(exc)) from exc
        return real_connect(sock, address)

    def connect_ex(sock, address):
        host = address[0] if isinstance(address, tuple) else address
        if sock.family != socket.AF_UNIX and not _is_loopback(host):
            seal.attempts.append(f'connect {host}')
            return 111
        return real_connect_ex(sock, address)

    def no_program(*args, **kwargs):
        seal.refuse(f'launch {args[0] if args else kwargs.get("args")}')

    import dns.resolver

    def no_query(self, qname, *args, **kwargs):
        seal.attempts.append(f'dns query {qname}')
        raise dns.resolver.NoNameservers()

    with contextlib.ExitStack() as stack:
        for target, replacement in (
                (socket, ('getaddrinfo', getaddrinfo)),
                (socket.socket, ('connect', connect)),
                (socket.socket, ('connect_ex', connect_ex)),
                (subprocess, ('Popen', no_program)),
                (os, ('system', no_program)),
                (os, ('popen', no_program)),
                (dns.resolver.Resolver, ('resolve', no_query))):
            stack.enter_context(mock.patch.object(target, replacement[0], replacement[1]))
        yield seal


# --------------------------------------------------------------------------
# certbot
# --------------------------------------------------------------------------

def _option(cmd, flag):
    return cmd[cmd.index(flag) + 1] if flag in cmd else None


@contextlib.contextmanager
def working_directory():
    """A directory of its own as the working directory, for as long as the plan runs.

    The DNS credentials file certbot is given is written relative to the working directory
    (`letsencrypt/config/cloudflare-<hash>.ini`) and removed afterwards. With the checkout as the
    working directory, a plan that issues a certificate puts a credential file in the repository
    tree for as long as the issuance takes, and leaves the empty directory behind. Measured.
    """
    previous = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            os.chdir(previous)


class Certbot:
    """The program the application launches, standing in for it.

    `run(cmd, **kwargs)` has `ShellExecutor.run`'s signature and returns what it
    returns. `fail_with(stderr)` makes the next invocation exit 1, which is how the
    failure answers (422 on create, 500 on renew) are reached on purpose.
    """

    produces_artifacts = True

    def __init__(self):
        self.commands = []
        self.cwds = []                  # where each run happened: the plan runs in a directory of its own
        self._failures = []
        self._holds = []
        self._ca = make_cert('Walk Test CA', is_ca=True)
        self._lock = threading.Lock()

    def fail_with(self, stderr='An unexpected error occurred: the walk asked for this failure'):
        with self._lock:
            self._failures.append(stderr)

    def hold_next(self):
        """The next issuance or renewal waits until the returned event is set. How a job is
        caught in flight, which is the only time the job list has anything in it."""
        gate = threading.Event()
        with self._lock:
            self._holds.append(gate)
        return gate

    def run(self, cmd, **kwargs):
        issuing = any(word in cmd for word in ('certonly', 'renew'))
        with self._lock:
            self.commands.append(list(cmd))
            self.cwds.append(os.getcwd())
            failure = self._failures.pop(0) if self._failures else None
            gate = self._holds.pop(0) if (issuing and self._holds) else None
        if gate is not None and not gate.wait(30):
            raise AssertionError('a held certbot run was never released')
        if failure is not None:
            return subprocess.CompletedProcess(cmd, 1, '', failure)
        if '--version' in cmd:
            return subprocess.CompletedProcess(cmd, 0, 'certbot 5.8.0\n', '')
        if any(word in cmd for word in ('certonly', 'renew')):
            self._write_lineage(cmd)
            return subprocess.CompletedProcess(cmd, 0, 'Successfully received certificate.\n', '')
        # Anything else is a deploy hook. It "runs" and exits 0, and nothing is launched.
        for stream in (kwargs.get('stdout'), kwargs.get('stderr')):
            if stream is not None and hasattr(stream, 'write'):
                stream.write(b'')
        return subprocess.CompletedProcess(cmd, 0, '', '')

    def _write_lineage(self, cmd):
        """What certbot leaves behind: the lineage under `<config-dir>/live/<cert-name>/`."""
        config_dir, name = _option(cmd, '--config-dir'), _option(cmd, '--cert-name')
        if not config_dir or not name:
            return
        names = [cmd[i + 1] for i, word in enumerate(cmd[:-1]) if word == '-d'] or [name]
        write_certificate(Path(config_dir) / 'live' / name, name, names[1:], self._ca)


def write_certificate(directory, name, sans=(), ca=None):
    """A certificate, its chain and its key, as certbot writes them."""
    ca_cert, ca_key = ca or make_cert('Walk Test CA', is_ca=True)
    leaf, leaf_key = make_cert(name, san_dns=[name, *sans], issuer=ca_cert, issuer_key=ca_key)
    directory.mkdir(parents=True, exist_ok=True)
    files = {'cert.pem': pem(leaf), 'chain.pem': pem(ca_cert), 'fullchain.pem': pem(leaf) + pem(ca_cert),
             'privkey.pem': key_pem(leaf_key)}
    for filename, content in files.items():
        (directory / filename).write_bytes(content)


@contextlib.contextmanager
def certbot_standing_in(certbot):
    """Route the one certbot launch point (`ShellExecutor.run`) to `certbot`."""
    with mock.patch('modules.core.shell.ShellExecutor.run',
                    lambda self, cmd, **kwargs: certbot.run(cmd, **kwargs)):
        yield certbot


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

class World:
    """What `seed` put in the instance, by the names the plan uses."""

    def __init__(self, domain, alias_domain, discovered, setup_key, port):
        self.domain = domain
        self.alias_domain = alias_domain
        self.discovered = discovered        # two fingerprints in the inventory, neither managed
        self.setup_key = setup_key          # an API key minted in setup mode, awaiting confirmation
        self.port = port                    # a TLS server on the loopback interface (`serving`)


@contextlib.contextmanager
def serving():
    """A TLS server on the loopback interface, so that the probes have something to read.

    The seal lets the loopback interface through, and the deployment probe allows loopback
    by design; the discovery probe refuses it unless `CERTMATE_PROBE_ALLOW_PRIVATE` says
    otherwise, which `environment` sets. With a server there, the walk records what a
    probe answers when it reaches a certificate, not only when it reaches nothing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        ca, ca_key = make_cert('Walk Test CA', is_ca=True)
        leaf, key = make_cert('localhost', san_dns=['localhost'], san_ip=['127.0.0.1'],
                              issuer=ca, issuer_key=ca_key)
        crt, keyfile = Path(tmp) / 'server.crt', Path(tmp) / 'server.key'
        crt.write_bytes(pem(leaf) + pem(ca))
        keyfile.write_bytes(key_pem(key))
        server = TLSServer(str(crt), str(keyfile), handler())
        try:
            yield server.port
        finally:
            server.close()


@contextlib.contextmanager
def environment():
    """The process environment the plan runs in, the same under `pytest` and under
    `python tests/contract_support.py write`.

    The snapshot is written by one and checked by the other, so whatever `tests/conftest.py`
    changes for the suite and the answers depend on has to be pinned here, or the file passes
    where it was written and fails everywhere else. Measured: the suite replaces the CAA
    resolver with one that finds no records, so `check-caa` answered `no_policy` in the test
    and `unknown` when the snapshot was written.

      * the discovery probe may connect to the loopback interface (the TLS server of the world);
      * no outbound proxy is inherited, whatever the machine has configured (the same `no_proxy`
        trick as conftest: on macOS an empty environment falls through to System Settings);
      * the CAA check uses its real resolver, which the seal then refuses to let out;
      * the metrics collector has not run.
    """
    from modules.core import caa, metrics
    proxies = {name for name in os.environ if name.lower().endswith('_proxy')}
    # `/api/metrics` reports when the (process-wide) collector last ran: 0, an int, in a fresh
    # process and a float once any test has collected. The plan does not collect, so it pins the
    # state it expects and puts back whatever the process had.
    with mock.patch.dict(os.environ, {'CERTMATE_PROBE_ALLOW_PRIVATE': '1'}), \
            contextlib.ExitStack() as restore:
        restore.callback(setattr, metrics.metrics_collector, 'last_collection',
                         metrics.metrics_collector.last_collection)
        metrics.metrics_collector.last_collection = 0
        for name in proxies:
            del os.environ[name]
        os.environ['no_proxy'] = '*'
        with mock.patch.object(caa, 'resolver_factory', caa._dnspython_resolver):
            yield


ALIAS = 'alias.example.test'
KEYLESS = 'keyless.example.test'
KEYLESS_TOO = 'keyless-too.example.test'


def _metadata(domain, sans=(), **more):
    metadata = {'domain': domain, 'san_domains': list(sans), 'dns_provider': 'cloudflare',
                'challenge_type': 'dns-01', 'created_at': dt.datetime(2026, 9, 1).isoformat(),
                'email': EMAIL, 'staging': True, 'account_id': 'default',
                'ca_provider': 'letsencrypt_staging'}
    metadata.update(more)
    return json.dumps(metadata)


def _record_a_renewal_window(directory):
    """What the nightly sweep keeps after the CA answered with a window (ARI, #962), built by the
    same functions: without it `renewal_info` is only ever `null` in the walk, and its fields are
    compared with nothing."""
    from cryptography import x509

    from modules.core import ari
    from modules.core.certificates import RENEWAL_INFO_FILE

    cert = x509.load_pem_x509_certificate((directory / 'cert.pem').read_bytes())
    now = dt.datetime(2026, 9, 27, 2, 0, 4)
    window = {'suggestedWindow': {'start': '2026-11-02T17:18:36Z', 'end': '2026-11-04T12:29:25Z'},
              'explanationURL': 'https://letsencrypt.org/docs/'}
    record = ari.observation(ari.certificate_id(cert), ari.STATUS_WINDOW, window, now)
    (directory / RENEWAL_INFO_FILE).write_text(json.dumps(record), encoding='utf-8')


def seed(container, port):
    """Certificates on disk the way an issuance leaves them, an inventory with two certificates
    nobody issued, a key from setup mode, and settings that allow another issuance.

    The metadata is what `create_certificate` writes, so the walk's reads (list, detail,
    download, deployment status) are answers about certificates shaped like the ones production
    holds, not about a fixture the code never meets.
    """
    from modules.core.auth import SETUP_USERNAME
    from modules.core.cert_probe import parse_certificate

    cert_dir = Path(container.cert_dir)
    write_certificate(cert_dir / DOMAIN, DOMAIN, [SAN])
    # Issued with an ACME profile (#395), as create_certificate records it.
    (cert_dir / DOMAIN / 'metadata.json').write_text(
        _metadata(DOMAIN, [SAN], acme_profile='tlsserver'), encoding='utf-8')
    _record_a_renewal_window(cert_dir / DOMAIN)
    # A certificate restored from a share-safe backup: everything but its private key.
    # Two of them, so that a reissue limited to one leaves one to do (`remaining`, `next_step`).
    for name in (KEYLESS, KEYLESS_TOO):
        write_certificate(cert_dir / name, name)
        (cert_dir / name / 'privkey.pem').unlink()
        archive = cert_dir / name / 'archive' / name            # the lineage keeps its certificates, not its keys
        archive.mkdir(parents=True)
        (archive / 'cert1.pem').write_bytes((cert_dir / name / 'cert.pem').read_bytes())
        (cert_dir / name / 'metadata.json').write_text(_metadata(name), encoding='utf-8')
    write_certificate(cert_dir / ALIAS, ALIAS)
    (cert_dir / ALIAS / 'metadata.json').write_text(
        # A profile its CA has since withdrawn: what a renewal records (#395).
        _metadata(ALIAS, domain_alias='alias-zone.example.test', alias_dns_provider='cloudflare',
                  acme_profile='shortlived', acme_profile_withdrawn_at='2026-09-30T03:00:04'),
        encoding='utf-8')

    settings = container.managers['settings']
    current = settings.load_settings()
    current['email'] = EMAIL
    current['domains'] = [{'domain': DOMAIN, 'dns_provider': 'cloudflare'},
                          {'domain': ALIAS, 'dns_provider': 'cloudflare'},
                          {'domain': KEYLESS, 'dns_provider': 'cloudflare'},
                          {'domain': KEYLESS_TOO, 'dns_provider': 'cloudflare'}]
    settings.save_settings(current)

    # Credentials for the DNS provider the seeded certificates name, so that adopting a
    # discovered certificate is possible and the answer is the one an adoption gives.
    assert container.managers['dns'].add_account('default', 'cloudflare', {'api_token': 'w' * 24})

    inventory = container.managers['cert_inventory']
    fingerprints = []
    for host in ('legacy.example.test', 'forgotten.example.test'):
        leaf, _key = make_cert(host, san_dns=[host])
        parsed = parse_certificate(pem(leaf))
        fingerprints.append(inventory.record_certificate(
            parsed['certificate'], source='probed', host=host, port=443))

    ok, made = container.managers['auth'].create_api_key('from-setup', role='viewer',
                                                          created_by=SETUP_USERNAME)
    assert ok, made
    return World(DOMAIN, ALIAS, fingerprints, made['id'], port)
