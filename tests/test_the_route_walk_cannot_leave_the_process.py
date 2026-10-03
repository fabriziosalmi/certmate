"""The world the route walk runs in: what it refuses, what it stands in for, what it seeds.

The walk calls every route of the API on the real application (`tests/contract_routes.py`).
Called for real, some of those routes would issue a certificate with certbot, query a DNS server,
open a connection to a host the caller names, or run a program. That is what
`tests/contract_world.py` prevents, and a walk that could reach the world would be a test that
sometimes issues a certificate. So the prevention is tested on its own, and each clause has the
case that would let it through:

  * a connection to anything but the loopback interface is refused, by name and by address;
  * a DNS query is refused, through the resolver and through `getaddrinfo`;
  * no program is launched by `subprocess` or by `os`;
  * what was refused is recorded;
  * and all of it is undone on the way out, including when the code under it raises.

The stand-in for certbot writes what certbot writes, which is what the code after it depends on.
"""
import os
import socket
import subprocess
import sys
import threading

import pytest

from tests import contract_support as support
from tests import contract_world as world

pytestmark = [pytest.mark.unit]

OUTSIDE = '203.0.113.7'      # TEST-NET-3: never routed, and nothing is sent to it anyway


# --- what the seal refuses ---------------------------------------------------

def test_a_connection_beyond_the_loopback_interface_is_refused_and_recorded():
    with world.sealed() as seal:
        with pytest.raises(OSError, match='refused by the walk'):
            socket.create_connection((OUTSIDE, 9), timeout=1)
        sock = socket.socket()
        try:
            assert sock.connect_ex((OUTSIDE, 9)) == 111      # ECONNREFUSED, and no packet
        finally:
            sock.close()
    assert seal.attempts == [f'connect {OUTSIDE}', f'connect {OUTSIDE}']


def test_a_name_is_not_resolved_and_the_failure_is_the_one_an_offline_host_gives():
    with world.sealed() as seal:
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo('example.org', 443)
        assert socket.getaddrinfo('localhost', 80), 'the loopback name has to keep resolving'
    assert seal.attempts == ['resolve example.org']


def test_a_dns_query_through_the_resolver_is_refused():
    import dns.resolver
    with world.sealed() as seal:
        with pytest.raises(dns.resolver.NoNameservers):
            dns.resolver.Resolver().resolve('example.org', 'CAA')
    assert seal.attempts == ['dns query example.org.'] or seal.attempts == ['dns query example.org']


# `os.system` and `os.popen` are launched here to be REFUSED: the point is that the seal stops them.
@pytest.mark.parametrize('launch', [
    lambda: subprocess.run([sys.executable, '-c', 'pass'], check=False),
    lambda: subprocess.Popen([sys.executable, '-c', 'pass']),
    lambda: subprocess.check_output([sys.executable, '-c', 'pass']),
    lambda: os.system('exit 0'),
    lambda: os.popen('exit 0'),
], ids=['run', 'Popen', 'check_output', 'os.system', 'os.popen'])
def test_no_program_is_launched(launch):
    with world.sealed() as seal:
        with pytest.raises(world.Escaped):
            launch()
    assert len(seal.attempts) == 1 and seal.attempts[0].startswith('launch ')


def test_the_loopback_interface_stays_open_because_the_walk_serves_its_own_probes():
    with world.serving() as port, world.sealed() as seal:
        with socket.create_connection(('127.0.0.1', port), timeout=5):
            pass
    assert seal.attempts == []


# --- and it is undone ---------------------------------------------------------

def test_everything_the_seal_changed_is_put_back():
    real = (socket.getaddrinfo, socket.socket.connect, subprocess.Popen, os.system)
    with world.sealed():
        assert socket.getaddrinfo is not real[0]
    assert (socket.getaddrinfo, socket.socket.connect, subprocess.Popen, os.system) == real
    assert subprocess.run([sys.executable, '-c', 'pass'], check=False).returncode == 0


def test_it_is_put_back_when_the_code_under_it_raises():
    real = socket.getaddrinfo
    with pytest.raises(RuntimeError):
        with world.sealed():
            raise RuntimeError('the plan failed')
    assert socket.getaddrinfo is real


def test_a_seal_inside_a_seal_leaves_the_outer_one_closed():
    with world.sealed() as outer:
        with world.sealed():
            pass
        with pytest.raises(world.Escaped):
            subprocess.run([sys.executable, '-c', 'pass'], check=False)
    assert len(outer.attempts) == 1


# --- certbot ------------------------------------------------------------------

def _issue(certbot, tmp_path, name='site.example.test', sans=('www.site.example.test',)):
    command = ['certbot', 'certonly', '--cert-name', name, '--config-dir', str(tmp_path), '-d', name]
    for san in sans:
        command += ['-d', san]
    return certbot.run(command)


def test_the_stand_in_writes_what_certbot_writes(tmp_path):
    from cryptography import x509
    certbot = world.Certbot()
    result = _issue(certbot, tmp_path)
    assert result.returncode == 0
    lineage = tmp_path / 'live' / 'site.example.test'
    assert sorted(path.name for path in lineage.iterdir()) == ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']
    leaf = x509.load_pem_x509_certificate((lineage / 'cert.pem').read_bytes())
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert names == ['site.example.test', 'www.site.example.test']
    assert (lineage / 'fullchain.pem').read_bytes().count(b'BEGIN CERTIFICATE') == 2


def test_it_fails_once_when_asked_and_then_succeeds(tmp_path):
    certbot = world.Certbot()
    certbot.fail_with('boom')
    first = _issue(certbot, tmp_path)
    assert (first.returncode, first.stderr) == (1, 'boom')
    assert not (tmp_path / 'live').exists(), 'a failed run left a lineage behind'
    assert _issue(certbot, tmp_path).returncode == 0


def test_it_does_not_run_anything_it_was_given_that_is_not_certbot(tmp_path):
    certbot = world.Certbot()
    result = certbot.run(['sh', '-c', f'touch {tmp_path}/ran'])
    assert result.returncode == 0
    assert not (tmp_path / 'ran').exists()
    assert certbot.commands[-1][0] == 'sh', 'the command is recorded, so a test can see what was asked'


def test_a_held_issuance_waits_for_its_release(tmp_path):
    certbot = world.Certbot()
    gate = certbot.hold_next()
    done = threading.Event()

    def issue():
        _issue(certbot, tmp_path)
        done.set()

    worker = threading.Thread(target=issue, daemon=True)
    worker.start()
    assert not done.wait(0.3), 'the run finished although it was held'
    assert not (tmp_path / 'live').exists()
    gate.set()
    assert done.wait(10)
    assert (tmp_path / 'live' / 'site.example.test' / 'cert.pem').exists()


def test_a_command_that_is_not_an_issuance_is_not_held():
    certbot = world.Certbot()
    certbot.hold_next()
    assert certbot.run(['certbot', '--version']).stdout.startswith('certbot ')


def test_the_executor_the_application_uses_reaches_the_stand_in_and_nothing_else(tmp_path):
    from modules.core.shell import ShellExecutor
    certbot = world.Certbot()
    with world.sealed() as seal, world.certbot_standing_in(certbot):
        result = ShellExecutor().run(['certbot', 'certonly', '--cert-name', 'x.example.test',
                                      '--config-dir', str(tmp_path), '-d', 'x.example.test'])
    assert result.returncode == 0 and (tmp_path / 'live' / 'x.example.test' / 'privkey.pem').exists()
    assert seal.attempts == [], 'the application launched a program of its own'


def test_the_working_directory_is_one_of_its_own_and_is_given_back(tmp_path):
    before = os.getcwd()
    with world.working_directory() as inside:
        assert os.getcwd() == str(inside.resolve()) and inside.resolve() != os.path.realpath(before)
        (inside / 'letsencrypt').mkdir()
    assert os.getcwd() == before and not inside.exists(), 'the directory was kept, or the old one not restored'


def test_the_working_directory_is_given_back_when_the_code_under_it_raises():
    before = os.getcwd()
    with pytest.raises(RuntimeError):
        with world.working_directory():
            raise RuntimeError('the plan failed')
    assert os.getcwd() == before


def test_certbot_records_where_it_was_run_from(tmp_path):
    certbot = world.Certbot()
    with world.working_directory() as inside:
        certbot.run(['certbot', '--version'])
    assert certbot.cwds == [str(inside.resolve())] or certbot.cwds == [str(inside)]


# --- the environment and the seed --------------------------------------------

def test_the_environment_is_pinned_and_restored(monkeypatch):
    from modules.core import caa
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:3128')
    monkeypatch.delenv('no_proxy', raising=False)
    before = caa.resolver_factory
    with world.environment():
        assert 'HTTPS_PROXY' not in os.environ and os.environ['no_proxy'] == '*'
        assert os.environ['CERTMATE_PROBE_ALLOW_PRIVATE'] == '1'
        assert caa.resolver_factory is caa._dnspython_resolver, (
            'the CAA check would answer by whatever the suite replaced it with')
    assert os.environ['HTTPS_PROXY'] == 'http://proxy.invalid:3128' and 'no_proxy' not in os.environ
    assert 'CERTMATE_PROBE_ALLOW_PRIVATE' not in os.environ and caa.resolver_factory is before


@pytest.mark.parametrize('platform_string_cached', [False, True], ids=['both cold', 'only uname cold'])
def test_the_questions_the_application_asks_of_the_machine_are_asked_before_the_seal(
        monkeypatch, platform_string_cached):
    """`platform.uname()` runs `uname -p` once per process. Asked for the first time under the
    seal it fails, and every later ask succeeds from the cache. The platform string has a cache
    of its own, so the two can be in different states."""
    import platform
    platform.platform()
    monkeypatch.setattr(platform, '_uname_cache', None)
    if not platform_string_cached:
        monkeypatch.setattr(platform, '_platform_cache', {})
    world.warm_up()
    with world.sealed() as seal:
        assert platform.platform() and platform.uname().processor is not None
    assert seal.attempts == []


def test_the_metrics_collector_is_pinned_and_given_back():
    from modules.core import metrics
    collector = metrics.metrics_collector
    before = collector.last_collection
    collector.last_collection = 12345.5
    try:
        with world.environment():
            assert collector.last_collection == 0 and isinstance(collector.last_collection, int)
        assert collector.last_collection == 12345.5
    finally:
        collector.last_collection = before


@pytest.fixture(scope='module')
def seeded():
    app, token = support.build_app()
    container = app.extensions['certmate_container']
    with world.sealed(), world.serving() as port:
        seeded = world.seed(container, port)
        client = app.test_client()
        headers = {'Authorization': f'Bearer {token}'}
        listing = client.get('/api/certificates', headers=headers).get_json()
        keys = client.get('/api/keys', headers=headers).get_json()['keys']
        yield seeded, {entry['domain']: entry for entry in listing}, keys, container


def test_the_seed_holds_the_certificates_it_says(seeded):
    _, listing, _, _ = seeded
    assert set(listing) == {world.ALIAS, world.DOMAIN, world.KEYLESS, world.KEYLESS_TOO}
    assert listing[world.DOMAIN]['private_key_state'] == 'present'
    for keyless in (world.KEYLESS, world.KEYLESS_TOO):
        assert listing[keyless]['private_key_state'] == 'missing', (
            f'{keyless} has a key, so a reissue limited to one leaves nothing remaining')
    assert (listing[world.DOMAIN]['renewal_info'] or {}).get('status') == 'window', (
        'the recorded ARI window is not the one the certificate answers with (its cert_id differs)')


def test_the_seed_holds_what_the_inventory_and_the_keys_routes_need(seeded):
    result, _, keys, container = seeded
    assert len(result.discovered) == 2 and all(result.discovered) and len(set(result.discovered)) == 2
    inventory = container.managers['cert_inventory']
    assert all(inventory.get(fingerprint) for fingerprint in result.discovered)
    assert any(key_id == result.setup_key for key_id in keys), 'the setup-mode key is not in the key list'
    assert result.port > 0
