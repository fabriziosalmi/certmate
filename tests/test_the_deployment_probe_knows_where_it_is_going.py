"""The deployment-status probe connected wherever it was pointed.

`deployment_host` is validated for *shape* when it is set — a bare hostname,
no scheme, no path, no whitespace — and for nothing else. The probe then
opened a socket to it. Driven end to end against an authenticated endpoint,
a certificate whose metadata carried a link-local address had that address
connected to.

**Why the obvious fix is wrong.** `cert_probe.ip_is_blocked` already exists
and refuses loopback, private, link-local, reserved, multicast and anything
non-global. Applying it here would not harden this feature, it would delete
it: the deployment probe exists to check the operator's OWN servers, and
those are routinely `10.0.0.5`, an internal IIS, or loopback behind a reverse
proxy. That policy answers "is this a safe PUBLIC endpoint to probe", which
is the discovery question, not this one.

`deployment_target_refusal` answers this one. It refuses what is never a
server an operator deploys a certificate to — link-local (where the cloud
metadata endpoints live), multicast, and the unspecified address — and
permits loopback and private, because they are the point.

The other half of the value is the resolution. The name is resolved once,
checked, and the connection is made to **that** address, so a name cannot
answer with a permitted address to the check and a different one to the
connect.

And both legs go through one opener now. They had drifted: direct TLS
tunnelled through `HTTPS_PROXY` and SMTP-STARTTLS opened a raw socket, so on
a host behind an outbound proxy an HTTPS probe worked and an SMTP one could
not connect at all — the fix for #326 reached one of the two.
"""
import socket

import pytest

from modules.core.cert_probe import deployment_target_refusal, ip_is_blocked

pytestmark = [pytest.mark.unit]


# --- the policy -----------------------------------------------------------

@pytest.mark.parametrize('address', [
    '169.254.169.254',          # the cloud metadata endpoint
    '169.254.1.1',
    '::ffff:169.254.169.254',   # the same, IPv4-mapped
    'fe80::1',
    '224.0.0.1',                # multicast
    '0.0.0.0',                  # "any", not a host
    '::',
])
def test_what_is_never_a_deployment_target_is_refused(address):
    assert deployment_target_refusal(address) is not None, address


@pytest.mark.parametrize('address', [
    '10.0.0.5',                 # the internal server this feature is FOR
    '192.168.1.10',
    '172.16.0.1',
    '127.0.0.1',                # loopback behind a reverse proxy
    '::1',
    '100.64.0.1',               # CGNAT / Tailscale — a real deployment target
    '8.8.8.8',
])
def test_what_an_operator_really_deploys_to_is_allowed(address):
    """CONTROL, and the reason this is not `ip_is_blocked`. Every address
    here is refused by the discovery policy and must be permitted by this
    one, or the feature is gone."""
    assert deployment_target_refusal(address) is None, address
    assert ip_is_blocked(address) is not None or address == '8.8.8.8'


def test_the_two_policies_are_deliberately_different():
    """Stated so nobody 'unifies' them later. They answer different
    questions: one is about probing the public internet, one is about
    reaching the operator's own estate."""
    assert deployment_target_refusal('10.0.0.5') is None
    assert ip_is_blocked('10.0.0.5') is not None

    # And they agree where they must.
    for address in ('169.254.169.254', '224.0.0.1'):
        assert deployment_target_refusal(address) is not None
        assert ip_is_blocked(address) is not None


def test_an_unparseable_address_is_refused():
    """Defensive: the caller only feeds it resolved addresses, but a policy
    that returns None on input it does not understand is a policy that fails
    open."""
    assert deployment_target_refusal('not-an-ip') is not None
    assert deployment_target_refusal('') is not None


# --- the probe ------------------------------------------------------------

def test_the_probe_refuses_a_target_that_is_not_one():
    """THE regression, through the probe itself."""
    from modules.api.tls_probe import _probe_tls_certificate

    with pytest.raises(ConnectionError) as excinfo:
        _probe_tls_certificate('169.254.169.254', port=80,
                               protocol='https-tls', timeout=3)

    assert 'not a deployment target' in str(excinfo.value)


def test_the_refusal_looks_like_every_other_failure():
    """It raises ConnectionError, which is what a closed port already raises,
    so the route's existing handler reports it as unreachable with the reason
    — no new shape for a caller to learn."""
    from modules.api.tls_probe import _probe_tls_certificate

    with pytest.raises(ConnectionError):
        _probe_tls_certificate('169.254.169.254', port=80, timeout=3)
    with pytest.raises(ConnectionError):
        _probe_tls_certificate('127.0.0.1', port=9, timeout=2)


def test_an_internal_target_is_still_probed(monkeypatch):
    """CONTROL that matters most: the feature must still work against the
    hosts it exists for. Connecting to a real local listener proves the
    guard lets it through — a refusal would raise before any socket."""
    from modules.api import tls_probe

    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        sock, closer = tls_probe._open_probe_socket('127.0.0.1', port, 3)
        peer = sock.getpeername()
        closer()
    finally:
        listener.close()

    assert peer[0] == '127.0.0.1' and peer[1] == port


def test_the_connection_goes_to_the_address_that_was_checked(monkeypatch):
    """The resolution half. A name is resolved once and connected to that
    address, so it cannot answer differently to the check and to the
    connect."""
    from modules.api import tls_probe

    seen = []

    def _spy(address, timeout=None):
        seen.append(address)
        raise ConnectionRefusedError('no listener, which is fine')

    monkeypatch.setattr(tls_probe.socket, 'create_connection', _spy)
    with pytest.raises(ConnectionRefusedError):
        tls_probe._open_probe_socket('localhost', 443, 2)

    assert seen, 'nothing connected — this test is reading nothing'
    host, _port = seen[0]
    assert host in ('127.0.0.1', '::1'), (
        f'connected to {host!r} rather than a resolved address')


# --- the two legs agree ---------------------------------------------------

def test_both_legs_use_the_one_opener():
    """They had drifted: direct TLS honoured HTTPS_PROXY and SMTP did not, so
    behind an outbound proxy one worked and the other could not connect."""
    import ast
    import inspect

    from modules.api import tls_probe

    for function in (tls_probe._probe_tls_certificate,
                     tls_probe._probe_smtp_starttls):
        source = inspect.getsource(function)
        calls = [ast.unparse(node) for node in ast.walk(ast.parse(source.strip()))
                 if isinstance(node, ast.Call)]
        assert any('_open_probe_socket(' in call for call in calls), (
            f'{function.__name__} opens its own socket again')
        assert not any('socket.create_connection(' in call for call in calls), (
            f'{function.__name__} still connects directly, so it skips both '
            f'the proxy and the guard')


def test_the_opener_still_honours_the_proxy(monkeypatch):
    """CONTROL. With a proxy configured the guard cannot apply — the proxy
    resolves, and there is no address to pin — so the opener must tunnel
    rather than refuse."""
    from modules.api import tls_probe

    tunnelled = []

    class _Conn:
        sock = 'a-socket'

        def __init__(self, host, port, timeout=None):
            tunnelled.append((host, port))

        def set_tunnel(self, host, port, headers=None):
            tunnelled.append(('tunnel', host, port))

        def connect(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(tls_probe, '_https_proxy_for',
                        lambda host: ('proxy.internal', 3128, {}))
    monkeypatch.setattr(tls_probe.http.client, 'HTTPConnection', _Conn)

    sock, closer = tls_probe._open_probe_socket('169.254.169.254', 443, 2)
    closer()

    assert sock == 'a-socket'
    assert ('proxy.internal', 3128) in tunnelled
