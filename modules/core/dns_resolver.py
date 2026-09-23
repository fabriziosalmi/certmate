"""Which nameservers CertMate asks, when the system's are the wrong ones.

Two checks in CertMate resolve names themselves rather than through the
operating system: the CAA lookup before an issuance, and the name-level checks
in ``domain_health``. Both used ``dns.resolver.Resolver()``, which reads
``/etc/resolv.conf`` — in a container, usually the engine's stub forwarding to
whatever the host uses.

That is the wrong resolver for one of them, and the documentation said so
without offering a way to change it. The large DNSBLs refuse queries that
arrive through a public resolver: Spamhaus answers ``127.255.255.254``, which
CertMate reports as `unknown`, and the advice attached to that answer was
"point CertMate at a resolver of your own" — which an operator could only do
by changing the host's or the container's DNS for every process on it. This
module is that advice made actionable.

**Literal addresses only.** A nameserver named by hostname has to be resolved
by something, and the only thing available is the resolver being replaced. A
hostname here would either quietly depend on the resolver the operator is
trying to stop using, or fail in a way that looks like the new resolver being
broken. Both are worse than refusing it.

A port may follow — ``10.0.0.53:5353``, or ``[2001:db8::1]:5353`` — because a
resolver on a non-standard port is a real deployment (an unbound beside the
container) and because it is the only way to prove this setting works without
a network: a test can stand up a responder on a free port and check that the
answer came from *it*. On a network that transparently intercepts port 53 —
which is where this was written — pointing at an unroutable address does not
fail, so "the lookup did not answer" proves nothing at all.

Empty means the system resolver, which is what every existing instance has and
keeps.
"""

import ipaddress

DEFAULT_TIMEOUT_SECONDS = 5.0


def split_address(entry):
    """``"1.2.3.4"`` -> ``('1.2.3.4', None)``; ``"1.2.3.4:5353"`` ->
    ``('1.2.3.4', 5353)``; ``"[2001:db8::1]:5353"`` likewise. Raises ValueError.

    The brackets are required for an IPv6 address with a port, for the reason
    they exist in URLs: without them the last colon is ambiguous.
    """
    text = str(entry).strip()
    port = None
    if text.startswith('['):
        host, _, rest = text[1:].partition(']')
        if not _:
            raise ValueError(f'{text!r} opens a bracket it never closes')
        if rest:
            if not rest.startswith(':'):
                raise ValueError(f'{text!r} has something after the address '
                                 f'that is not a port')
            port = rest[1:]
    elif text.count(':') == 1:
        host, _, port = text.partition(':')
    else:
        host = text  # bare IPv4, or a bare IPv6 with several colons

    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(
            f'{host!r} is not an IP address. A nameserver has to be given by '
            f'address: resolving its hostname would need the resolver you are '
            f'replacing.'
        ) from None

    if port is None:
        return host, None
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f'{port!r} is not a port number')
    return host, int(port)


def parse_nameservers(value):
    """Validate a list of nameserver addresses. Raises ValueError.

    Returns the cleaned list, de-duplicated, order preserved — a resolver
    tries them in order, so the order is the operator's preference and is not
    sorted away.
    """
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise ValueError('nameservers must be a list of IP addresses')
    cleaned = []
    for raw in value:
        entry = str(raw).strip()
        if not entry:
            continue
        host, port = split_address(entry)
        normalised = entry if port is None else f'{_bracket(host)}:{port}'
        if normalised not in cleaned:
            cleaned.append(normalised)
    return cleaned


def _bracket(host):
    """An IPv6 address needs brackets before a port; IPv4 does not."""
    return f'[{host}]' if ipaddress.ip_address(host).version == 6 else host


ENV_VAR = 'CERTMATE_DNS_RESOLVERS'


def env_nameservers(environ=None):
    """``CERTMATE_DNS_RESOLVERS``, comma-separated, or [].

    There for the deployments where this problem actually lives: a container
    whose resolver is the engine's stub, configured by whoever wrote the
    compose file rather than by whoever uses the web interface. Never raises,
    for the same reason as below — a bad value in the environment must not
    stop an instance from starting.
    """
    import os

    raw = (environ if environ is not None else os.environ).get(ENV_VAR, '')
    try:
        return parse_nameservers([p for p in raw.split(',') if p.strip()])
    except ValueError:
        return []


def configured_nameservers(settings, environ=None):
    """The nameservers an instance is configured with, or [].

    The stored setting wins when there is one, and the environment is the
    default beneath it. That way round because the setting is the one an
    operator can see and change in the interface: if the environment
    overrode it, saving a resolver would appear to work and change nothing,
    which is the worse of the two surprises.

    Never raises: a settings file that somehow holds an invalid entry falls
    back rather than stopping every check that resolves a name. Saving an
    invalid one is refused up front, which is where the operator finds out.
    """
    section = (settings or {}).get('dns_resolver') or {}
    try:
        stored = parse_nameservers(section.get('nameservers'))
    except ValueError:
        stored = []
    return stored or env_nameservers(environ)


def build(timeout=DEFAULT_TIMEOUT_SECONDS, nameservers=None):
    """A dnspython resolver, pointed at *nameservers* when there are any.

    With none, this is ``dns.resolver.Resolver()`` — the system's — so an
    instance that configures nothing behaves exactly as before.
    """
    import dns.resolver

    import dns.nameserver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    if nameservers:
        servers = []
        for entry in nameservers:
            host, port = split_address(entry)
            servers.append(host if port is None
                           else dns.nameserver.Do53Nameserver(host, port))
        # Assigning rather than appending: the point is to stop using the
        # ones from resolv.conf, and leaving them in place would let a query
        # the chosen resolver refuses be answered by the one it replaced —
        # silently, and differently each run.
        resolver.nameservers = servers
    return resolver
