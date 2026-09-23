"""Does this host still accept TLS 1.0 or 1.1?

Every other check CertMate makes about a live host reads what the host chose
to send. This one asks a question the host would rather not be asked: offer it
a deprecated protocol version and see whether it agrees.

RFC 8996 deprecated TLS 1.0 and 1.1 in March 2021 — MUST NOT be used — and
PCI DSS had required 1.0 gone since 2018. A server that still accepts them is
usually not doing it on purpose; it is a load balancer nobody re-read, or a
vhost that never picked up the profile the others got. Nothing in CertMate
could see it: both its probes set ``minimum_version = TLSv1_2``, so they
report what was negotiated and never what the server would have agreed to
further down.

**The trap this module is built around.** A probe for old TLS is easy to write
so that it can never find anything. Modern OpenSSL builds refuse to *offer*
TLS 1.0/1.1 — the distribution's ``openssl.cnf`` raises ``MinProtocol``, or
the security level excludes every cipher those versions can use — and then
every handshake fails locally, before a byte leaves the machine, and a probe
that reads "handshake failed" as "the server said no" reports a clean estate
having asked nothing. That is the same defect as a blocklist that reads a
refusal as "not listed", and it is the reason for :func:`can_offer`: the
runtime is asked, in memory and without a network, whether it can produce a
ClientHello for that version at all. If it cannot, the answer is ``unknown``.

So a verdict of "refuses old TLS" is only ever reached when this process could
demonstrably make the offer *and* the host declined it.
"""

import logging
import socket
import ssl

# One direction only: this module knows the vocabulary of answers, and
# domain_health imports this one when it needs the check. The reverse import
# is lazy there, so neither file has to be loaded to read the other.
from .domain_health import FAILING, OK, UNKNOWN, _result

logger = logging.getLogger(__name__)

# The versions RFC 8996 says MUST NOT be used. Named rather than referenced
# directly because `ssl.TLSVersion.TLSv1` is deprecated and touching the
# attribute warns; it is resolved through getattr where it is needed.
WEAK_VERSIONS = ('TLSv1', 'TLSv1_1')
VERSION_LABELS = {'TLSv1': 'TLS 1.0', 'TLSv1_1': 'TLS 1.1'}
# What `SSLSocket.version()` returns for each, so an acceptance can be checked
# against the version actually negotiated rather than inferred from the fact
# that a handshake completed. Without this, a context that failed to pin its
# maximum would negotiate TLS 1.3 with a healthy host and report it as
# accepting TLS 1.0 — a finding against every correctly configured server.
NEGOTIATED_NAMES = {'TLSv1': 'TLSv1', 'TLSv1_1': 'TLSv1.1'}

# Old versions cannot use the ciphers a modern security level allows, so the
# offer has to be made at level 0. This widens only what *we* are willing to
# propose; it changes nothing about what the server may accept, and no data is
# ever exchanged over the connection.
LEGACY_CIPHERS = 'ALL:@SECLEVEL=0'

DEFAULT_TIMEOUT_SECONDS = 6.0

ACCEPTED = 'accepted'
REFUSED = 'refused'
UNAVAILABLE = 'unavailable'


def _context(version_name):
    """A client context pinned to exactly one old version.

    Raises ``ssl.SSLError``/``ValueError``/``AttributeError`` when this build
    cannot be configured that way — which is the case worth detecting.
    """
    version = getattr(ssl.TLSVersion, version_name)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The certificate is beside the point: the question is which protocol
    # version the server agrees to speak, and an expired or self-signed
    # certificate does not make an accepted TLS 1.0 handshake acceptable.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version
    context.set_ciphers(LEGACY_CIPHERS)
    return context


def can_offer(version_name):
    """Can this process put a ClientHello for *version_name* on the wire?

    Answered in memory, against no server: the handshake is driven through a
    pair of BIOs until OpenSSL either writes the ClientHello and asks for a
    reply, or refuses. A build that will not make the offer produces no bytes,
    and every "the server refused" this module could otherwise report would be
    this machine refusing instead.
    """
    try:
        context = _context(version_name)
    except (ssl.SSLError, ValueError, AttributeError, TypeError) as e:
        logger.info("This build cannot be configured for %s: %s", version_name, e)
        return False

    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    try:
        handshake = context.wrap_bio(incoming, outgoing, server_hostname='example.invalid')
        try:
            handshake.do_handshake()
        except ssl.SSLWantReadError:
            pass  # expected: the ClientHello is written and a reply awaited
    except (ssl.SSLError, ValueError, OSError) as e:
        logger.info("This build will not offer %s: %s", version_name,
                    getattr(e, 'reason', None) or e)
        return False
    return bool(outgoing.read())


def probe(host, version_name, *, timeout=DEFAULT_TIMEOUT_SECONDS,
          allow_private=False, port=443):
    """Offer *version_name* to *host*. ``accepted`` / ``refused`` / ``unavailable``.

    ``refused`` is only returned once the TCP connection is established: a
    server that answers the offer with an alert, and one that simply resets
    the connection, are both declining, but a connection that never opened has
    declined nothing.
    """
    from .cert_probe import _resolve_and_guard

    try:
        context = _context(version_name)
    except (ssl.SSLError, ValueError, AttributeError, TypeError):
        return UNAVAILABLE

    family, connect_ip, reason = _resolve_and_guard(host, port, allow_private)
    if reason is not None:
        logger.info("Weak-TLS probe skipped for %s: %s", host, reason)
        return UNAVAILABLE

    try:
        raw = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        return UNAVAILABLE
    try:
        raw.settimeout(timeout)
        try:
            raw.connect((connect_ip, port))
        except OSError as e:
            logger.info("Weak-TLS probe could not reach %s: %s", host, e.__class__.__name__)
            return UNAVAILABLE
        # Past this point the host is there and answering, so anything other
        # than a completed handshake is the host declining the version.
        try:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                negotiated = tls.version()
                if negotiated != NEGOTIATED_NAMES[version_name]:
                    # A handshake completed, but not at the version offered.
                    # Whatever happened, the host did not agree to this one.
                    logger.info("Weak-TLS probe for %s offered %s and negotiated %s",
                                host, version_name, negotiated)
                    return REFUSED
                return ACCEPTED
        except (ssl.SSLError, OSError, ValueError, TypeError, UnicodeError):
            return REFUSED
    finally:
        try:
            raw.close()
        except OSError:
            pass


def check(host, *, prober=None, capability=None, timeout=DEFAULT_TIMEOUT_SECONDS,
          allow_private=False):
    """What *host* says about TLS 1.0 and 1.1.

    *capability* is an optional dict shared across a sweep: whether this build
    can make the offer is a fact about the runtime, identical for every host,
    and it costs a handshake attempt to establish.
    """
    capability = capability if capability is not None else {}
    prober = prober or (lambda h, v: probe(h, v, timeout=timeout,
                                           allow_private=allow_private))

    accepted, refused, unasked = [], [], []
    for version_name in WEAK_VERSIONS:
        label = VERSION_LABELS[version_name]
        if version_name not in capability:
            capability[version_name] = can_offer(version_name)
        if not capability[version_name]:
            unasked.append(f'{label}: this CertMate build cannot offer it, so the '
                           f'host was never asked')
            continue
        verdict = prober(host, version_name)
        if verdict == ACCEPTED:
            accepted.append(label)
        elif verdict == REFUSED:
            refused.append(label)
        else:
            unasked.append(f'{label}: the host could not be reached')

    if accepted:
        return _result(FAILING,
                       f'the host still accepts {" and ".join(accepted)}, deprecated '
                       f'by RFC 8996 since 2021',
                       accepted=accepted, refused=refused, unasked=unasked)
    if not refused:
        # Nothing was established. Saying "refuses old TLS" here would be this
        # machine's silence reported as the host's answer.
        return _result(UNKNOWN, '; '.join(unasked) or 'the host was not asked',
                       accepted=[], refused=[], unasked=unasked)
    if unasked:
        return _result(OK, f'refuses {" and ".join(refused)}, and '
                           f'{len(unasked)} version(s) could not be asked',
                       accepted=[], refused=refused, unasked=unasked)
    return _result(OK, f'refuses {" and ".join(refused)}',
                   accepted=[], refused=refused, unasked=[])
