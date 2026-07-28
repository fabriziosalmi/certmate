"""Certificate discovery — populate the inventory by probing endpoints.

The inventory (:mod:`modules.core.cert_inventory`) is only useful once something
writes to it. The simplest, most controllable source is a list of endpoints the
operator wants watched: this module probes each with the deep TLS probe
(:func:`modules.core.cert_probe.probe_certificate`, SSRF guard included) and
upserts every reachable certificate into the inventory.

Managed domains CertMate already issues for are probed too, so "what we issued"
and "what is actually being served" can be compared — catching, for example, a
renewed certificate that was never deployed (the served fingerprint differs from
the newest issued one).

The sweep is **failure-isolated**: the probe never raises, and each endpoint is
additionally wrapped so one bad target can never abort the run or block any
certificate operation. Every endpoint yields a per-endpoint status record.
"""

import logging

from .cert_probe import probe_certificate, STATUS_OK

logger = logging.getLogger(__name__)

DEFAULT_PORT = 443

# Default ``monitored_endpoints`` settings section. Discovery is opt-in
# (``enabled`` defaults False) so an upgrade never starts probing external
# hosts until an operator turns it on and lists endpoints.
DEFAULT_DISCOVERY_CONFIG = {
    'enabled': False,
    'endpoints': [],
    'allow_private': False,
    'include_managed': True,
}


def parse_endpoint(spec):
    """Parse an endpoint spec into ``(host, port)``.

    Accepts ``host``, ``host:port``, a bare IPv4, and bracketed IPv6
    (``[2001:db8::1]:8443`` or ``[2001:db8::1]``). A bare, unbracketed IPv6
    literal is treated as a host with the default port (its colons are not port
    separators). Raises ``ValueError`` on an empty spec or non-numeric port.
    """
    if spec is None:
        raise ValueError("empty endpoint")
    spec = str(spec).strip()
    if not spec:
        raise ValueError("empty endpoint")

    # Bracketed IPv6, optionally with a port: [addr] or [addr]:port
    if spec.startswith('['):
        close = spec.find(']')
        if close == -1:
            raise ValueError(f"unbalanced brackets in endpoint {spec!r}")
        host = spec[1:close]
        rest = spec[close + 1:]
        if not rest:
            port = DEFAULT_PORT
        elif rest.startswith(':'):
            port = _parse_port(rest[1:], spec)
        else:
            raise ValueError(f"unexpected text after ']' in endpoint {spec!r}")
        if not host:
            raise ValueError(f"empty host in endpoint {spec!r}")
        return host, port

    # Unbracketed: more than one colon => bare IPv6 literal, no port.
    if spec.count(':') > 1:
        return spec, DEFAULT_PORT

    if ':' in spec:
        host, _, port_str = spec.partition(':')
        if not host:
            raise ValueError(f"empty host in endpoint {spec!r}")
        return host, _parse_port(port_str, spec)

    return spec, DEFAULT_PORT


def _parse_port(port_str, spec):
    port_str = port_str.strip()
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"invalid port {port_str!r} in endpoint {spec!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range in endpoint {spec!r}")
    return port


def discover_endpoints(
    endpoints,
    inventory,
    *,
    allow_private=False,
    timeout=None,
    managed_domains=None,
    probe=probe_certificate,
    observed_at=None,
):
    """Probe each endpoint and upsert results into *inventory*.

    *endpoints* is an iterable of specs (``host`` / ``host:port`` / bracketed
    IPv6). *managed_domains* optionally maps a host (case-insensitive) to the
    managed-domain name CertMate issues for; a match records the observation as
    ``source='issued'``, ``managed=True`` and links the managed domain, so a
    served-vs-issued comparison is possible.

    Returns a list of per-endpoint result dicts, one per input spec, each with
    ``endpoint`` (the raw spec), ``host``, ``port``, ``status`` (``ok`` /
    ``blocked`` / ``unreachable`` / ``invalid``), ``fingerprint`` (on ok) and
    ``error`` (otherwise). Never raises: a malformed spec or an unexpected probe
    error is captured as a status, so a scheduled sweep always completes.
    """
    managed = {h.lower(): d for h, d in (managed_domains or {}).items()}
    results = []

    for spec in endpoints:
        try:
            host, port = parse_endpoint(spec)
        except ValueError as e:
            results.append({
                'endpoint': spec, 'host': None, 'port': None,
                'status': 'invalid', 'fingerprint': None, 'error': str(e),
            })
            continue

        managed_domain = managed.get(host.lower())
        is_managed = managed_domain is not None
        try:
            probe_result = probe(
                host, port=port, timeout=timeout, allow_private=allow_private,
            )
        except Exception as e:  # defensive: the probe is meant never to raise
            logger.warning("Discovery probe crashed for %s:%s: %s", host, port, e)
            results.append({
                'endpoint': spec, 'host': host, 'port': port,
                'status': 'unreachable', 'fingerprint': None,
                'error': f'probe error: {e}',
            })
            continue

        entry = {
            'endpoint': spec, 'host': host, 'port': port,
            'status': probe_result.get('status'), 'fingerprint': None,
            'error': probe_result.get('error'),
        }
        if probe_result.get('status') == STATUS_OK:
            fingerprint = inventory.record_probe_result(
                probe_result,
                source='issued' if is_managed else 'probed',
                managed=is_managed,
                managed_domain=managed_domain,
                observed_at=observed_at,
            )
            entry['fingerprint'] = fingerprint
            entry['error'] = None
        results.append(entry)

    return results


def _managed_domain_map(settings):
    """Map probe-able managed domain host -> domain name from settings.

    Skips wildcard domains (``*.example.com`` has no probe-able host of its
    own) and malformed entries. Both keys and values are the domain name, so a
    managed domain probed during a sweep is recorded as issued+managed and
    linked back to its managed entry.
    """
    mapping = {}
    for entry in settings.get('domains', []) or []:
        name = entry.get('domain') if isinstance(entry, dict) else entry
        if not name:
            continue
        name = str(name)
        if name.startswith('*.'):
            continue
        mapping[name] = name
    return mapping


class CertDiscoveryManager:
    """Settings-backed scheduled discovery: probe monitored endpoints into the
    inventory.

    Reads the ``monitored_endpoints`` settings section, probes each configured
    endpoint (plus, by default, the hosts of every managed domain so served vs
    issued can be compared), and upserts results into the inventory. Designed to
    run as a background scheduler job: :meth:`run_discovery` never raises.
    """

    def __init__(self, settings_manager, inventory, probe=probe_certificate):
        self.settings_manager = settings_manager
        self.inventory = inventory
        self._probe = probe

    def get_config(self):
        """Return the effective ``monitored_endpoints`` config (with defaults)."""
        settings = self.settings_manager.load_settings()
        config = dict(DEFAULT_DISCOVERY_CONFIG)
        config.update(settings.get('monitored_endpoints') or {})
        return config

    def save_config(self, config):
        """Validate and persist the ``monitored_endpoints`` config.

        Endpoints are normalised (stripped, blanks dropped) and each is parsed
        to reject a malformed ``host:port`` at save time rather than silently at
        sweep time. Returns the cleaned config.
        """
        endpoints = []
        for raw in (config.get('endpoints') or []):
            spec = str(raw).strip()
            if not spec:
                continue
            parse_endpoint(spec)  # raises ValueError on a bad spec
            endpoints.append(spec)
        clean = {
            'enabled': bool(config.get('enabled', False)),
            'endpoints': endpoints,
            'allow_private': bool(config.get('allow_private', False)),
            'include_managed': bool(config.get('include_managed', True)),
        }
        self.settings_manager.update(
            lambda s: s.__setitem__('monitored_endpoints', clean),
            'monitored_endpoints_save',
        )
        return clean

    def run_discovery(self):
        """Run one discovery sweep. Safe to call from a scheduler thread.

        Returns a summary dict: ``{'skipped': bool, 'results': [...],
        'summary': {...}}``. When discovery is disabled or there is nothing to
        probe, ``skipped`` is True and no probing happens.
        """
        settings = self.settings_manager.load_settings()
        config = dict(DEFAULT_DISCOVERY_CONFIG)
        config.update(settings.get('monitored_endpoints') or {})

        if not config.get('enabled'):
            logger.info("Certificate discovery disabled; skipping sweep.")
            return {'skipped': True, 'reason': 'disabled', 'results': []}

        endpoints = list(config.get('endpoints') or [])
        managed_map = {}
        if config.get('include_managed', True):
            managed_map = _managed_domain_map(settings)
            for host in managed_map:
                if host not in endpoints:
                    endpoints.append(host)

        if not endpoints:
            logger.info("Certificate discovery: no endpoints configured; nothing to do.")
            return {'skipped': True, 'reason': 'no_endpoints', 'results': []}

        results = discover_endpoints(
            endpoints, self.inventory,
            allow_private=bool(config.get('allow_private', False)),
            managed_domains=managed_map,
            probe=self._probe,
        )
        ok = sum(1 for r in results if r['status'] == STATUS_OK)
        logger.info(
            "Certificate discovery sweep: %d endpoints probed, %d ok, "
            "%d certificates in inventory.",
            len(results), ok, self.inventory.count(),
        )
        return {
            'skipped': False,
            'results': results,
            'summary': {
                'total': len(results),
                'ok': ok,
                'inventory_count': self.inventory.count(),
            },
        }
