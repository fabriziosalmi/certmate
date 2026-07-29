"""Certificate Transparency log monitoring (crt.sh) as an inventory source.

Endpoint probing (:mod:`modules.core.cert_discovery`) only finds certificates on
hosts you already know about. Certificates issued for your domains that you did
*not* register — shadow or forgotten issuance — never appear on a monitored
endpoint, so they stay invisible. Certificate Transparency logs make them
visible: every publicly-trusted certificate is logged, and crt.sh indexes them.

This module polls crt.sh for the configured (and, by default, managed) domains
and adds newly-seen certificates to the inventory with ``source='ct-log'``,
flagged unmanaged. A certificate that appears in CT but is not managed by
CertMate is exactly the shadow-issuance signal an operator wants to see.

Two practical constraints shape the design:

* **crt.sh's JSON gives an issuer + serial, not the SHA-256 fingerprint** the
  inventory is keyed by. Rather than fetch every historical certificate's DER
  (hundreds of requests per domain), the poll deduplicates by *serial* against
  the inventory first — a real certificate's serial is effectively unique — and
  only fetches the DER (to compute the true fingerprint and full metadata) for
  certificates it has never seen. Known certs cost zero extra requests.
* **Polling must be rate-limited and failure-isolated.** Requests are spaced by
  a minimum interval; only currently-valid certificates are considered; the
  number of new certs ingested per run is capped (and any truncation is
  logged, never silent); and every per-domain / per-certificate error is caught
  so one bad response can never abort the poll or block certificate operations.
"""

import json
import logging
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .cert_probe import parse_certificate

logger = logging.getLogger(__name__)

CRTSH_BASE = 'https://crt.sh/'
_USER_AGENT = 'CertMate-CT-Monitor'

# Default ``ct_monitoring`` settings section. Opt-in, like endpoint discovery.
DEFAULT_CT_CONFIG = {
    'enabled': False,
    'domains': [],
    'include_managed': True,
    'only_valid': True,          # ignore already-expired CT entries
    'max_new_per_run': 100,      # cap DER fetches / inserts per poll
    'min_request_interval': 2.0,  # seconds between crt.sh requests
}


class CrtShError(Exception):
    """A crt.sh request failed (network, HTTP, or malformed response)."""


class CrtShClient:
    """A minimal, rate-limited crt.sh client.

    Only ever talks to the fixed crt.sh host (URLs are built here), so there is
    no SSRF surface. Requests are spaced by *min_interval* seconds; pass a
    custom *sleeper*/*clock* in tests to avoid real sleeps.
    """

    def __init__(self, timeout=15.0, min_interval=2.0, sleeper=None, clock=None):
        self.timeout = timeout
        self.min_interval = min_interval
        self._sleep = sleeper
        self._clock = clock
        self._last_request = None

    def _throttle(self):
        if not self.min_interval or self._clock is None or self._sleep is None:
            return
        if self._last_request is not None:
            elapsed = self._clock() - self._last_request
            wait = self.min_interval - elapsed
            if wait > 0:
                self._sleep(wait)
        self._last_request = self._clock()

    def _get(self, url):
        self._throttle()
        req = urllib.request.Request(url, headers={'User-Agent': _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                return resp.read()
        except Exception as e:  # urllib raises a zoo of errors; normalise them
            raise CrtShError(f"crt.sh request failed for {url}: {e}") from e

    def search(self, domain):
        """Return the crt.sh JSON entries for *domain* (a list of dicts)."""
        query = urllib.parse.urlencode({'q': domain, 'output': 'json'})
        raw = self._get(f"{CRTSH_BASE}?{query}")
        try:
            data = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as e:
            raise CrtShError(f"crt.sh returned non-JSON for {domain!r}: {e}") from e
        return data if isinstance(data, list) else []

    def fetch_certificate(self, crtsh_id):
        """Return the DER bytes of the crt.sh certificate with id *crtsh_id*."""
        query = urllib.parse.urlencode({'d': crtsh_id})
        return self._get(f"{CRTSH_BASE}?{query}")


def _serial_to_decimal(serial_hex):
    """Convert a crt.sh hex serial to the decimal string the inventory stores.

    Returns None if the serial is missing/unparseable, so the caller can fall
    back to fetching the DER rather than dedup on a bad key.
    """
    if not serial_hex:
        return None
    try:
        return str(int(str(serial_hex).strip(), 16))
    except ValueError:
        return None


def _is_currently_valid(entry, now):
    """True if the crt.sh entry's not_after is in the future (or unparseable).

    crt.sh usually emits a naive timestamp, but a tz-aware/``Z``-suffixed value
    would otherwise make ``fromisoformat`` return an aware datetime and blow up
    the comparison against the naive ``now`` — so normalise to naive UTC and
    treat anything unparseable as "keep it" rather than raising.
    """
    not_after = entry.get('not_after')
    if not not_after:
        return True
    text = str(not_after).strip()
    if text.endswith('Z'):
        text = text[:-1]
    try:
        parsed = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return True
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed >= now


def _managed_domains(settings):
    """Non-wildcard managed domain names from settings['domains']."""
    out = []
    for entry in settings.get('domains', []) or []:
        name = entry.get('domain') if isinstance(entry, dict) else entry
        if name and not str(name).startswith('*.'):
            out.append(str(name))
    return out


class CTMonitorManager:
    """Settings-backed CT-log polling that feeds the inventory."""

    def __init__(self, settings_manager, inventory, client=None):
        self.settings_manager = settings_manager
        self.inventory = inventory
        self._client = client  # lazily built from config on first poll if None

    def get_config(self):
        settings = self.settings_manager.load_settings()
        config = dict(DEFAULT_CT_CONFIG)
        config.update(settings.get('ct_monitoring') or {})
        return config

    def save_config(self, config):
        """Validate and persist the ``ct_monitoring`` config. Returns it cleaned."""
        domains = []
        for raw in (config.get('domains') or []):
            name = str(raw).strip().lower()
            if name:
                domains.append(name)
        clean = {
            'enabled': bool(config.get('enabled', False)),
            'domains': domains,
            'include_managed': bool(config.get('include_managed', True)),
            'only_valid': bool(config.get('only_valid', True)),
            'max_new_per_run': max(0, int(config.get('max_new_per_run', 100))),
            'min_request_interval': max(
                0.0, float(config.get('min_request_interval', 2.0))
            ),
        }
        self.settings_manager.update(
            lambda s: s.__setitem__('ct_monitoring', clean),
            'ct_monitoring_save',
        )
        return clean

    def _resolve_client(self, config):
        if self._client is not None:
            return self._client
        import time
        return CrtShClient(
            min_interval=config.get('min_request_interval', 2.0),
            sleeper=time.sleep, clock=time.monotonic,
        )

    def run_poll(self, now=None):
        """Poll crt.sh for the configured/managed domains. Never raises.

        Returns a summary dict with counts of new / known certs, per-domain
        errors, and whether the per-run cap truncated ingestion.
        """
        settings = self.settings_manager.load_settings()
        config = dict(DEFAULT_CT_CONFIG)
        config.update(settings.get('ct_monitoring') or {})

        if not config.get('enabled'):
            logger.info("CT-log monitoring disabled; skipping poll.")
            return {'skipped': True, 'reason': 'disabled'}

        domains = list(dict.fromkeys(
            [d.strip().lower() for d in (config.get('domains') or []) if d.strip()]
            + (_managed_domains(settings) if config.get('include_managed', True) else [])
        ))
        if not domains:
            logger.info("CT-log monitoring: no domains configured; nothing to do.")
            return {'skipped': True, 'reason': 'no_domains'}

        now = now or datetime.utcnow()
        client = self._resolve_client(config)
        only_valid = config.get('only_valid', True)
        # Coerce defensively: config comes from raw settings, which a hand-edit
        # could leave non-numeric.
        try:
            cap = int(config.get('max_new_per_run', 100))
        except (TypeError, ValueError):
            cap = 100

        new_count = known_count = 0
        errors = []
        truncated = False

        for domain in domains:
            try:
                entries = client.search(domain)
            except CrtShError as e:
                logger.warning("CT-log poll failed for %s: %s", domain, e)
                errors.append({'domain': domain, 'error': str(e)})
                continue

            for entry in entries:
                # Per-entry isolation: a malformed entry (non-dict, bad date,
                # inventory hiccup) must never abort the poll and strand every
                # remaining domain.
                try:
                    if not isinstance(entry, dict):
                        continue
                    if only_valid and not _is_currently_valid(entry, now):
                        continue
                    serial = _serial_to_decimal(entry.get('serial_number'))
                    if serial and self.inventory.find_by_serial(serial):
                        known_count += 1
                        continue
                    # Unknown certificate: fetch its DER for the true fingerprint.
                    if new_count >= cap:
                        truncated = True
                        continue
                    if self._ingest_new(client, entry, now):
                        new_count += 1
                except Exception as e:
                    logger.warning("CT-log: skipping a bad entry for %s: %s", domain, e)
                    errors.append({'domain': domain, 'error': f'entry error: {e}'})

            if truncated:
                logger.warning(
                    "CT-log poll hit the per-run cap of %d new certificates; "
                    "remaining new certs will be picked up on the next run.", cap,
                )
                break

        logger.info(
            "CT-log poll: %d domains, %d new, %d already known, %d errors.",
            len(domains), new_count, known_count, len(errors),
        )
        return {
            'skipped': False,
            'domains': len(domains),
            'new': new_count,
            'known': known_count,
            'errors': errors,
            'truncated': truncated,
        }

    def _ingest_new(self, client, entry, now):
        """Fetch + parse + record one new CT certificate. Returns True on success.

        Failure-isolated: any fetch/parse error is logged and swallowed so the
        poll continues.
        """
        crtsh_id = entry.get('id')
        if crtsh_id is None:
            return False
        try:
            der = client.fetch_certificate(crtsh_id)
            parsed = parse_certificate(der)
            fingerprint = self.inventory.record_certificate(
                parsed['certificate'], source='ct-log', managed=False,
                observed_at=now.replace(microsecond=0).isoformat() + 'Z',
            )
        except (CrtShError, ValueError) as e:
            logger.warning("CT-log: could not ingest crt.sh id %s: %s", crtsh_id, e)
            return False
        return fingerprint is not None
