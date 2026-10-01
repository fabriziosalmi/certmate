"""A deploy target that delivers the certificate to an HTTPS endpoint (#218).

A notification webhook ANNOUNCES a renewal: what it reports reaches alerts, mail
and logs, and it never carries the private key. This target DELIVERS one: the
certificate, the chain and, when the template asks for it, the private key, to a
named destination the operator chose. They are different things with different
rules, which is why this is a typed deploy target and not another placeholder of
the notification webhook.

What it holds itself to, each one checked by a test that breaks it:

* **HTTPS only, and always verified** (system store, a supplied CA, or a pinned
  fingerprint). There is no setting that turns verification off.
* **No redirect is followed**, and the address is resolved once and connected to.
  A destination on a private network needs the target's own `allow_internal`; a
  loopback, link-local or metadata address is never a destination.
* **The key is read only when the template names it**, through one of
  `privkey_pkcs8` or `privkey_traditional`. There is deliberately no bare
  `privkey`: two spellings make the choice visible, and a typo cannot silently
  send nothing.
* **Sending the key is a decision about a destination.** The template is what
  makes a target send it, so the operator confirms the HOST it goes to, and the
  server records who and when. If the host changes the confirmation no longer
  applies and the target refuses to send until it is given again.
* **Nothing the receiver says is kept.** A result holds a status and a fixed
  sentence naming the host, never the address, the body or the headers: a
  receiver can echo what it was sent, and the result goes into an audit log that
  cannot be edited.
* **Every delivery that carried the key says so** in the audit log: where it went,
  for which domain, which certificate. Never the key.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import pinned_https
from .key_formats import KeyFormatError, private_key_pkcs8, private_key_traditional
from .notifier import Notifier, WEBHOOK_AUTH_TYPES, render_payload_template

logger = logging.getLogger(__name__)

TARGET_WEBHOOK = 'webhook'

METHODS = ('POST', 'PUT', 'PATCH')
DEFAULT_TIMEOUT, MAX_TIMEOUT = 15, 60
DEFAULT_ATTEMPTS, MAX_ATTEMPTS = 3, 5
MAX_TEMPLATE_BYTES = 64 * 1024
EVENTS = ('created', 'renewed', 'revoked', 'manual')

# A status that describes this attempt and not the request: the same request may
# succeed later. Everything else in the 4xx range says the request is wrong, and
# sending a key again to be told so again helps nobody.
RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})

# The variables a template may use, and where each comes from.
EVENT_VARIABLES = ('event', 'domain', 'timestamp', 'certificate_sha256')
PUBLIC_MATERIAL = {'cert': 'cert.pem', 'fullchain': 'fullchain.pem', 'chain': 'chain.pem'}
KEY_MATERIAL = {'privkey_pkcs8': private_key_pkcs8, 'privkey_traditional': private_key_traditional}
ALLOWED_VARIABLES = frozenset(EVENT_VARIABLES) | frozenset(PUBLIC_MATERIAL) | frozenset(KEY_MATERIAL)

_PLACEHOLDER_RE = re.compile(r'\{\{\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\s*\}\}')
_HOST_RE = re.compile(r'^[A-Za-z0-9.-]+$')

EXAMPLE_CERT = '-----BEGIN CERTIFICATE-----\nEXAMPLE-CERTIFICATE\n-----END CERTIFICATE-----\n'
EXAMPLE_KEY = '-----BEGIN PRIVATE KEY-----\nEXAMPLE-NOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n'


def referenced(template):
    """The variable names a payload template uses."""
    if not isinstance(template, str):
        return set()
    return {m.group(1) for m in _PLACEHOLDER_RE.finditer(template)}


def key_variables(template):
    """The private-key variables a template uses: the ones that make a target send the key."""
    return sorted(referenced(template) & set(KEY_MATERIAL))


def _valid_host(hostname):
    """A DNS name, or an IP literal. `urlparse().hostname` has no brackets, so an IPv6 literal is a bare address."""
    if _HOST_RE.match(hostname):
        return True
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _url_host(url):
    try:
        return (urlparse(url or '').hostname or '').lower()
    except ValueError:
        return ''


def _url_port(url):
    """The port the request goes to: the one in the URL, else 443 (the scheme is https)."""
    try:
        return urlparse(url or '').port or 443
    except ValueError:
        return 443


def _example_variables(event='renewed', domain='example.com'):
    variables = {'event': event, 'domain': domain, 'certificate_sha256': '0' * 64,
                 'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    variables.update({name: EXAMPLE_CERT for name in PUBLIC_MATERIAL})
    variables.update({name: EXAMPLE_KEY for name in KEY_MATERIAL})
    return variables


# --------------------------------------------------------------------------
# Save-time validation and consent
# --------------------------------------------------------------------------

def validate_webhook_target(target):
    """Return ``(True, None)`` or ``(False, reason)`` for a saved webhook target."""
    if not isinstance(target, dict):
        return False, 'target must be an object'
    if not isinstance(target.get('id'), str) or not target['id'].strip():
        return False, 'a webhook target needs an id'
    if not isinstance(target.get('name'), str) or not target['name'].strip():
        return False, 'a webhook target needs a name'
    domains = target.get('domains')
    if (not isinstance(domains, list) or not domains
            or not all(isinstance(d, str) and d.strip() and len(d) <= 253 for d in domains)):
        return False, ('a webhook target needs an explicit list of domains: it sends certificate '
                       'material off the host, so it is never applied to "all domains" by default')
    events = target.get('on_events')
    if events is not None and (not isinstance(events, list) or not set(events) <= set(EVENTS)):
        return False, f'on_events must be a list drawn from {", ".join(EVENTS)}'

    cfg = target.get('config')
    if not isinstance(cfg, dict):
        return False, 'config must be an object'
    url = cfg.get('url')
    try:
        parsed = urlparse(url) if isinstance(url, str) else None
        port = parsed.port if parsed else None
    except ValueError:
        return False, 'url is not a valid URL (is the port a number from 1 to 65535?)'
    if parsed is not None and parsed.scheme == 'http' and parsed.hostname:
        # The case a first user hits: a receiver that listens on plain HTTP by default
        # (n8n does). Say how to get out of it, not only that it is refused.
        return False, ('url must be https://: the request carries certificate material. A receiver '
                       'that answers over plain HTTP (n8n does by default) needs TLS enabled on it '
                       'or in front of it; see docs/deploy-hooks.md, "Receiving it in n8n"')
    if (parsed is None or parsed.scheme != 'https' or not parsed.hostname
            or not _valid_host(parsed.hostname)):
        return False, 'url must be an https:// address with a host: the request carries certificate material'
    if parsed.username or parsed.password:
        return False, 'url must not carry credentials; use the authentication fields'
    if port is not None and not 1 <= port <= 65535:
        return False, 'url has an invalid port'

    if (cfg.get('method') or 'POST').upper() not in METHODS:
        return False, f'method must be one of {", ".join(METHODS)}'
    auth_type = cfg.get('auth_type') or 'none'
    if auth_type not in WEBHOOK_AUTH_TYPES:
        return False, f'auth_type must be one of {", ".join(WEBHOOK_AUTH_TYPES)}'
    auth_error = Notifier._apply_webhook_auth(cfg, {})
    if auth_error:
        return False, auth_error
    for field, low, high in (('timeout', 1, MAX_TIMEOUT), ('attempts', 1, MAX_ATTEMPTS)):
        value = cfg.get(field)
        if value not in (None, '') and (isinstance(value, bool) or not isinstance(value, int)
                                        or not low <= value <= high):
            return False, f'{field} must be a whole number between {low} and {high}'
    if not isinstance(cfg.get('allow_internal', False), bool):
        return False, 'allow_internal must be true or false'
    if cfg.get('ca_cert') and cfg.get('pin_sha256'):
        return False, 'use either ca_cert or pin_sha256, not both: a pin replaces the chain check'
    if cfg.get('pin_sha256'):
        try:
            pinned_https.normalise_pin(cfg['pin_sha256'])
        except pinned_https.UnsafeDestination:
            return False, pinned_https.PIN_FORMAT
    if cfg.get('ca_cert'):
        try:
            x509.load_pem_x509_certificate(str(cfg['ca_cert']).encode())
        except ValueError:
            return False, 'ca_cert is not a PEM certificate'

    template = cfg.get('payload_template')
    if not isinstance(template, str) or not template.strip():
        return False, 'payload_template is required'
    if len(template.encode('utf-8')) > MAX_TEMPLATE_BYTES:
        return False, f'payload_template is larger than {MAX_TEMPLATE_BYTES // 1024} KiB'
    unknown = sorted(referenced(template) - ALLOWED_VARIABLES)
    if unknown:
        hint = ''
        if 'privkey' in unknown:
            hint = ' There is no bare privkey: use privkey_pkcs8 or privkey_traditional.'
        return False, (f'unknown variable(s) in payload_template: {", ".join(unknown)}.{hint} '
                       f'Available: {", ".join(sorted(ALLOWED_VARIABLES))}')
    try:
        render_payload_template(template, _example_variables())
    except ValueError as error:
        # Only where the parser stopped, read as numbers: its own wording is not
        # passed on to a caller.
        cause = error.__context__
        where = (f' (line {int(cause.lineno)}, column {int(cause.colno)})'
                 if isinstance(cause, json.JSONDecodeError) else '')
        return False, f'payload_template does not render to valid JSON with the example values{where}'

    if key_variables(template):
        consent = target.get('delivery_consent')
        host = _url_host(url)
        if not isinstance(consent, dict) or (consent.get('host') or '').lower() != host:
            return False, (f'this target sends the private key to {host}: confirm it by setting '
                           f'acknowledge_key_delivery_to to "{host}"')
    return True, None


def stamp_consent(targets, previous_targets, actor, when=None):
    """Turn a client's acknowledgement into a server-recorded consent, or say why not.

    Returns ``(targets, None)`` or ``(None, reason)``. The consent (`host`, `by`,
    `at`) is written HERE, never read from the request: a client that posted its
    own `delivery_consent` would otherwise be confirming for itself. A consent
    carries over only while the destination host is the one that was confirmed.
    """
    when = when or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    previous = {t.get('id'): t for t in (previous_targets or []) if isinstance(t, dict)}
    out = []
    for target in targets or []:
        if not isinstance(target, dict) or target.get('type') != TARGET_WEBHOOK:
            out.append(target)
            continue
        target = dict(target)
        cfg = dict(target.get('config') or {})
        acknowledgement = cfg.pop('acknowledge_key_delivery_to', None)
        target.pop('delivery_consent', None)
        host = _url_host(cfg.get('url'))
        if key_variables(cfg.get('payload_template')):
            earlier = (previous.get(target.get('id')) or {}).get('delivery_consent') or {}
            if acknowledgement and str(acknowledgement).strip().lower() == host:
                target['delivery_consent'] = {'host': host, 'by': actor, 'at': when}
            elif not acknowledgement and (earlier.get('host') or '').lower() == host and host:
                target['delivery_consent'] = {'host': host, 'by': earlier.get('by'), 'at': earlier.get('at')}
            else:
                return None, (f'target "{target.get("name") or target.get("id")}" sends the private '
                              f'key to {host or "its destination"}: confirm it by setting '
                              f'acknowledge_key_delivery_to to "{host}"')
        target['config'] = cfg
        out.append(target)
    return out, None


# --------------------------------------------------------------------------
# The target
# --------------------------------------------------------------------------

class WebhookTarget:
    """Deliver the certificate, and optionally the key, to an HTTPS endpoint."""

    def __init__(self, target, *, send=None, sleep=None, resolver=None):
        self.target = target or {}
        self.config = self.target.get('config') or {}
        self._send = send or pinned_https.send
        self._sleep = sleep or time.sleep
        self._resolver = resolver

    # -- what it needs ------------------------------------------------------ #

    def _names(self):
        return referenced(self.config.get('payload_template'))

    def required_files(self):
        """The files a delivery reads. The key's is included ONLY when the template names it."""
        files = ['cert.pem']
        for name, filename in PUBLIC_MATERIAL.items():
            if name in self._names() and filename not in files:
                files.append(filename)
        if key_variables(self.config.get('payload_template')):
            files.append('privkey.pem')
        return tuple(files)

    def sends_private_key(self):
        return bool(key_variables(self.config.get('payload_template')))

    # -- building the request ---------------------------------------------- #

    def _variables(self, material, domain, event_type):
        cert_pem = material('cert.pem')
        try:
            leaf = x509.load_pem_x509_certificate(cert_pem)
            fingerprint = hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
        except ValueError:
            fingerprint = hashlib.sha256(cert_pem).hexdigest()
        variables = {'event': event_type, 'domain': domain, 'certificate_sha256': fingerprint,
                     'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
        for name, filename in PUBLIC_MATERIAL.items():
            if name in self._names():
                variables[name] = material(filename).decode('utf-8', 'replace')
        wanted = key_variables(self.config.get('payload_template'))
        if wanted:
            key_pem = material('privkey.pem')
            for name in wanted:
                variables[name] = KEY_MATERIAL[name](key_pem)
        return variables

    def _headers(self, body, event_type, domain, fingerprint):
        headers = {'Content-Type': 'application/json', 'User-Agent': 'CertMate-Deploy/1',
                   'X-CertMate-Event': event_type,
                   # Stable across the retries of one delivery, different for the next
                   # certificate: a receiver can tell a repeat from a new delivery.
                   'Idempotency-Key': hashlib.sha256(
                       f'{self.target.get("id")}|{domain}|{fingerprint}|{event_type}'.encode()).hexdigest()}
        error = Notifier._apply_webhook_auth(self.config, headers)
        if error:
            raise ValueError(error)
        secret = self.config.get('signing_secret')
        if secret:
            stamp = str(int(time.time()))
            signature = hmac.new(secret.encode(), f'{stamp}.'.encode() + body, hashlib.sha256).hexdigest()
            headers['X-CertMate-Signature'] = f't={stamp},v1={signature}'
        return headers

    def _consent_error(self, host):
        if not self.sends_private_key():
            return None
        consent = self.target.get('delivery_consent') or {}
        if (consent.get('host') or '').lower() != host:
            return (f'sending the private key to {host} has not been confirmed for this target; '
                    f'save it again with acknowledge_key_delivery_to')
        return None

    # -- sending ------------------------------------------------------------ #

    def deploy_from(self, material, domain, event_type):
        """Deliver once per attempt, and return the outcome. Never raises for an operational failure."""
        url = self.config.get('url') or ''
        host = _url_host(url)
        outcome = {'success': False, 'status_code': None, 'message': '', 'key_sent_to': None,
                   'certificate_sha256': None, 'attempts': 0}
        refusal = self._consent_error(host)
        if refusal:
            outcome['message'] = refusal
            return outcome
        try:
            variables = self._variables(material, domain, event_type)
            body = render_payload_template(self.config['payload_template'], variables).encode('utf-8')
            outcome['certificate_sha256'] = variables['certificate_sha256']
            headers = self._headers(body, event_type, domain, variables['certificate_sha256'])
        except KeyFormatError as error:
            outcome['message'] = f'the private key cannot be produced in the requested form: {error}'
            return outcome
        except OSError:
            outcome['message'] = 'certificate files unreadable'
            return outcome
        except (ValueError, KeyError, TypeError) as error:
            outcome['message'] = f'the request could not be built: {error}'
            return outcome

        timeout = self.config.get('timeout') or DEFAULT_TIMEOUT
        attempts = self.config.get('attempts') or DEFAULT_ATTEMPTS
        for attempt in range(1, attempts + 1):
            outcome['attempts'] = attempt
            try:
                reply = self._send(
                    url, method=(self.config.get('method') or 'POST').upper(), body=body,
                    headers=headers, timeout=timeout, ca_pem=self.config.get('ca_cert') or None,
                    pin_sha256=self.config.get('pin_sha256') or None,
                    allow_internal=bool(self.config.get('allow_internal')), resolver=self._resolver)
            except pinned_https.UnsafeDestination as error:
                outcome['message'] = f'refused, nothing was sent: {error}'
                return outcome
            except pinned_https.TLSVerificationFailed as error:
                outcome['message'] = f'{host}: {error}; nothing was sent'
                return outcome
            except pinned_https.TransportError as error:
                # The key may or may not have left: a reset after the handshake is
                # indistinguishable from one before it, so it is recorded as sent.
                outcome['key_sent_to'] = host if self.sends_private_key() else None
                outcome['message'] = f'{host}: {error}'
                if attempt < attempts:
                    self._sleep(2 ** (attempt - 1))
                    continue
                return outcome
            outcome['status_code'] = reply.status
            if self.sends_private_key():
                outcome['key_sent_to'] = host
            if reply.redirected:
                outcome['message'] = (f'{host} answered with a redirect (HTTP {reply.status}); '
                                      f'redirects are not followed, so the request was not repeated '
                                      f'anywhere else')
                return outcome
            if 200 <= reply.status < 300:
                outcome['success'] = True
                outcome['message'] = f'Delivered to {host}: HTTP {reply.status}'
                return outcome
            outcome['message'] = f'{host} answered HTTP {reply.status}'
            if reply.status in RETRYABLE_STATUSES and attempt < attempts:
                self._sleep(2 ** (attempt - 1))
                continue
            return outcome
        return outcome

    # -- previewing --------------------------------------------------------- #

    def preview(self, domain='example.com', event_type='renewed'):
        """What would be sent, rendered against an EXAMPLE certificate and key. No network, no file read."""
        cfg = self.config
        variables = _example_variables(event_type, domain)
        body = render_payload_template(cfg['payload_template'], variables)
        headers = {'Content-Type': 'application/json', 'User-Agent': 'CertMate-Deploy/1',
                   'X-CertMate-Event': event_type, 'Idempotency-Key': '<derived per delivery>'}
        probe = {}
        if not Notifier._apply_webhook_auth(cfg, probe):
            headers.update({name: '[masked]' for name in probe})
        if cfg.get('signing_secret'):
            headers['X-CertMate-Signature'] = '[computed per delivery]'
        if cfg.get('pin_sha256'):
            tls = 'pinned fingerprint'
        elif cfg.get('ca_cert'):
            tls = 'the supplied CA'
        else:
            tls = 'the system trust store'
        url = cfg.get('url') or ''
        return {
            'method': (cfg.get('method') or 'POST').upper(),
            'host': _url_host(url),
            'port': _url_port(url),
            'path': (urlparse(url).path or '/') if url else '/',
            'headers': headers,
            'body': body,
            'sends_private_key': self.sends_private_key(),
            'key_variables': key_variables(cfg.get('payload_template')),
            'files_needed': list(self.required_files()),
            'tls_verified_with': tls,
            'allow_internal': bool(cfg.get('allow_internal')),
            'note': 'Rendered with an example certificate and key; nothing was sent and no file was read.',
        }
