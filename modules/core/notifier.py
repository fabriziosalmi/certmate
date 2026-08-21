"""
Notification system for CertMate.
Supports SMTP email and webhook (Slack, Discord, generic) notifications.
"""

import base64
import json
import logging
import os
import re
import smtplib
import hashlib
import hmac
import ipaddress
import socket
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _webhook_url_is_internal(url: str) -> bool:
    """Return True if *url*'s host resolves to a loopback / private / link-local
    / reserved address.

    Used to block SSRF to internal services or the cloud metadata endpoint
    (169.254.169.254) via an admin-supplied webhook URL — including the
    interactive "Test" button, which would otherwise turn CertMate into a
    confused deputy on its own network segment. Checks every resolved address so
    a dual A-record can't smuggle one private IP past the guard. Hosts that do
    not resolve are NOT treated as internal (they aren't a reachable internal
    target — urlopen will just fail), so transient-DNS / placeholder hosts are
    left to the normal request path.
    """
    try:
        host = urlparse(url).hostname
        if not host:
            return False
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False


# --- Generic webhook: method, authentication, payload template (#218) ------ #
#
# A generic webhook used to be "POST this fixed JSON, optionally signed, with
# whatever headers you typed". Slack, PagerDuty, Mattermost, an internal ITSM
# endpoint — each wants its own body shape and its own way of being told who
# is calling. These fields make that declarative config rather than a shell
# hook with curl in it:
#
#   method           POST (default) | PUT | PATCH
#   auth_type        none (default) | bearer | basic | header
#   auth_token       bearer token, or the header value for auth_type=header
#   auth_username    basic auth
#   auth_password    basic auth
#   auth_header      header name for auth_type=header (default X-API-Key)
#   payload_template JSON text with {{placeholders}}; empty = the default body
#   timeout          seconds, 1..60 (default 10)
#   max_retries      total delivery attempts, 1..5 (default 3, as before); 0 is
#                    accepted from older configs and means 1
#
# Every secret-bearing field name matches the settings secret regex (token,
# password), so it is masked on GET and restored on a round-trip save.

WEBHOOK_METHODS = ('POST', 'PUT', 'PATCH')
WEBHOOK_AUTH_TYPES = ('none', 'bearer', 'basic', 'header')
WEBHOOK_DEFAULT_TIMEOUT = 10
WEBHOOK_MAX_TIMEOUT = 60
WEBHOOK_DEFAULT_RETRIES = 3
WEBHOOK_MAX_RETRIES = 5

# What a template may reference. ``details.*`` reaches into the event payload
# (domain, error, hook_name, days_until_expiry, ... whatever the event carries).
TEMPLATE_VARIABLES = (
    ('event', 'event name, e.g. certificate_renewed'),
    ('title', 'human title, e.g. Certificate Renewed'),
    ('message', 'one-line message'),
    ('timestamp', 'ISO-8601 UTC'),
    ('domain', 'the certificate domain (shortcut for details.domain)'),
    ('details', 'the whole event payload as a JSON object'),
    ('details.<field>', 'one field of the event payload, e.g. details.error'),
)

_PLACEHOLDER_RE = re.compile(r'\{\{\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\s*\}\}')


def webhook_template_variables(event, title, message, details=None):
    """The variable set a payload template is rendered against."""
    details = details if isinstance(details, dict) else {}
    return {
        'event': event,
        'title': title,
        'message': message,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'domain': details.get('domain'),
        'details': details,
    }


def _lookup(variables, dotted):
    node = variables
    for part in dotted.split('.'):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _inside_json_string(prefix):
    """True when *prefix* ends inside a JSON string literal — i.e. an odd
    number of unescaped double quotes precede this point."""
    inside = False
    i = 0
    while i < len(prefix):
        ch = prefix[i]
        if ch == '\\' and inside:
            i += 2
            continue
        if ch == '"':
            inside = not inside
        i += 1
    return inside


def render_payload_template(template, variables):
    """Substitute ``{{name}}`` placeholders and return the JSON text.

    A placeholder *inside* a JSON string (``"text": "{{domain}} renewed"``)
    is inserted as an escaped string fragment, so a value carrying quotes,
    newlines or backslashes cannot break out of the string. A placeholder
    *outside* a string (``"days": {{details.days_until_expiry}}``) is
    inserted as a JSON literal — number, bool, object, or a quoted string —
    so the template stays valid JSON either way. Unknown names render as an
    empty fragment inside a string and ``null`` outside it.

    Raises ValueError when the result is not valid JSON: the template is the
    operator's, and a broken one must fail at save/preview time, not only at
    3 a.m. on the first renewal.
    """
    if not isinstance(template, str):
        raise ValueError('payload_template must be a string')

    out = []
    last = 0
    for match in _PLACEHOLDER_RE.finditer(template):
        out.append(template[last:match.start()])
        value = _lookup(variables, match.group(1))
        if _inside_json_string(''.join(out)):
            if value is None:
                fragment = ''
            elif isinstance(value, (dict, list)):
                fragment = json.dumps(json.dumps(value, separators=(',', ':'), default=str))[1:-1]
            else:
                fragment = json.dumps(str(value))[1:-1]
        else:
            # default=str: an event payload may carry a datetime or another
            # object json does not know; a runtime value must never turn a
            # valid template into an exception (review, #580).
            fragment = json.dumps(value, default=str)
        out.append(fragment)
        last = match.end()
    out.append(template[last:])
    rendered = ''.join(out)
    try:
        json.loads(rendered)
    except ValueError as exc:
        raise ValueError(f'payload_template does not render to valid JSON: {exc}')
    return rendered


def _coerce_int(value, default, low, high, name):
    if value in (None, ''):
        return default, None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None, f'{name} must be a whole number'
    if number < low or number > high:
        return None, f'{name} must be between {low} and {high}'
    return number, None


def validate_webhook_config(cfg):
    """Return an error string for a malformed generic-webhook config, else None.

    Only the new fields are judged here (method, auth, template, timeout,
    retries); URL/scheme/SSRF checks stay in the send path, where they
    always were, so a placeholder URL can still be saved and tested later.
    """
    if not isinstance(cfg, dict):
        return 'webhook must be an object'
    if cfg.get('type', 'generic') != 'generic':
        return None
    method = (cfg.get('method') or 'POST').upper()
    if method not in WEBHOOK_METHODS:
        return f"method must be one of {', '.join(WEBHOOK_METHODS)}"
    auth_type = cfg.get('auth_type') or 'none'
    if auth_type not in WEBHOOK_AUTH_TYPES:
        return f"auth_type must be one of {', '.join(WEBHOOK_AUTH_TYPES)}"
    if auth_type == 'bearer' and not cfg.get('auth_token'):
        return 'bearer authentication needs auth_token'
    if auth_type == 'basic' and not (cfg.get('auth_username') and cfg.get('auth_password')):
        return 'basic authentication needs auth_username and auth_password'
    if auth_type == 'header':
        if not cfg.get('auth_token'):
            return 'header authentication needs auth_token (the header value)'
        name = (cfg.get('auth_header') or 'X-API-Key').strip()
        if not re.match(r'^[A-Za-z0-9-]+$', name):
            return 'auth_header is not a valid header name'
    _, err = _coerce_int(cfg.get('timeout'), WEBHOOK_DEFAULT_TIMEOUT, 1, WEBHOOK_MAX_TIMEOUT, 'timeout')
    if err:
        return err
    _, err = _coerce_int(cfg.get('max_retries'), WEBHOOK_DEFAULT_RETRIES, 0, WEBHOOK_MAX_RETRIES, 'max_retries')
    if err:
        return err
    template = cfg.get('payload_template')
    if template:
        try:
            render_payload_template(template, webhook_template_variables(
                'certificate_renewed', 'Certificate Renewed',
                'Certificate Renewed: example.com', {'domain': 'example.com'}))
        except ValueError as exc:
            return str(exc)
    return None


class Notifier:
    """Sends notifications via configured channels."""

    MAX_DELIVERY_LOG_ENTRIES = 1000

    def __init__(self, settings_manager, data_dir: str = 'data'):
        self.settings_manager = settings_manager
        self._delivery_log_path = Path(data_dir) / 'webhook_deliveries.jsonl'

    def _get_config(self) -> dict:
        """Get notification config from settings."""
        settings = self.settings_manager.load_settings()
        return settings.get('notifications', {})

    def notify(self, event: str, title: str, message: str,
               details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send notification to all enabled channels.

        Args:
            event: Event type (certificate_created, certificate_expiring, etc.)
            title: Notification title
            message: Notification body text
            details: Extra structured data

        Returns:
            Dict with channel results
        """
        config = self._get_config()
        if not config.get('enabled', False):
            return {'skipped': 'notifications disabled'}

        events_filter = config.get('events', [])
        if events_filter and event not in events_filter:
            return {'skipped': 'event not in filter'}

        results = {}
        channels = config.get('channels', {})

        # SMTP email
        smtp_cfg = channels.get('smtp', {})
        if smtp_cfg.get('enabled', False):
            results['smtp'] = self._send_email_with_retry(smtp_cfg, event, title, message, details)

        # Webhooks (generic, Slack, Discord)
        for wh in channels.get('webhooks', []):
            if not wh.get('enabled', False):
                continue
            # Per-webhook event filtering
            wh_events = wh.get('events', [])
            if wh_events and event not in wh_events:
                continue
            name = wh.get('name', 'webhook')
            results[name] = self._send_webhook_with_retry(wh, event, title, message, details)

        return results

    def _send_email(self, cfg: dict, subject: str, body: str,
                    details: Optional[dict] = None) -> dict:
        """Send email via SMTP."""
        try:
            host = cfg.get('host', '')
            port = cfg.get('port', 587)
            username = cfg.get('username', '')
            password = cfg.get('password', '')
            from_addr = cfg.get('from_address', username)
            to_addrs = cfg.get('to_addresses', [])

            if not host or not to_addrs:
                return {'error': 'SMTP not fully configured'}

            msg = MIMEMultipart('alternative')
            msg['Subject'] = f'[CertMate] {subject}'
            msg['From'] = from_addr
            msg['To'] = ', '.join(to_addrs)

            # Plain text body
            text_body = body
            if details:
                text_body += '\n\nDetails:\n'
                for k, v in details.items():
                    text_body += f'  {k}: {v}\n'

            msg.attach(MIMEText(text_body, 'plain'))

            # HTML body
            html_body = f'''<div style="font-family:sans-serif;max-width:600px;margin:0 auto">
<h2 style="color:#2563eb">CertMate</h2>
<p>{body}</p>'''
            if details:
                html_body += '<table style="margin-top:12px;border-collapse:collapse">'
                for k, v in details.items():
                    html_body += f'<tr><td style="padding:4px 12px 4px 0;color:#6b7280;font-size:14px">{k}</td><td style="padding:4px 0;font-size:14px">{v}</td></tr>'
                html_body += '</table>'
            html_body += '</div>'
            msg.attach(MIMEText(html_body, 'html'))

            use_tls = cfg.get('use_tls', True)
            server = smtplib.SMTP(host, port, timeout=10)
            try:
                if use_tls:
                    server.starttls()
                if username and password:
                    server.login(username, password)
                server.sendmail(from_addr, to_addrs, msg.as_string())
                logger.info(f"Email notification sent: {subject}")
                return {'success': True}
            finally:
                try:
                    server.quit()
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return {'error': str(e)}

    def _send_email_with_retry(self, cfg: dict, event: str, title: str,
                               message: str, details: Optional[dict] = None,
                               max_retries: int = 3) -> dict:
        """Send SMTP email with the same retry/backoff and delivery-log
        contract as webhooks. Configuration errors are not retried —
        only actual send failures (DNS, connect, auth-flap, 4xx greylisting)
        get the 1s/2s backoff."""
        start_ms = int(time.time() * 1000)
        result = {}
        attempts = 0
        for attempt in range(max_retries):
            attempts = attempt + 1
            result = self._send_email(cfg, title, message, details)
            if result.get('success'):
                break
            if result.get('error') == 'SMTP not fully configured':
                break  # static config problem — retrying cannot help
            if attempt < max_retries - 1:
                delay = 2 ** attempt  # 1s, 2s
                time.sleep(delay)
                logger.debug(f"SMTP retry {attempt + 2}/{max_retries}")

        duration_ms = int(time.time() * 1000) - start_ms
        self._log_delivery(
            {'name': 'smtp', 'type': 'smtp', 'url': cfg.get('host', '')},
            event, result, attempts, duration_ms,
        )
        return result

    def _send_webhook_with_retry(self, cfg: dict, event: str, title: str,
                                message: str, details: Optional[dict] = None,
                                max_retries: Optional[int] = None) -> dict:
        """Send webhook with exponential backoff retry and delivery logging.

        ``max_retries`` is the total number of attempts; the per-webhook
        ``max_retries`` setting (0..5) wins over the default of 3 (#218).
        """
        if max_retries is None:
            max_retries, err = _coerce_int(cfg.get('max_retries'), WEBHOOK_DEFAULT_RETRIES,
                                           0, WEBHOOK_MAX_RETRIES, 'max_retries')
            if err:
                max_retries = WEBHOOK_DEFAULT_RETRIES
        max_retries = max(1, int(max_retries))
        start_ms = int(time.time() * 1000)
        result = {}
        attempts = 0
        for attempt in range(max_retries):
            attempts = attempt + 1
            result = self._send_webhook(cfg, event, title, message, details)
            if result.get('success'):
                break
            if attempt < max_retries - 1:
                delay = 2 ** attempt  # 1s, 2s, 4s
                time.sleep(delay)
                logger.debug(f"Webhook retry {attempt + 2}/{max_retries} for '{cfg.get('name', 'webhook')}'")

        duration_ms = int(time.time() * 1000) - start_ms
        self._log_delivery(cfg, event, result, attempts, duration_ms)
        return result

    def _log_delivery(self, cfg: dict, event: str, result: dict,
                      attempts: int, duration_ms: int) -> None:
        """Append a delivery record to the JSONL log file."""
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'webhook_name': cfg.get('name', 'webhook'),
            'webhook_type': cfg.get('type', 'generic'),
            'event': event,
            'url': cfg.get('url', ''),
            'status': result.get('status'),
            'success': bool(result.get('success')),
            'attempts': attempts,
            'error': result.get('error'),
            'duration_ms': duration_ms,
        }
        try:
            self._delivery_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._delivery_log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            self._truncate_delivery_log()
        except OSError as e:
            logger.debug(f"Failed to write delivery log: {e}")

    def _truncate_delivery_log(self) -> None:
        """Keep only the last MAX_DELIVERY_LOG_ENTRIES entries (atomic)."""
        try:
            lines = self._delivery_log_path.read_text().splitlines()
            if len(lines) > self.MAX_DELIVERY_LOG_ENTRIES:
                keep = lines[-self.MAX_DELIVERY_LOG_ENTRIES:]
                import tempfile as _tmpmod
                tmp_fd, tmp_path = _tmpmod.mkstemp(
                    dir=str(self._delivery_log_path.parent), suffix='.tmp')
                try:
                    with os.fdopen(tmp_fd, 'w') as f:
                        f.write('\n'.join(keep) + '\n')
                    os.replace(tmp_path, str(self._delivery_log_path))
                except Exception:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    raise
        except OSError:
            pass

    def get_deliveries(self, limit: int = 50) -> List[dict]:
        """Read recent delivery log entries, newest first."""
        try:
            if not self._delivery_log_path.exists():
                return []
            lines = self._delivery_log_path.read_text().splitlines()
            entries = []
            for line in reversed(lines[-limit:]):
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
            return entries
        except (OSError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to read delivery log: {e}")
            return []

    def _send_webhook(self, cfg: dict, event: str, title: str,
                      message: str, details: Optional[dict] = None) -> dict:
        """Send a notification to a webhook-style channel.

        Supported ``type`` values: ``generic`` (signed JSON), ``slack``,
        ``discord``, ``telegram``, ``ntfy``, ``gotify``. Each formats the
        request (URL, body, headers) for its target service. Microsoft Teams
        is covered by the SMTP channel via a Teams channel email address — no
        dedicated adapter.
        """
        try:
            wh_type = cfg.get('type', 'generic')
            url = (cfg.get('url') or '').strip()
            secret = cfg.get('secret', '')
            headers = {'User-Agent': 'CertMate-Webhook/2.0'}
            content_type = 'application/json'

            def _detail_lines():
                if not details:
                    return ''
                return '\n' + '\n'.join(f'{k}: {v}' for k, v in details.items())

            if wh_type == 'slack':
                payload = {
                    'text': f'*{title}*\n{message}',
                    'blocks': [
                        {'type': 'header', 'text': {'type': 'plain_text', 'text': title}},
                        {'type': 'section', 'text': {'type': 'mrkdwn', 'text': message}}
                    ]
                }
                if details:
                    payload['blocks'].append({'type': 'section', 'fields': [
                        {'type': 'mrkdwn', 'text': f'*{k}:* {v}'} for k, v in details.items()]})
                body = json.dumps(payload).encode('utf-8')

            elif wh_type == 'discord':
                embed = {'title': title, 'description': message, 'color': 2067276}
                if details:
                    embed['fields'] = [{'name': k, 'value': str(v), 'inline': True}
                                       for k, v in details.items()]
                body = json.dumps({'embeds': [embed]}).encode('utf-8')

            elif wh_type == 'telegram':
                # Bot API: the token is in the URL path, chat_id in the body.
                # Send PLAIN TEXT (no parse_mode). Titles/messages/details carry
                # certbot error strings and wildcard '*' / '_acme-challenge'
                # metacharacters; with parse_mode='Markdown' those unbalanced
                # entities make the Bot API reject the message with HTTP 400
                # "can't parse entities" and the alert is silently dropped —
                # precisely on the failure events that matter most.
                token = (cfg.get('token') or '').strip()
                chat_id = str(cfg.get('chat_id') or '').strip()
                if not (token and chat_id):
                    return {'error': 'Telegram channel requires token and chat_id'}
                url = f'https://api.telegram.org/bot{token}/sendMessage'
                body = json.dumps({
                    'chat_id': chat_id,
                    'text': f'{title}\n{message}{_detail_lines()}',
                }).encode('utf-8')

            elif wh_type == 'ntfy':
                # url is the topic URL, e.g. https://ntfy.sh/my-topic
                body = (message + _detail_lines()).encode('utf-8')
                content_type = 'text/plain; charset=utf-8'
                headers['Title'] = title
                headers['Priority'] = str(cfg.get('priority') or 'default')
                if cfg.get('token'):
                    headers['Authorization'] = f"Bearer {cfg['token']}"

            elif wh_type == 'gotify':
                token = (cfg.get('token') or '').strip()
                if not (url and token):
                    return {'error': 'Gotify channel requires url and token'}
                url = url.rstrip('/') + '/message'
                headers['X-Gotify-Key'] = token
                try:
                    priority = int(cfg.get('priority', 5))
                except (TypeError, ValueError):
                    priority = 5
                body = json.dumps({'title': title, 'message': message + _detail_lines(),
                                   'priority': priority}).encode('utf-8')

            else:  # generic — signed JSON with optional custom headers
                template = cfg.get('payload_template')
                if template:
                    # Operator-shaped body (#218); a broken template is a
                    # config error, reported rather than retried into.
                    # (TypeError would mean a value json cannot serialise
                    # even with default=str — not expected, but not a
                    # reason to crash the notifier either.)
                    try:
                        rendered = render_payload_template(
                            template, webhook_template_variables(event, title, message, details))
                    except (ValueError, TypeError) as exc:
                        return {'error': str(exc), 'config_error': True}
                    body = rendered.encode('utf-8')
                else:
                    payload = {
                        'event': event, 'title': title, 'message': message,
                        'details': details or {},
                        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    }
                    body = json.dumps(payload).encode('utf-8')
                for hdr_name, hdr_value in (cfg.get('headers') or {}).items():
                    headers[hdr_name] = hdr_value
                auth_err = self._apply_webhook_auth(cfg, headers)
                if auth_err:
                    return {'error': auth_err, 'config_error': True}
                # HMAC-SHA256 signature with timestamp for replay protection.
                if secret:
                    timestamp = str(int(time.time()))
                    sig = hmac.new(secret.encode(), f'{timestamp}.'.encode() + body,
                                   hashlib.sha256).hexdigest()
                    headers['X-CertMate-Signature'] = f't={timestamp},v1={sig}'

            if not url:
                return {'error': 'Webhook URL not configured'}
            # Only allow http/https schemes to prevent file:// or other attacks.
            if not url.startswith(('https://', 'http://')):
                return {'error': 'Webhook URL must use http or https scheme'}
            # SSRF guard: refuse targets that resolve to internal/loopback/
            # metadata addresses unless an operator explicitly allows them.
            if _webhook_url_is_internal(url) and \
                    os.getenv('CERTMATE_ALLOW_INTERNAL_WEBHOOKS', '').lower() not in ('true', '1', 'yes'):
                logger.warning("Refused webhook to internal/loopback target: %s",
                               urlparse(url).hostname)
                return {'error': 'Webhook target resolves to an internal/loopback address; '
                                 'refused (SSRF guard). Set CERTMATE_ALLOW_INTERNAL_WEBHOOKS=true '
                                 'to permit internal targets.'}

            method = 'POST'
            timeout = WEBHOOK_DEFAULT_TIMEOUT
            if wh_type == 'generic':
                method = (cfg.get('method') or 'POST').upper()
                if method not in WEBHOOK_METHODS:
                    return {'error': f"method must be one of {', '.join(WEBHOOK_METHODS)}",
                            'config_error': True}
            timeout, t_err = _coerce_int(cfg.get('timeout'), WEBHOOK_DEFAULT_TIMEOUT,
                                         1, WEBHOOK_MAX_TIMEOUT, 'timeout')
            if t_err:
                return {'error': t_err, 'config_error': True}
            req = Request(url, data=body, method=method)
            req.add_header('Content-Type', content_type)
            for hdr_name, hdr_value in headers.items():
                req.add_header(hdr_name, hdr_value)

            with urlopen(req, timeout=timeout) as resp:  # nosec B310
                status = resp.status
                logger.info(f"Webhook '{cfg.get('name', 'webhook')}' ({wh_type}) sent: HTTP {status}")
                return {'success': True, 'status': status}

        except URLError as e:
            logger.error(f"Webhook failed: {e}")
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Webhook failed: {e}")
            return {'error': str(e)}

    @staticmethod
    def _apply_webhook_auth(cfg: dict, headers: dict) -> Optional[str]:
        """Add the configured authentication header. Returns an error or None."""
        auth_type = cfg.get('auth_type') or 'none'
        if auth_type == 'none':
            return None
        if auth_type == 'bearer':
            token = (cfg.get('auth_token') or '').strip()
            if not token:
                return 'bearer authentication needs auth_token'
            headers['Authorization'] = f'Bearer {token}'
            return None
        if auth_type == 'basic':
            username = cfg.get('auth_username') or ''
            password = cfg.get('auth_password') or ''
            if not (username and password):
                return 'basic authentication needs auth_username and auth_password'
            raw = f'{username}:{password}'.encode('utf-8')
            headers['Authorization'] = 'Basic ' + base64.b64encode(raw).decode('ascii')
            return None
        if auth_type == 'header':
            token = (cfg.get('auth_token') or '').strip()
            if not token:
                return 'header authentication needs auth_token (the header value)'
            name = (cfg.get('auth_header') or 'X-API-Key').strip()
            if not re.match(r'^[A-Za-z0-9-]+$', name):
                return 'auth_header is not a valid header name'
            headers[name] = token
            return None
        return f"auth_type must be one of {', '.join(WEBHOOK_AUTH_TYPES)}"

    def preview_webhook(self, cfg: dict, event: str = 'certificate_renewed',
                        details: Optional[dict] = None) -> dict:
        """Render what a generic webhook would send for a sample event, without
        sending it: method, URL, header names (values of credentials masked),
        and the body. Returns ``{'error': ...}`` for a config that cannot
        render."""
        if (cfg.get('type') or 'generic') != 'generic':
            return {'error': "preview renders generic webhooks only; Slack, Discord, "
                             "Telegram, ntfy and Gotify have a fixed body — use Test"}
        err = validate_webhook_config(cfg)
        if err:
            return {'error': err}
        details = details or {'domain': 'example.com', 'days_until_expiry': 29,
                              'expires_at': '2026-09-19T08:00:00Z'}
        title = event.replace('_', ' ').title()
        message = f"{title}: {details.get('domain', 'example.com')}"
        variables = webhook_template_variables(event, title, message, details)
        template = cfg.get('payload_template')
        if template:
            body = render_payload_template(template, variables)
        else:
            body = json.dumps({
                'event': event, 'title': title, 'message': message,
                'details': details, 'timestamp': variables['timestamp'],
            }, indent=2)
        headers = {'User-Agent': 'CertMate-Webhook/2.0', 'Content-Type': 'application/json'}
        for hdr_name, hdr_value in (cfg.get('headers') or {}).items():
            headers[hdr_name] = hdr_value
        self._apply_webhook_auth(cfg, headers)
        if cfg.get('secret'):
            headers['X-CertMate-Signature'] = 't=<timestamp>,v1=<hmac-sha256>'
        shown = {}
        for name, value in headers.items():
            lowered = name.lower()
            sensitive = any(word in lowered for word in ('authorization', 'key', 'token', 'secret', 'cookie'))
            shown[name] = '********' if sensitive else value
        return {
            'method': (cfg.get('method') or 'POST').upper(),
            'url': (cfg.get('url') or '').strip(),
            'headers': shown,
            'body': body,
            'variables': [{'name': n, 'description': d} for n, d in TEMPLATE_VARIABLES],
        }

    def test_channel(self, channel_type: str, config: dict) -> dict:
        """Test a notification channel with a test message."""
        if channel_type == 'smtp':
            return self._send_email(config, 'Test Notification',
                                    'This is a test notification from CertMate.')
        elif channel_type == 'webhook':
            return self._send_webhook(config, 'test', 'Test Notification',
                                      'This is a test notification from CertMate.',
                                      {'source': 'CertMate test'})
        return {'error': f'Unknown channel type: {channel_type}'}
