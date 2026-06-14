"""
Notification system for CertMate.
Supports SMTP email and webhook (Slack, Discord, generic) notifications.
"""

import json
import logging
import os
import smtplib
import hashlib
import hmac
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


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
                                max_retries: int = 3) -> dict:
        """Send webhook with exponential backoff retry and delivery logging."""
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
                token = (cfg.get('token') or '').strip()
                chat_id = str(cfg.get('chat_id') or '').strip()
                if not (token and chat_id):
                    return {'error': 'Telegram channel requires token and chat_id'}
                url = f'https://api.telegram.org/bot{token}/sendMessage'
                body = json.dumps({
                    'chat_id': chat_id,
                    'text': f'*{title}*\n{message}{_detail_lines()}',
                    'parse_mode': 'Markdown',
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
                payload = {
                    'event': event, 'title': title, 'message': message,
                    'details': details or {},
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                }
                body = json.dumps(payload).encode('utf-8')
                for hdr_name, hdr_value in cfg.get('headers', {}).items():
                    headers[hdr_name] = hdr_value
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

            req = Request(url, data=body, method='POST')
            req.add_header('Content-Type', content_type)
            for hdr_name, hdr_value in headers.items():
                req.add_header(hdr_name, hdr_value)

            with urlopen(req, timeout=10) as resp:  # nosec B310
                status = resp.status
                logger.info(f"Webhook '{cfg.get('name', 'webhook')}' ({wh_type}) sent: HTTP {status}")
                return {'success': True, 'status': status}

        except URLError as e:
            logger.error(f"Webhook failed: {e}")
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"Webhook failed: {e}")
            return {'error': str(e)}

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
