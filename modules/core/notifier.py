"""
Notification system for CertMate.
Supports SMTP email and webhook (Slack, Discord, generic) notifications.
"""

import json
import logging
import smtplib
import hashlib
import hmac
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any, List
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


class Notifier:
    """Sends notifications via configured channels."""

    def __init__(self, settings_manager):
        self.settings_manager = settings_manager

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
            results['smtp'] = self._send_email(smtp_cfg, title, message, details)

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
            if use_tls:
                server = smtplib.SMTP(host, port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP(host, port, timeout=10)

            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
            logger.info(f"Email notification sent: {subject}")
            return {'success': True}

        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return {'error': str(e)}

    def _send_webhook_with_retry(self, cfg: dict, event: str, title: str,
                                message: str, details: Optional[dict] = None,
                                max_retries: int = 3) -> dict:
        """Send webhook with exponential backoff retry."""
        result = {}
        for attempt in range(max_retries):
            result = self._send_webhook(cfg, event, title, message, details)
            if result.get('success'):
                return result
            if attempt < max_retries - 1:
                delay = 2 ** attempt  # 1s, 2s, 4s
                time.sleep(delay)
                logger.debug(f"Webhook retry {attempt + 2}/{max_retries} for '{cfg.get('name', 'webhook')}'")
        return result

    def _send_webhook(self, cfg: dict, event: str, title: str,
                      message: str, details: Optional[dict] = None) -> dict:
        """Send webhook notification (generic, Slack, or Discord format)."""
        try:
            url = cfg.get('url', '')
            if not url:
                return {'error': 'Webhook URL not configured'}

            # Only allow http/https schemes to prevent file:// or other attacks
            if not url.startswith(('https://', 'http://')):
                return {'error': 'Webhook URL must use http or https scheme'}

            wh_type = cfg.get('type', 'generic')
            secret = cfg.get('secret', '')

            if wh_type == 'slack':
                payload = {
                    'text': f'*{title}*\n{message}',
                    'blocks': [
                        {'type': 'header', 'text': {'type': 'plain_text', 'text': title}},
                        {'type': 'section', 'text': {'type': 'mrkdwn', 'text': message}}
                    ]
                }
                if details:
                    fields = [{'type': 'mrkdwn', 'text': f'*{k}:* {v}'}
                              for k, v in details.items()]
                    payload['blocks'].append({'type': 'section', 'fields': fields})

            elif wh_type == 'discord':
                embed = {
                    'title': title,
                    'description': message,
                    'color': 2067276,  # CertMate blue
                }
                if details:
                    embed['fields'] = [{'name': k, 'value': str(v), 'inline': True}
                                       for k, v in details.items()]
                payload = {'embeds': [embed]}

            else:  # generic
                payload = {
                    'event': event,
                    'title': title,
                    'message': message,
                    'details': details or {},
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                }

            body = json.dumps(payload).encode('utf-8')
            req = Request(url, data=body, method='POST')
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'CertMate-Webhook/1.0')

            # HMAC signature for generic webhooks
            if secret and wh_type == 'generic':
                sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
                req.add_header('X-CertMate-Signature', sig)

            with urlopen(req, timeout=10) as resp:  # nosec B310
                status = resp.status
                logger.info(f"Webhook '{cfg.get('name', 'webhook')}' sent: HTTP {status}")
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
