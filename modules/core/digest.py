"""
Weekly digest for CertMate.
Collects certificate stats and recent activity, then sends a summary
email via the existing Notifier SMTP channel.
"""

import logging
import smtplib
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class WeeklyDigest:
    """Builds and sends a weekly summary email."""

    def __init__(self, certificate_manager, client_cert_manager,
                 audit_logger, notifier, settings_manager):
        self.certificate_manager = certificate_manager
        self.client_cert_manager = client_cert_manager
        self.audit_logger = audit_logger
        self.notifier = notifier
        self.settings_manager = settings_manager

    def _get_server_cert_stats(self) -> Dict[str, Any]:
        """Gather stats for server certificates."""
        settings = self.settings_manager.load_settings()
        settings = self.settings_manager.migrate_domains_format(settings)
        domains_from_settings = settings.get('domains', [])

        cert_dir = self.certificate_manager.cert_dir
        all_domains = set()

        for entry in domains_from_settings:
            if isinstance(entry, str):
                all_domains.add(entry)
            elif isinstance(entry, dict):
                d = entry.get('domain')
                if d:
                    all_domains.add(d)

        if cert_dir.exists():
            for p in cert_dir.iterdir():
                if p.is_dir():
                    all_domains.add(p.name)

        total = 0
        valid = 0
        expiring_soon = 0
        expired = 0
        expiring_domains: List[str] = []

        renewal_threshold = settings.get('renewal_threshold_days', 30)

        for domain in sorted(all_domains):
            info = self.certificate_manager.get_certificate_info(domain)
            if not info or not info.get('exists'):
                continue
            total += 1
            days = info.get('days_left')
            if days is None:
                continue
            if days <= 0:
                expired += 1
            elif days <= renewal_threshold:
                expiring_soon += 1
                expiring_domains.append(f"{domain} ({days}d)")
            else:
                valid += 1

        return {
            'total': total,
            'valid': valid,
            'expiring_soon': expiring_soon,
            'expired': expired,
            'expiring_domains': expiring_domains,
        }

    def _get_client_cert_stats(self) -> Dict[str, int]:
        """Gather stats for client certificates."""
        try:
            all_certs = self.client_cert_manager.list_client_certificates()
            active = [c for c in all_certs if not c.get('revoked')]
            revoked = [c for c in all_certs if c.get('revoked')]
            return {'total': len(all_certs), 'active': len(active), 'revoked': len(revoked)}
        except Exception as e:
            logger.debug(f"Failed to get client cert stats: {e}")
            return {'total': 0, 'active': 0, 'revoked': 0}

    def _get_weekly_activity(self) -> Dict[str, int]:
        """Count operations in the last 7 days from the audit log."""
        cutoff = datetime.utcnow() - timedelta(days=7)
        cutoff_str = cutoff.isoformat()

        entries = self.audit_logger.get_recent_entries(limit=500)
        created = 0
        renewed = 0
        failed = 0

        for entry in entries:
            ts = entry.get('timestamp', '')
            if ts < cutoff_str:
                continue
            op = entry.get('operation', '')
            status = entry.get('status', '')
            if status == 'failure':
                failed += 1
            elif op in ('certificate_create', 'certificate_created'):
                created += 1
            elif op in ('certificate_renew', 'certificate_renewed'):
                renewed += 1

        return {'created': created, 'renewed': renewed, 'failed': failed}

    def build_digest(self) -> Dict[str, Any]:
        """Build the digest payload (useful for testing without sending)."""
        server = self._get_server_cert_stats()
        client = self._get_client_cert_stats()
        activity = self._get_weekly_activity()

        return {
            'server_certs': server,
            'client_certs': client,
            'activity': activity,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
        }

    def _format_text(self, digest: Dict[str, Any]) -> str:
        """Format digest as plain text."""
        s = digest['server_certs']
        c = digest['client_certs']
        a = digest['activity']

        lines = [
            'Weekly Certificate Digest',
            '=' * 40,
            '',
            'Server Certificates',
            f'  Total: {s["total"]}',
            f'  Valid: {s["valid"]}',
            f'  Expiring soon: {s["expiring_soon"]}',
            f'  Expired: {s["expired"]}',
        ]
        if s['expiring_domains']:
            lines.append('')
            lines.append('  Expiring:')
            for d in s['expiring_domains']:
                lines.append(f'    - {d}')

        lines += [
            '',
            'Client Certificates',
            f'  Total: {c["total"]}  Active: {c["active"]}  Revoked: {c["revoked"]}',
            '',
            'Activity (last 7 days)',
            f'  Created: {a["created"]}  Renewed: {a["renewed"]}  Failed: {a["failed"]}',
        ]
        return '\n'.join(lines)

    def _format_html(self, digest: Dict[str, Any]) -> str:
        """Format digest as HTML email body."""
        s = digest['server_certs']
        c = digest['client_certs']
        a = digest['activity']

        expiring_rows = ''
        if s['expiring_domains']:
            items = ''.join(f'<li style="color:#d97706">{d}</li>' for d in s['expiring_domains'])
            expiring_rows = f'<ul style="margin:8px 0;padding-left:20px">{items}</ul>'

        return f'''<div style="font-family:sans-serif;max-width:600px;margin:0 auto">
<h2 style="color:#2563eb">CertMate — Weekly Digest</h2>

<h3 style="margin-top:20px">Server Certificates</h3>
<table style="border-collapse:collapse;width:100%">
<tr><td style="padding:4px 12px 4px 0;color:#6b7280">Total</td><td>{s["total"]}</td></tr>
<tr><td style="padding:4px 12px 4px 0;color:#22c55e">Valid</td><td>{s["valid"]}</td></tr>
<tr><td style="padding:4px 12px 4px 0;color:#f59e0b">Expiring soon</td><td>{s["expiring_soon"]}</td></tr>
<tr><td style="padding:4px 12px 4px 0;color:#ef4444">Expired</td><td>{s["expired"]}</td></tr>
</table>
{expiring_rows}

<h3 style="margin-top:20px">Client Certificates</h3>
<table style="border-collapse:collapse;width:100%">
<tr><td style="padding:4px 12px 4px 0;color:#6b7280">Total</td><td>{c["total"]}</td></tr>
<tr><td style="padding:4px 12px 4px 0;color:#22c55e">Active</td><td>{c["active"]}</td></tr>
<tr><td style="padding:4px 12px 4px 0;color:#6b7280">Revoked</td><td>{c["revoked"]}</td></tr>
</table>

<h3 style="margin-top:20px">Activity (last 7 days)</h3>
<table style="border-collapse:collapse;width:100%">
<tr><td style="padding:4px 12px 4px 0;color:#6b7280">Created</td><td>{a["created"]}</td></tr>
<tr><td style="padding:4px 12px 4px 0;color:#6b7280">Renewed</td><td>{a["renewed"]}</td></tr>
<tr><td style="padding:4px 12px 4px 0;color:#ef4444">Failed</td><td>{a["failed"]}</td></tr>
</table>

<p style="margin-top:24px;color:#9ca3af;font-size:12px">
Generated {digest['generated_at']} by CertMate
</p>
</div>'''

    def send(self) -> Dict[str, Any]:
        """Build and send the weekly digest email.

        Returns:
            Dict with send result or skip reason.
        """
        config = self.notifier._get_config()

        # Digest requires notifications enabled + SMTP configured
        if not config.get('enabled', False):
            return {'skipped': 'notifications disabled'}

        smtp_cfg = config.get('channels', {}).get('smtp', {})
        if not smtp_cfg.get('enabled', False):
            return {'skipped': 'SMTP not enabled'}

        # Check digest_enabled flag (default True when SMTP is configured)
        if not config.get('digest_enabled', True):
            return {'skipped': 'digest disabled'}

        digest = self.build_digest()
        text_body = self._format_text(digest)
        html_body = self._format_html(digest)

        # Send via SMTP directly with custom HTML formatting
        try:
            host = smtp_cfg.get('host', '')
            port = smtp_cfg.get('port', 587)
            username = smtp_cfg.get('username', '')
            password = smtp_cfg.get('password', '')
            from_addr = smtp_cfg.get('from_address', username)
            to_addrs = smtp_cfg.get('to_addresses', [])

            if not host or not to_addrs:
                return {'error': 'SMTP not fully configured'}

            msg = MIMEMultipart('alternative')
            msg['Subject'] = '[CertMate] Weekly Certificate Digest'
            msg['From'] = from_addr
            msg['To'] = ', '.join(to_addrs)
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            use_tls = smtp_cfg.get('use_tls', True)
            server = smtplib.SMTP(host, port, timeout=10)
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()

            logger.info("Weekly digest email sent successfully")
            return {'success': True}

        except Exception as e:
            logger.error(f"Weekly digest email failed: {e}")
            return {'error': str(e)}
