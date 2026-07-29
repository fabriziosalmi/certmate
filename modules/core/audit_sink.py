"""SIEM audit sink (#474).

The tamper-evident audit trail is a signed, hash-chained JSON event stream, but
until now the only way out was the on-disk file + the signed export bundle.
SOC/SIEM integration expects a *push* in a standard format. This module streams
each audit entry to an external collector in one of three formats:

* **syslog** (RFC 5424) over UDP or TCP
* **CEF** (ArcSight Common Event Format) over UDP or TCP
* **generic HTTP/JSON** (POST the entry as JSON)

Every entry is run through the existing credential/secret sanitizer
(:class:`structured_logging.JSONFormatter.sanitize_data` — redacts sensitive
keys and PEM/key=value secrets) before it leaves the process, so a token in a
detail field never reaches the collector.

The sink is **failure-isolated**, exactly like the hash chain: any formatting or
transport error is caught and logged, never raised into the audited operation.
Sends use a short socket/HTTP timeout so a dead collector can't stall a
certificate operation.
"""

import json
import logging
import socket
import urllib.request

from .structured_logging import JSONFormatter

logger = logging.getLogger(__name__)

# One shared sanitizer instance (stateless w.r.t. the entry).
_SANITIZER = JSONFormatter(include_hostname=False, include_pid=False)

FORMAT_SYSLOG = 'syslog'
FORMAT_CEF = 'cef'
FORMAT_JSON = 'json'
FORMATS = (FORMAT_SYSLOG, FORMAT_CEF, FORMAT_JSON)

DEFAULT_CONFIG = {
    'enabled': False,
    'format': FORMAT_SYSLOG,     # syslog | cef | json
    'protocol': 'udp',           # udp | tcp (syslog/cef transport)
    'host': '',
    'port': 514,
    'url': '',                   # for format=json (HTTP POST)
    'timeout': 3.0,
    'facility': 16,              # local0
    'app_name': 'certmate',
}

# RFC 5424 severity per audit status (lower = more severe).
_SEVERITY = {'success': 6, 'failure': 3, 'denied': 4}  # info / error / warning
# CEF severity 0-10.
_CEF_SEVERITY = {'success': 3, 'failure': 8, 'denied': 6}


def _severity(status):
    return _SEVERITY.get(status, 5)


def format_syslog(entry, config):
    """Render an audit entry as an RFC 5424 syslog line (JSON in the MSG)."""
    facility = int(config.get('facility', 16))
    pri = facility * 8 + _severity(entry.get('status'))
    ts = entry.get('timestamp') or '-'
    host = socket.gethostname() or '-'
    app = config.get('app_name', 'certmate')
    msgid = (entry.get('operation') or '-')[:32]
    msg = json.dumps(entry, separators=(',', ':'))
    # <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
    return f'<{pri}>1 {ts} {host} {app} - {msgid} - {msg}'


def _cef_escape(value):
    return (str(value).replace('\\', '\\\\').replace('|', '\\|')
            .replace('\n', ' '))


def _cef_ext_escape(value):
    return str(value).replace('\\', '\\\\').replace('=', '\\=').replace('\n', ' ')


def format_cef(entry, config):
    """Render an audit entry as a CEF line with a syslog header."""
    facility = int(config.get('facility', 16))
    pri = facility * 8 + _severity(entry.get('status'))
    ts = entry.get('timestamp') or '-'
    host = socket.gethostname() or '-'
    vendor = 'CertMate'
    op = entry.get('operation') or 'audit'
    sev = _CEF_SEVERITY.get(entry.get('status'), 5)
    ext = {
        'act': entry.get('operation'),
        'outcome': entry.get('status'),
        'suser': entry.get('user'),
        'src': entry.get('ip_address'),
        'cs1Label': 'resource', 'cs1': entry.get('resource_id'),
        'cs2Label': 'resource_type', 'cs2': entry.get('resource_type'),
    }
    if entry.get('error'):
        ext['reason'] = entry['error']
    ext_str = ' '.join(
        f'{k}={_cef_ext_escape(v)}' for k, v in ext.items() if v is not None)
    header = (f'CEF:0|{vendor}|CertMate|1|{_cef_escape(op)}|'
              f'{_cef_escape(op)}|{sev}|{ext_str}')
    return f'<{pri}>1 {ts} {host} {config.get("app_name", "certmate")} - - - {header}'


def format_json(entry):
    return json.dumps(entry)


class AuditSink:
    """Streams sanitized audit entries to a configured SIEM collector.

    Config is read from ``settings['audit_sink']`` on each send, so an admin can
    enable/disable or retune it at runtime. Transports are injectable for tests.
    """

    def __init__(self, settings_manager, syslog_send=None, http_post=None):
        self.settings_manager = settings_manager
        self._syslog_send = syslog_send or _syslog_transport
        self._http_post = http_post or _http_transport

    def _config(self):
        config = dict(DEFAULT_CONFIG)
        try:
            block = self.settings_manager.load_settings().get('audit_sink')
        except Exception:  # pragma: no cover - defensive; never break audit
            block = None
        if isinstance(block, dict):
            config.update(block)
        return config

    def send(self, entry):
        """Sanitize, format and ship one audit entry. Never raises."""
        try:
            config = self._config()
            if not config.get('enabled'):
                return
            sanitized = _SANITIZER.sanitize_data(entry)
            fmt = config.get('format', FORMAT_SYSLOG)
            if fmt == FORMAT_JSON:
                self._http_post(format_json(sanitized), config)
            elif fmt == FORMAT_CEF:
                self._syslog_send(format_cef(sanitized, config), config)
            else:
                self._syslog_send(format_syslog(sanitized, config), config)
        except Exception as e:
            # Isolated like the hash chain: a broken collector must never break
            # audit logging or the audited certificate operation.
            logger.warning("Audit sink send failed (isolated): %s", e)


def _syslog_transport(line, config):
    host = config.get('host')
    if not host:
        raise ValueError('audit_sink: syslog/cef selected but no host configured')
    port = int(config.get('port', 514))
    timeout = float(config.get('timeout', 3.0))
    data = line.encode('utf-8')
    if str(config.get('protocol', 'udp')).lower() == 'tcp':
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(data + b'\n')
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(data, (host, port))
        finally:
            sock.close()


def _http_transport(payload, config):
    url = config.get('url')
    if not url:
        raise ValueError('audit_sink: json format selected but no url configured')
    timeout = float(config.get('timeout', 3.0))
    req = urllib.request.Request(
        url, data=payload.encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json',
                 'User-Agent': 'CertMate-AuditSink'})
    with urllib.request.urlopen(req, timeout=timeout):  # nosec B310 - operator-configured URL
        pass
