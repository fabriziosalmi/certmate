"""SIEM audit sink (#474): formatters, send routing, secret redaction,
failure isolation, and the AuditLogger integration."""

import json
from unittest.mock import MagicMock

import pytest

from modules.core.audit_sink import (
    AuditSink, format_syslog, format_cef, format_json,
    _syslog_transport, _http_transport,
    FORMAT_SYSLOG, FORMAT_CEF, FORMAT_JSON,
)

pytestmark = [pytest.mark.unit]


def _entry(**over):
    e = {
        'timestamp': '2026-07-29T10:00:00+00:00',
        'operation': 'create', 'resource_type': 'certificate',
        'resource_id': 'example.com', 'status': 'success',
        'user': 'alice', 'ip_address': '10.0.0.9', 'details': {}, 'error': None,
    }
    e.update(over)
    return e


class _Capture:
    def __init__(self):
        self.payloads = []

    def __call__(self, payload, config):
        self.payloads.append(payload)


def _sink(settings, **kw):
    sm = MagicMock()
    sm.load_settings.return_value = settings
    return AuditSink(sm, **kw)


# --------------------------------------------------------------------------- #
# formatters
# --------------------------------------------------------------------------- #

def test_format_syslog_rfc5424():
    line = format_syslog(_entry(), {'facility': 16, 'app_name': 'certmate'})
    # PRI = 16*8 + 6 (info) = 134; version 1; MSGID=operation; JSON in MSG.
    assert line.startswith('<134>1 2026-07-29T10:00:00+00:00 ')
    assert ' certmate - create - ' in line
    payload = line.split(' - ', 1)[1].split(' - ', 1)[1]
    assert json.loads(payload)['resource_id'] == 'example.com'


def test_format_syslog_severity_for_failure():
    line = format_syslog(_entry(status='failure'), {'facility': 16})
    # 16*8 + 3 (error) = 131
    assert line.startswith('<131>1 ')


def test_format_cef():
    line = format_cef(_entry(error='boom', status='failure'), {'facility': 16})
    assert 'CEF:0|CertMate|CertMate|1|create|create|8|' in line
    assert 'act=create' in line and 'outcome=failure' in line
    assert 'suser=alice' in line and 'src=10.0.0.9' in line
    assert 'reason=boom' in line


def test_format_json():
    assert json.loads(format_json(_entry()))['operation'] == 'create'


# --------------------------------------------------------------------------- #
# AuditSink.send routing
# --------------------------------------------------------------------------- #

def test_disabled_sink_sends_nothing():
    syslog, http = _Capture(), _Capture()
    _sink({'audit_sink': {'enabled': False}}, syslog_send=syslog, http_post=http).send(_entry())
    assert syslog.payloads == [] and http.payloads == []


def test_syslog_format_uses_syslog_transport():
    syslog, http = _Capture(), _Capture()
    _sink({'audit_sink': {'enabled': True, 'format': FORMAT_SYSLOG, 'host': 'siem'}},
          syslog_send=syslog, http_post=http).send(_entry())
    assert len(syslog.payloads) == 1 and syslog.payloads[0].startswith('<')
    assert http.payloads == []


def test_cef_format_uses_syslog_transport():
    syslog, http = _Capture(), _Capture()
    _sink({'audit_sink': {'enabled': True, 'format': FORMAT_CEF, 'host': 'siem'}},
          syslog_send=syslog, http_post=http).send(_entry())
    assert 'CEF:0|' in syslog.payloads[0]
    assert http.payloads == []


def test_json_format_uses_http_transport():
    syslog, http = _Capture(), _Capture()
    _sink({'audit_sink': {'enabled': True, 'format': FORMAT_JSON, 'url': 'https://x/y'}},
          syslog_send=syslog, http_post=http).send(_entry())
    assert len(http.payloads) == 1 and json.loads(http.payloads[0])['operation'] == 'create'
    assert syslog.payloads == []


# --------------------------------------------------------------------------- #
# secret redaction + isolation
# --------------------------------------------------------------------------- #

def test_secrets_are_redacted_before_send():
    http = _Capture()
    entry = _entry(details={'token': 'super-secret-value', 'note': 'ok',
                            'blob': 'api_key=leaked123'})
    _sink({'audit_sink': {'enabled': True, 'format': FORMAT_JSON, 'url': 'https://x'}},
          http_post=http).send(entry)
    payload = http.payloads[0]
    assert 'super-secret-value' not in payload
    assert 'leaked123' not in payload
    assert '[REDACTED]' in payload
    assert 'ok' in payload  # non-secret preserved


def test_send_is_failure_isolated():
    def boom(payload, config):
        raise ConnectionError('collector down')
    # Must not raise.
    _sink({'audit_sink': {'enabled': True, 'format': FORMAT_SYSLOG, 'host': 'h'}},
          syslog_send=boom).send(_entry())


def test_settings_read_failure_isolated():
    sm = MagicMock()
    sm.load_settings.side_effect = RuntimeError('settings unavailable')
    # No enabled config -> disabled; must not raise.
    AuditSink(sm, syslog_send=_Capture()).send(_entry())


# --------------------------------------------------------------------------- #
# transports (config validation)
# --------------------------------------------------------------------------- #

def test_syslog_transport_requires_host():
    with pytest.raises(ValueError):
        _syslog_transport('msg', {'protocol': 'udp'})


def test_http_transport_requires_url():
    with pytest.raises(ValueError):
        _http_transport('{}', {})


# --------------------------------------------------------------------------- #
# AuditLogger integration
# --------------------------------------------------------------------------- #

def test_audit_logger_streams_to_sink(tmp_path):
    from modules.core.audit import AuditLogger
    sink = MagicMock()
    logger = AuditLogger(tmp_path / 'logs', chain_dir=tmp_path / 'chain',
                         audit_sink=sink)
    logger.log_operation(operation='revoke', resource_type='certificate',
                         resource_id='ex.com', status='success', user='bob')
    assert sink.send.called
    sent = sink.send.call_args[0][0]
    assert sent['operation'] == 'revoke' and sent['resource_id'] == 'ex.com'


def test_audit_logger_survives_sink_error(tmp_path):
    from modules.core.audit import AuditLogger
    sink = MagicMock()
    sink.send.side_effect = RuntimeError('sink exploded')
    logger = AuditLogger(tmp_path / 'logs', chain_dir=tmp_path / 'chain',
                         audit_sink=sink)
    # Must not raise despite the sink blowing up.
    logger.log_operation(operation='create', resource_type='certificate',
                         resource_id='ex.com', status='success')
