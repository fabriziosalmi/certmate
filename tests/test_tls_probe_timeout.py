"""
Tests for the TLS probe timeout reduction and slow-probe instrumentation.

The dashboard's "is this cert actually deployed?" check opens a raw TCP
socket to <domain>:443 and completes a TLS handshake. Each probe blocks
one Flask worker thread for up to `timeout` seconds. The previous default
of 5s combined with sync workers and multiple unreachable hosts could
stall an operator's dashboard rendering for tens of seconds. The fix:

1. Lower the default to 3s.
2. Make it configurable via CERTMATE_TLS_PROBE_TIMEOUT_SECONDS (clamped
   to [1, 30]).
3. Emit a warning log when a probe takes more than 1 second so an
   operator can spot the offending target without reproducing the stall.

These tests pin all three contracts.
"""
from __future__ import annotations

import logging
import time
from unittest.mock import patch, MagicMock

import pytest


from modules.api.resources import _tls_probe_timeout_seconds, _probe_https_certificate


# ---- _tls_probe_timeout_seconds -------------------------------------------


def test_default_timeout_is_three_seconds(monkeypatch):
    monkeypatch.delenv('CERTMATE_TLS_PROBE_TIMEOUT_SECONDS', raising=False)
    assert _tls_probe_timeout_seconds() == 3.0


def test_env_var_override(monkeypatch):
    monkeypatch.setenv('CERTMATE_TLS_PROBE_TIMEOUT_SECONDS', '7')
    assert _tls_probe_timeout_seconds() == 7.0


@pytest.mark.parametrize("raw,expected", [
    ('0', 1.0),       # clamped up to 1
    ('-5', 1.0),      # negative clamped to 1
    ('100', 30.0),    # clamped down to 30
    ('not-a-number', 3.0),  # falls back to default
    ('', 3.0),        # empty falls back
    ('  ', 3.0),      # whitespace falls back
])
def test_env_var_clamp_and_fallback(monkeypatch, raw, expected):
    monkeypatch.setenv('CERTMATE_TLS_PROBE_TIMEOUT_SECONDS', raw)
    assert _tls_probe_timeout_seconds() == expected


# ---- _probe_https_certificate slow-warning -------------------------------


def test_slow_probe_logs_warning(caplog):
    """A probe that takes >1s must surface a warning so the operator
    can spot the slow domain without reproducing the dashboard stall."""

    def slow_create_connection(*args, **kwargs):
        # Simulate a slow TLS handshake by sleeping briefly before
        # raising — we only need to verify the timing branch fires.
        time.sleep(1.05)
        raise ConnectionRefusedError("simulated unreachable")

    with caplog.at_level(logging.WARNING, logger="modules.api.resources"):
        with patch('modules.api.resources.socket.create_connection',
                   side_effect=slow_create_connection):
            with pytest.raises(ConnectionRefusedError):
                _probe_https_certificate('example.com', timeout=2)

    warned = [r for r in caplog.records if 'Slow TLS probe' in r.message]
    assert len(warned) == 1, (
        f"Expected one 'Slow TLS probe' warning; got {[r.message for r in caplog.records]}"
    )
    assert 'example.com' in warned[0].message


def test_fast_probe_does_not_log_warning(caplog):
    """Sub-second probes are the common case and must not spam the log."""
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    mock_tls_sock = MagicMock()
    mock_tls_sock.__enter__ = MagicMock(return_value=mock_tls_sock)
    mock_tls_sock.__exit__ = MagicMock(return_value=False)
    mock_tls_sock.getpeercert.return_value = b'fake-cert-bytes'

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_tls_sock

    with caplog.at_level(logging.WARNING, logger="modules.api.resources"):
        with patch('modules.api.resources.socket.create_connection',
                   return_value=mock_sock):
            with patch('modules.api.resources.ssl.create_default_context',
                       return_value=mock_context):
                result = _probe_https_certificate('fast.example.com', timeout=2)

    assert result['reachable'] is True
    warned = [r for r in caplog.records if 'Slow TLS probe' in r.message]
    assert warned == [], (
        f"Fast probe must not log slow warning; got {[r.message for r in warned]}"
    )


def test_probe_uses_env_var_when_timeout_not_passed(monkeypatch):
    """When _probe_https_certificate is called with timeout=None, it must
    pick up CERTMATE_TLS_PROBE_TIMEOUT_SECONDS so deployment-time tuning
    actually takes effect."""
    monkeypatch.setenv('CERTMATE_TLS_PROBE_TIMEOUT_SECONDS', '4.5')

    captured_timeout = {}

    def capturing_create_connection(addr, timeout):
        captured_timeout['value'] = timeout
        raise ConnectionRefusedError("simulated")

    with patch('modules.api.resources.socket.create_connection',
               side_effect=capturing_create_connection):
        with pytest.raises(ConnectionRefusedError):
            _probe_https_certificate('example.com')  # timeout=None

    assert captured_timeout['value'] == 4.5


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
