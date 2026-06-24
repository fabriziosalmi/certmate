"""
Tests for tunnelling the TLS deployment probe through an HTTP proxy.

The dashboard's "is this cert actually deployed?" probe opens a raw TCP socket
to <domain>:<port>. A raw socket ignores HTTPS_PROXY, so on a host that can
only reach the outside internet via an outbound HTTP proxy the server-side
probe always reports "Unreachable" even though the target is up. The fix: when
HTTPS_PROXY is set (and the host isn't in NO_PROXY) tunnel the TCP leg through
the proxy with HTTP CONNECT, then run the TLS handshake over that tunnel (#326).

These tests pin: proxy discovery (env + NO_PROXY + auth) and that the probe
actually uses CONNECT — to the configured port — when a proxy applies.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from modules.api.resources import _https_proxy_for, _probe_tls_certificate


# ---- _https_proxy_for -----------------------------------------------------


def test_no_proxy_env_returns_none(monkeypatch):
    monkeypatch.delenv('HTTPS_PROXY', raising=False)
    monkeypatch.delenv('https_proxy', raising=False)
    assert _https_proxy_for('example.com') is None


def test_parses_host_and_port(monkeypatch):
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', 'http://proxy.internal:3128')
    assert _https_proxy_for('example.com') == ('proxy.internal', 3128, {})


def test_default_port_when_omitted(monkeypatch):
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', 'http://proxy.internal')
    host, port, headers = _https_proxy_for('example.com')
    assert (host, port) == ('proxy.internal', 8080)


def test_scheme_optional(monkeypatch):
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', 'proxy.internal:3128')
    assert _https_proxy_for('example.com') == ('proxy.internal', 3128, {})


def test_basic_auth_header_from_credentials(monkeypatch):
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', 'http://user:p%40ss@proxy.internal:3128')
    host, port, headers = _https_proxy_for('example.com')
    assert (host, port) == ('proxy.internal', 3128)
    # base64("user:p@ss") — note the password is URL-decoded first.
    assert headers == {'Proxy-Authorization': 'Basic dXNlcjpwQHNz'}


def test_no_proxy_bypass(monkeypatch):
    monkeypatch.setenv('https_proxy', 'http://proxy.internal:3128')
    monkeypatch.setenv('no_proxy', 'example.com')
    assert _https_proxy_for('example.com') is None


# ---- _probe_tls_certificate proxy path ------------------------------------


def _mock_tls_context(cert_bytes):
    tls_sock = MagicMock()
    tls_sock.__enter__ = MagicMock(return_value=tls_sock)
    tls_sock.__exit__ = MagicMock(return_value=False)
    tls_sock.getpeercert.return_value = cert_bytes
    context = MagicMock()
    context.wrap_socket.return_value = tls_sock
    return context


def test_probe_tunnels_via_connect_when_proxy_set(monkeypatch):
    """With a proxy configured the probe must use HTTP CONNECT, not a direct
    socket, and still return the peer certificate from the tunnelled TLS."""
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', 'http://proxy.internal:3128')

    mock_conn = MagicMock()
    mock_conn.sock = MagicMock()

    with patch('modules.api.resources.http.client.HTTPConnection',
               return_value=mock_conn) as mock_http, \
            patch('modules.api.resources.ssl.create_default_context',
                  return_value=_mock_tls_context(b'tunnelled-cert')), \
            patch('modules.api.resources.socket.create_connection') as mock_direct:
        result = _probe_tls_certificate('example.com', timeout=2)

    mock_http.assert_called_once_with('proxy.internal', 3128, timeout=2)
    mock_conn.set_tunnel.assert_called_once_with('example.com', 443, headers={})
    mock_conn.connect.assert_called_once()
    mock_conn.close.assert_called_once()
    mock_direct.assert_not_called()  # never a direct connection when proxied
    assert result == {
        'reachable': True,
        'certificate_bytes': b'tunnelled-cert',
        'port': 443,
        'protocol': 'https-tls',
    }


def test_proxy_tunnel_uses_configured_port(monkeypatch):
    """The CONNECT target must be the per-cert probe port, not a hardcoded 443."""
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', 'http://proxy.internal:3128')

    mock_conn = MagicMock()
    mock_conn.sock = MagicMock()

    with patch('modules.api.resources.http.client.HTTPConnection',
               return_value=mock_conn), \
            patch('modules.api.resources.ssl.create_default_context',
                  return_value=_mock_tls_context(b'cert')):
        result = _probe_tls_certificate('example.com', port=8443, protocol='tls', timeout=2)

    mock_conn.set_tunnel.assert_called_once_with('example.com', 8443, headers={})
    assert result['port'] == 8443
    assert result['protocol'] == 'tls'


def test_probe_direct_when_no_proxy(monkeypatch):
    """Without a proxy the probe keeps its original direct-socket behaviour."""
    monkeypatch.delenv('HTTPS_PROXY', raising=False)
    monkeypatch.delenv('https_proxy', raising=False)

    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    with patch('modules.api.resources.socket.create_connection',
               return_value=mock_sock), \
            patch('modules.api.resources.ssl.create_default_context',
                  return_value=_mock_tls_context(b'direct-cert')), \
            patch('modules.api.resources.http.client.HTTPConnection') as mock_http:
        result = _probe_tls_certificate('example.com', timeout=2)

    mock_http.assert_not_called()
    assert result == {
        'reachable': True,
        'certificate_bytes': b'direct-cert',
        'port': 443,
        'protocol': 'https-tls',
    }


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
