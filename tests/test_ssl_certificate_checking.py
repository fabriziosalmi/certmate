import pytest
import ssl
import socket
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import sys
import os

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import check_ssl_certificate

class TestSSLCertificateChecking:
    """Test SSL certificate checking functionality."""
    
    @patch('app.socket.create_connection')
    @patch('app.ssl.create_default_context')
    def test_check_ssl_certificate_success(self, mock_ssl_context, mock_socket_conn):
        """Test successful SSL certificate check."""
        # Mock certificate data
        mock_cert_data = MagicMock()
        mock_cert_data.subject = [
            MagicMock(oid=MagicMock(), value='example.com')
        ]
        mock_cert_data.extensions.get_extension_for_oid.return_value.value = [
            MagicMock(value='www.example.com'),
            MagicMock(value='api.example.com')
        ]
        mock_cert_data.issuer.rfc4514_string.return_value = "CN=Let's Encrypt Authority X3"
        mock_cert_data.not_valid_after_utc = datetime.now() + timedelta(days=30)
        
        # Mock socket and SSL context
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = b'mock_cert_der_data'
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context
        
        mock_socket = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_socket
        
        # Mock x509 certificate parsing
        with patch('app.x509.load_der_x509_certificate', return_value=mock_cert_data):
            with patch('app.x509.oid.NameOID.COMMON_NAME', 'mock_cn_oid'):
                # Make subject iteration work
                mock_subject_attr = MagicMock()
                mock_subject_attr.oid = 'mock_cn_oid'
                mock_subject_attr.value = 'example.com'
                mock_cert_data.subject = [mock_subject_attr]
                
                result = check_ssl_certificate('example.com')
        
        # Verify result structure
        assert result['deployed'] is True
        assert result['reachable'] is True
        assert result['certificate_match'] is True
        assert 'certificate_domains' in result
        assert 'issuer' in result
        assert 'expires_at' in result
        assert result['method'] == 'ssl-direct'
        assert 'timestamp' in result
    
    @patch('app.socket.create_connection')
    def test_check_ssl_certificate_timeout(self, mock_socket_conn):
        """Test SSL certificate check with timeout."""
        mock_socket_conn.side_effect = socket.timeout()
        
        result = check_ssl_certificate('example.com', timeout=1)
        
        assert result['deployed'] is False
        assert result['reachable'] is False
        assert result['certificate_match'] is False
        assert result['error'] == 'timeout'
        assert result['method'] == 'ssl-direct'
    
    @patch('app.socket.create_connection')
    def test_check_ssl_certificate_dns_error(self, mock_socket_conn):
        """Test SSL certificate check with DNS resolution error."""
        mock_socket_conn.side_effect = socket.gaierror('Name resolution failed')
        
        result = check_ssl_certificate('nonexistent.domain.com')
        
        assert result['deployed'] is False
        assert result['reachable'] is False
        assert result['certificate_match'] is False
        assert result['error'] == 'dns_resolution_failed'
        assert result['method'] == 'ssl-direct'
    
    @patch('app.socket.create_connection')
    def test_check_ssl_certificate_ssl_error(self, mock_socket_conn):
        """Test SSL certificate check with SSL error."""
        mock_socket = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_socket
        
        with patch('app.ssl.create_default_context') as mock_ssl_context:
            mock_context = MagicMock()
            mock_ssl_context.return_value = mock_context
            mock_context.wrap_socket.side_effect = ssl.SSLError('SSL handshake failed')
            
            result = check_ssl_certificate('example.com')
        
        assert result['deployed'] is False
        assert result['reachable'] is True
        assert result['certificate_match'] is False
        assert 'ssl_error' in result['error']
        assert result['method'] == 'ssl-direct'
    
    @patch('app.socket.create_connection')
    def test_check_ssl_certificate_generic_error(self, mock_socket_conn):
        """Test SSL certificate check with generic error."""
        mock_socket_conn.side_effect = Exception('Unexpected error')
        
        result = check_ssl_certificate('example.com')
        
        assert result['deployed'] is False
        assert result['reachable'] is False
        assert result['certificate_match'] is False
        assert 'unknown' in result['error']
        assert result['method'] == 'ssl-direct'
    
    @patch('app.socket.create_connection')
    @patch('app.ssl.create_default_context')
    def test_check_ssl_certificate_wildcard_match(self, mock_ssl_context, mock_socket_conn):
        """Test SSL certificate check with wildcard certificate."""
        # Mock certificate data with wildcard
        mock_cert_data = MagicMock()
        mock_cert_data.subject = []  # No CN
        mock_cert_data.extensions.get_extension_for_oid.return_value.value = [
            MagicMock(value='*.example.com')
        ]
        mock_cert_data.issuer.rfc4514_string.return_value = "CN=Let's Encrypt Authority X3"
        mock_cert_data.not_valid_after_utc = datetime.now() + timedelta(days=30)
        
        # Mock socket and SSL context
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = b'mock_cert_der_data'
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context
        
        mock_socket = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_socket
        
        # Mock x509 certificate parsing
        with patch('app.x509.load_der_x509_certificate', return_value=mock_cert_data):
            result = check_ssl_certificate('api.example.com')  # Should match *.example.com
        
        assert result['deployed'] is True
        assert result['certificate_match'] is True
        assert '*.example.com' in result['certificate_domains']
    
    @patch('app.socket.create_connection')
    @patch('app.ssl.create_default_context')
    def test_check_ssl_certificate_no_san_extension(self, mock_ssl_context, mock_socket_conn):
        """Test SSL certificate check when SAN extension is missing."""
        # Mock certificate data without SAN extension
        mock_cert_data = MagicMock()
        mock_cert_data.extensions.get_extension_for_oid.side_effect = Exception('No SAN extension')
        mock_cert_data.issuer.rfc4514_string.return_value = "CN=Test CA"
        mock_cert_data.not_valid_after_utc = datetime.now() + timedelta(days=30)
        
        # Mock subject with CN
        mock_subject_attr = MagicMock()
        mock_subject_attr.oid = 'mock_cn_oid'
        mock_subject_attr.value = 'example.com'
        mock_cert_data.subject = [mock_subject_attr]
        
        # Mock socket and SSL context
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = b'mock_cert_der_data'
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context
        
        mock_socket = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_socket
        
        # Mock x509 certificate parsing
        with patch('app.x509.load_der_x509_certificate', return_value=mock_cert_data):
            with patch('app.x509.oid.NameOID.COMMON_NAME', 'mock_cn_oid'):
                result = check_ssl_certificate('example.com')
        
        assert result['deployed'] is True
        assert result['certificate_match'] is True
        assert 'example.com' in result['certificate_domains']
    
    def test_check_ssl_certificate_different_ports(self):
        """Test SSL certificate check with different ports."""
        with patch('app.socket.create_connection') as mock_socket_conn:
            mock_socket_conn.side_effect = socket.timeout()
            
            # Test default port (443)
            result = check_ssl_certificate('example.com')
            mock_socket_conn.assert_called_with(('example.com', 443), timeout=10)
            
            # Test custom port
            result = check_ssl_certificate('example.com', port=8443)
            mock_socket_conn.assert_called_with(('example.com', 8443), timeout=10)
            
            # Test custom timeout
            result = check_ssl_certificate('example.com', timeout=5)
            mock_socket_conn.assert_called_with(('example.com', 443), timeout=5)
    
    @patch('app.socket.create_connection')
    @patch('app.ssl.create_default_context')
    def test_check_ssl_certificate_domain_mismatch(self, mock_ssl_context, mock_socket_conn):
        """Test SSL certificate check with domain mismatch."""
        # Mock certificate data for different domain
        mock_cert_data = MagicMock()
        mock_cert_data.subject = []  # No CN
        mock_cert_data.extensions.get_extension_for_oid.return_value.value = [
            MagicMock(value='different.com')
        ]
        mock_cert_data.issuer.rfc4514_string.return_value = "CN=Test CA"
        mock_cert_data.not_valid_after_utc = datetime.now() + timedelta(days=30)
        
        # Mock socket and SSL context
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = b'mock_cert_der_data'
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context
        
        mock_socket = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_socket
        
        # Mock x509 certificate parsing
        with patch('app.x509.load_der_x509_certificate', return_value=mock_cert_data):
            result = check_ssl_certificate('example.com')  # Different from cert domain
        
        assert result['deployed'] is True
        assert result['reachable'] is True
        assert result['certificate_match'] is False  # Domain doesn't match
        assert 'different.com' in result['certificate_domains']
