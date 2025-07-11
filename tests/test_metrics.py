"""
Test suite for CertMate metrics functionality.

Tests the Prometheus metrics integration, including:
- Metrics collection and generation
- Certificate-related metrics
- DNS provider metrics
- ACME error tracking
- API endpoints
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import os

# Test imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.metrics import (
    CertMateMetricsCollector, 
    generate_metrics_response,
    get_metrics_summary,
    is_prometheus_available,
    PROMETHEUS_AVAILABLE
)

class TestMetricsAvailability:
    """Test metrics availability detection."""
    
    def test_prometheus_availability_detection(self):
        """Test that prometheus availability is correctly detected."""
        # This should return True if prometheus_client is installed
        assert isinstance(is_prometheus_available(), bool)
        assert isinstance(PROMETHEUS_AVAILABLE, bool)
    
    def test_metrics_summary_structure(self):
        """Test metrics summary returns expected structure."""
        summary = get_metrics_summary()
        assert isinstance(summary, dict)
        
        if PROMETHEUS_AVAILABLE:
            assert 'prometheus_available' in summary
            assert summary['prometheus_available'] is True
            assert 'metrics_endpoint' in summary
            assert 'last_collection' in summary
            assert 'uptime_seconds' in summary
        else:
            assert 'error' in summary


class TestMetricsCollector:
    """Test the CertMateMetricsCollector class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertMateMetricsCollector()
    
    def test_collector_initialization(self):
        """Test metrics collector initializes correctly."""
        assert hasattr(self.collector, 'start_time')
        assert hasattr(self.collector, 'last_collection')
        assert hasattr(self.collector, 'collection_interval')
        assert self.collector.collection_interval == 30
        assert isinstance(self.collector.start_time, float)
    
    def test_should_collect_timing(self):
        """Test collection timing logic."""
        # Fresh collector should collect
        fresh_collector = CertMateMetricsCollector()
        fresh_collector.last_collection = 0
        assert fresh_collector.should_collect() is True
        
        # Recently collected should not collect
        fresh_collector.last_collection = time.time()
        assert fresh_collector.should_collect() is False
    
    def test_record_certificate_request(self):
        """Test certificate request recording."""
        # These should not raise exceptions
        self.collector.record_certificate_request("example.com", "cloudflare", True)
        self.collector.record_certificate_request("test.com", "route53", False)
        
        # Test with different providers
        providers = ["azure", "google", "digitalocean", "unknown"]
        for provider in providers:
            self.collector.record_certificate_request(f"test-{provider}.com", provider, True)
    
    def test_record_certificate_renewal(self):
        """Test certificate renewal recording."""
        self.collector.record_certificate_renewal("example.com", "cloudflare", True)
        self.collector.record_certificate_renewal("failed.com", "route53", False)
    
    def test_record_acme_errors(self):
        """Test ACME error recording."""
        error_types = ["authorization_failed", "challenge_failed", "rate_limit", "exception"]
        
        for error_type in error_types:
            self.collector.record_acme_error(error_type, "example.com", "cloudflare")
    
    def test_record_rate_limit_hits(self):
        """Test rate limit recording."""
        limit_types = ["certificate_creation", "certificate_renewal", "dns_challenge"]
        
        for limit_type in limit_types:
            self.collector.record_rate_limit_hit(limit_type, "cloudflare")
    
    def test_record_certificate_creation_time(self):
        """Test certificate creation time recording."""
        durations = [30.5, 120.0, 300.7, 600.2]
        
        for duration in durations:
            self.collector.record_certificate_creation_time("cloudflare", duration)
    
    def test_record_certificate_renewal_time(self):
        """Test certificate renewal time recording."""
        self.collector.record_certificate_renewal_time("route53", 45.3)
        self.collector.record_certificate_renewal_time("azure", 180.8)
    
    def test_record_dns_api_call(self):
        """Test DNS API call recording."""
        operations = ["create_record", "delete_record", "update_record", "list_records"]
        
        for operation in operations:
            self.collector.record_dns_api_call("cloudflare", operation, True)
            self.collector.record_dns_api_call("route53", operation, False)
    
    def test_record_background_job(self):
        """Test background job recording."""
        job_types = ["renewal_check", "cleanup", "backup"]
        
        for job_type in job_types:
            self.collector.record_background_job(job_type, 15.2)
    
    def test_record_cache_operations(self):
        """Test cache operation recording."""
        self.collector.record_cache_hit()
        self.collector.record_cache_miss()


class TestMetricsCollection:
    """Test metrics collection with mock data."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertMateMetricsCollector()
        
        # Create temporary directories for testing
        self.temp_dir = Path(tempfile.mkdtemp())
        self.cert_dir = self.temp_dir / "certificates"
        self.cert_dir.mkdir()
        
        # Create mock certificate directories
        (self.cert_dir / "example.com").mkdir()
        (self.cert_dir / "test.com").mkdir()
        (self.cert_dir / "expired.com").mkdir()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_mock_app_context(self):
        """Create mock application context for testing."""
        def mock_get_certificate_info(domain):
            """Mock certificate info function."""
            cert_data = {
                "example.com": {
                    'domain': 'example.com',
                    'exists': True,
                    'expiry_date': '2025-08-15 12:00:00',
                    'days_left': 35,
                    'needs_renewal': False,
                    'dns_provider': 'cloudflare'
                },
                "test.com": {
                    'domain': 'test.com',
                    'exists': True,
                    'expiry_date': '2025-07-25 12:00:00',
                    'days_left': 14,
                    'needs_renewal': True,
                    'dns_provider': 'route53'
                },
                "expired.com": {
                    'domain': 'expired.com',
                    'exists': True,
                    'expiry_date': '2025-07-01 12:00:00',
                    'days_left': -10,
                    'needs_renewal': True,
                    'dns_provider': 'azure'
                }
            }
            return cert_data.get(domain)
        
        mock_settings = {
            'domains': [
                {'domain': 'example.com', 'dns_provider': 'cloudflare'},
                {'domain': 'test.com', 'dns_provider': 'route53'},
                'expired.com'  # Test old format
            ],
            'dns_providers': {
                'cloudflare': {
                    'production': {'api_token': 'token1'},
                    'staging': {'api_token': 'token2'}
                },
                'route53': {
                    'default': {
                        'access_key_id': 'key1',
                        'secret_access_key': 'secret1'
                    }
                },
                'azure': {
                    'main': {
                        'subscription_id': 'sub1',
                        'resource_group': 'rg1',
                        'tenant_id': 'tenant1',
                        'client_id': 'client1',
                        'client_secret': 'secret1'
                    }
                }
            }
        }
        
        mock_cache = Mock()
        mock_cache.get_stats.return_value = {
            'total_entries': 5,
            'hit_ratio': 0.85
        }
        
        return {
            'settings': mock_settings,
            'cert_dir': self.cert_dir,
            'get_certificate_info': mock_get_certificate_info,
            'cache': mock_cache
        }
    
    def test_collect_certificate_metrics(self):
        """Test certificate metrics collection."""
        app_context = self.create_mock_app_context()
        
        # Force collection by setting last_collection to 0
        self.collector.last_collection = 0
        
        # This should not raise exceptions
        self.collector.collect_all_metrics(app_context)
        
        # Verify collection timestamp was updated
        assert self.collector.last_collection > 0
    
    def test_collect_dns_provider_metrics(self):
        """Test DNS provider metrics collection."""
        app_context = self.create_mock_app_context()
        
        # Test the private method directly
        self.collector._collect_dns_provider_metrics(app_context)
        
        # Should not raise exceptions
    
    def test_collect_cache_metrics(self):
        """Test cache metrics collection."""
        app_context = self.create_mock_app_context()
        
        # Test the private method directly
        self.collector._collect_cache_metrics(app_context)
        
        # Should not raise exceptions
    
    def test_collect_all_metrics_without_context(self):
        """Test metrics collection without app context."""
        self.collector.last_collection = 0
        
        # Should not raise exceptions
        self.collector.collect_all_metrics()
        
        # Should still update uptime
        assert self.collector.last_collection > 0


class TestMetricsResponse:
    """Test metrics response generation."""
    
    def test_generate_metrics_response_without_prometheus(self):
        """Test metrics response when Prometheus is not available."""
        if not PROMETHEUS_AVAILABLE:
            response_data, status_code, headers = generate_metrics_response()
            
            assert status_code == 503
            assert 'Content-Type' in headers
            assert 'not available' in response_data
    
    def test_generate_metrics_response_with_prometheus(self):
        """Test metrics response when Prometheus is available."""
        if PROMETHEUS_AVAILABLE:
            app_context = {
                'settings': {'domains': [], 'dns_providers': {}},
                'cert_dir': Path('/tmp'),
                'get_certificate_info': lambda x: None,
                'cache': Mock()
            }
            
            response_data, status_code, headers = generate_metrics_response(app_context)
            
            assert status_code == 200
            assert headers['Content-Type'] == 'text/plain; version=0.0.4; charset=utf-8'
            assert isinstance(response_data, (str, bytes))
    
    def test_generate_metrics_response_with_exception(self):
        """Test metrics response generation with exceptions."""
        # Test with invalid app context
        with patch('modules.metrics.generate_latest', side_effect=Exception("Test error")):
            if PROMETHEUS_AVAILABLE:
                response_data, status_code, headers = generate_metrics_response({'invalid': 'context'})
                
                assert status_code == 500
                assert 'Error generating metrics' in response_data


class TestMetricsIntegration:
    """Test metrics integration with Flask app."""
    
    @pytest.fixture
    def app_client(self):
        """Create a test Flask app client."""
        # Import here to avoid circular imports
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        from app import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    def test_metrics_endpoint_availability(self, app_client):
        """Test that /metrics endpoint is available."""
        response = app_client.get('/metrics')
        
        # Should return either metrics data or unavailable message
        assert response.status_code in [200, 503]
        
        if response.status_code == 200:
            # Should return prometheus format
            assert 'text/plain' in response.content_type
        else:
            # Should return unavailable message
            assert b'not available' in response.data
    
    def test_api_metrics_endpoint(self, app_client):
        """Test that /api/metrics endpoint is available."""
        response = app_client.get('/api/metrics')
        
        assert response.status_code == 200
        assert response.content_type == 'application/json'
        
        data = json.loads(response.data)
        assert 'metrics_available' in data
        assert 'prometheus_endpoint' in data
        assert 'api_endpoint' in data
        assert 'summary' in data


class TestMetricsContentValidation:
    """Test that metrics contain expected content."""
    
    def test_expected_metric_names(self):
        """Test that expected metric names are present."""
        if not PROMETHEUS_AVAILABLE:
            pytest.skip("Prometheus client not available")
        
        app_context = {
            'settings': {
                'domains': [{'domain': 'test.com', 'dns_provider': 'cloudflare'}],
                'dns_providers': {
                    'cloudflare': {'default': {'api_token': 'test'}}
                }
            },
            'cert_dir': Path('/tmp'),
            'get_certificate_info': lambda x: {
                'domain': x,
                'exists': True,
                'days_left': 30,
                'dns_provider': 'cloudflare'
            },
            'cache': Mock()
        }
        
        response_data, status_code, headers = generate_metrics_response(app_context)
        
        if status_code == 200:
            # Convert bytes to string if necessary
            if isinstance(response_data, bytes):
                response_data = response_data.decode('utf-8')
            
            # Check for expected metric names
            expected_metrics = [
                'certmate_domains_total',
                'certmate_certificates_total',
                'certmate_certificates_by_provider',
                'certmate_certificates_by_status',
                'certmate_certificate_expiry_days',
                'certmate_certificate_requests_total',
                'certmate_acme_errors_total',
                'certmate_application_uptime_seconds'
            ]
            
            for metric in expected_metrics:
                assert metric in response_data, f"Metric {metric} not found in response"


class TestMetricsErrorHandling:
    """Test error handling in metrics collection."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertMateMetricsCollector()
    
    def test_collection_with_invalid_app_context(self):
        """Test metrics collection with invalid app context."""
        invalid_contexts = [
            None,
            {},
            {'settings': None},
            {'settings': {}, 'cert_dir': None},
            {'settings': {}, 'cert_dir': Path('/nonexistent'), 'get_certificate_info': None}
        ]
        
        for context in invalid_contexts:
            # Should not raise exceptions
            self.collector.collect_all_metrics(context)
    
    def test_collection_with_exception_in_certificate_info(self):
        """Test handling of exceptions in certificate info retrieval."""
        def failing_cert_info(domain):
            raise Exception("Certificate info failed")
        
        app_context = {
            'settings': {'domains': ['test.com'], 'dns_providers': {}},
            'cert_dir': Path('/tmp'),
            'get_certificate_info': failing_cert_info,
            'cache': Mock()
        }
        
        # Should not raise exceptions
        self.collector._collect_certificate_metrics(app_context)
    
    def test_record_methods_with_invalid_inputs(self):
        """Test record methods with invalid inputs."""
        # Test with None values
        self.collector.record_certificate_request(None, None, True)
        self.collector.record_acme_error(None, None, None)
        
        # Test with empty strings
        self.collector.record_certificate_request("", "", False)
        self.collector.record_dns_api_call("", "", True)
        
        # Test with special characters
        self.collector.record_certificate_request("test.com", "provider-with-dashes", True)
        self.collector.record_acme_error("error_type_with_underscores", "test.com", "provider")


class TestMetricsPerformance:
    """Test metrics performance characteristics."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertMateMetricsCollector()
    
    def test_collection_performance(self):
        """Test that metrics collection completes within reasonable time."""
        # Create a large mock context
        large_domains = [f"domain-{i}.com" for i in range(100)]
        
        def mock_cert_info(domain):
            return {
                'domain': domain,
                'exists': True,
                'days_left': 30,
                'dns_provider': 'cloudflare'
            }
        
        app_context = {
            'settings': {
                'domains': large_domains,
                'dns_providers': {
                    'cloudflare': {'default': {'api_token': 'test'}}
                }
            },
            'cert_dir': Path('/tmp'),
            'get_certificate_info': mock_cert_info,
            'cache': Mock()
        }
        
        # Force collection
        self.collector.last_collection = 0
        
        start_time = time.time()
        self.collector.collect_all_metrics(app_context)
        collection_time = time.time() - start_time
        
        # Should complete within 5 seconds even with 100 domains
        assert collection_time < 5.0
    
    def test_record_method_performance(self):
        """Test that record methods are fast."""
        start_time = time.time()
        
        # Record many metrics
        for i in range(1000):
            self.collector.record_certificate_request(f"domain-{i}.com", "cloudflare", True)
            self.collector.record_acme_error("test_error", f"domain-{i}.com", "cloudflare")
        
        record_time = time.time() - start_time
        
        # Should complete quickly
        assert record_time < 1.0


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v'])
