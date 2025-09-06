"""
Prometheus metrics module for CertMate.

This module provides OpenMetrics/Prometheus-compatible metrics for monitoring
SSL certificate infrastructure health and status.
"""

import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Prometheus client library
try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Info, 
        generate_latest, CONTENT_TYPE_LATEST,
        CollectorRegistry, REGISTRY
    )
    PROMETHEUS_AVAILABLE = True
    logger.info("Prometheus client library loaded successfully")
except ImportError as e:
    logger.warning(f"Prometheus client library not available: {e}")
    PROMETHEUS_AVAILABLE = False
    # Mock classes for when prometheus_client is not available
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        
    class Info:
        def __init__(self, *args, **kwargs): pass
        def info(self, *args, **kwargs): pass
        
    def generate_latest(*args, **kwargs):
        return "# Prometheus client not available\n"
        
    CONTENT_TYPE_LATEST = "text/plain"
except Exception as e:
    logger.error(f"Unexpected error loading Prometheus client: {e}")
    PROMETHEUS_AVAILABLE = False
    # Use the same mock classes
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        
    class Info:
        def __init__(self, *args, **kwargs): pass
        def info(self, *args, **kwargs): pass
        
    def generate_latest(*args, **kwargs):
        return "# Prometheus client not available\n"
        
    CONTENT_TYPE_LATEST = "text/plain"

# =============================================
# METRICS DEFINITIONS
# =============================================

# Application info
certmate_info = Info(
    'certmate_build_info', 
    'CertMate application build information',
    ['version', 'python_version']
)

# Domain and certificate counts
total_domains = Gauge(
    'certmate_domains_total',
    'Total number of managed domains'
)

total_certificates = Gauge(
    'certmate_certificates_total',
    'Total number of certificates'
)

certificates_by_provider = Gauge(
    'certmate_certificates_by_provider',
    'Number of certificates by DNS provider',
    ['provider']
)

certificates_by_status = Gauge(
    'certmate_certificates_by_status',
    'Number of certificates by status',
    ['status']
)

# Certificate expiration metrics
certificate_expiry_days = Gauge(
    'certmate_certificate_expiry_days',
    'Days until certificate expiry',
    ['domain', 'dns_provider']
)

certificate_last_renewal = Gauge(
    'certmate_certificate_last_renewal_timestamp',
    'Unix timestamp of last successful renewal',
    ['domain', 'dns_provider']
)

certificate_next_renewal = Gauge(
    'certmate_certificate_next_renewal_timestamp',
    'Unix timestamp of next scheduled renewal',
    ['domain', 'dns_provider']
)

# Certificate operations metrics
certificate_requests_total = Counter(
    'certmate_certificate_requests_total',
    'Total number of certificate requests',
    ['domain', 'dns_provider', 'status']
)

certificate_renewals_total = Counter(
    'certmate_certificate_renewals_total',
    'Total number of certificate renewal attempts',
    ['domain', 'dns_provider', 'status']
)

certificate_creation_duration = Histogram(
    'certmate_certificate_creation_duration_seconds',
    'Time spent creating certificates',
    ['dns_provider'],
    buckets=[30, 60, 120, 300, 600, 1200, 3600]
)

certificate_renewal_duration = Histogram(
    'certmate_certificate_renewal_duration_seconds',
    'Time spent renewing certificates',
    ['dns_provider'],
    buckets=[30, 60, 120, 300, 600, 1200, 3600]
)

# ACME/Let's Encrypt metrics
acme_errors_total = Counter(
    'certmate_acme_errors_total',
    'Total number of ACME errors encountered',
    ['error_type', 'domain', 'dns_provider']
)

acme_rate_limit_hits = Counter(
    'certmate_acme_rate_limit_hits_total',
    'Number of times ACME rate limits were hit',
    ['limit_type', 'dns_provider']
)

# DNS provider metrics
dns_provider_accounts = Gauge(
    'certmate_dns_provider_accounts',
    'Number of configured accounts per DNS provider',
    ['provider']
)

dns_provider_api_calls = Counter(
    'certmate_dns_provider_api_calls_total',
    'Total DNS provider API calls',
    ['provider', 'operation', 'status']
)

# System health metrics
application_uptime = Gauge(
    'certmate_application_uptime_seconds',
    'Application uptime in seconds'
)

background_job_last_run = Gauge(
    'certmate_background_job_last_run_timestamp',
    'Unix timestamp of last background job execution',
    ['job_type']
)

background_job_duration = Histogram(
    'certmate_background_job_duration_seconds',
    'Time spent executing background jobs',
    ['job_type'],
    buckets=[1, 5, 15, 30, 60, 300, 600]
)

# Cache metrics  
cache_hits_total = Counter(
    'certmate_cache_hits_total',
    'Total number of cache hits'
)

cache_misses_total = Counter(
    'certmate_cache_misses_total', 
    'Total number of cache misses'
)

cache_entries = Gauge(
    'certmate_cache_entries',
    'Number of entries in cache'
)

# =============================================
# METRICS COLLECTION FUNCTIONS
# =============================================

class CertMateMetricsCollector:
    """Main metrics collector for CertMate application."""
    
    def __init__(self):
        self.start_time = time.time()
        self.last_collection = 0
        self.collection_interval = 30  # Collect metrics every 30 seconds
        
        # Set application info
        if PROMETHEUS_AVAILABLE:
            import sys
            try:
                # Try the newer way first
                certmate_info.info({
                    'version': '1.2.1',
                    'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                })
            except AttributeError as e:
                # Fall back to older prometheus_client API or use Gauge
                logger.debug(f"Info metric not supported in this prometheus_client version: {e}")
                try:
                    global application_version
                    application_version = Gauge('certmate_version_info', 'CertMate version information', ['version', 'python_version'])
                    application_version.labels(
                        version='1.2.1',
                        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                    ).set(1)
                except Exception as fallback_error:
                    logger.debug(f"Could not set version metric: {fallback_error}")
            except Exception as e:
                logger.debug(f"Could not set application info metric: {e}")
    
    def should_collect(self) -> bool:
        """Check if it's time to collect metrics."""
        return time.time() - self.last_collection >= self.collection_interval
    
    def collect_all_metrics(self, app_context=None):
        """Collect all metrics from the application state."""
        if not self.should_collect():
            return
            
        try:
            # Update uptime
            uptime = time.time() - self.start_time
            application_uptime.set(uptime)
            
            # Only collect other metrics if we have app context
            if app_context:
                self._collect_certificate_metrics(app_context)
                self._collect_dns_provider_metrics(app_context)
                self._collect_cache_metrics(app_context)
            
            self.last_collection = time.time()
            logger.debug("Metrics collection completed")
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
    
    def _collect_certificate_metrics(self, app_context):
        """Collect certificate-related metrics."""
        try:
            # Import here to avoid circular imports
            from . import utils
            
            settings = app_context.get('settings', {})
            cert_dir = app_context.get('cert_dir')
            get_certificate_info = app_context.get('get_certificate_info')
            
            if not all([settings, cert_dir, get_certificate_info]):
                return
                
            # Get configurable renewal threshold (default 30 days for backward compatibility)
            renewal_threshold_days = settings.get('renewal_threshold_days', 30)
                
            domains = settings.get('domains', [])
            total_domains.set(len(domains))
            
            # Collect certificate metrics
            cert_count = 0
            provider_counts = {}
            status_counts = {
                'valid': 0,
                'expiring_soon': 0,
                'expired': 0,
                'missing': 0,
                'renewal_failed': 0
            }
            
            # Check existing certificate directories
            cert_dirs = []
            if cert_dir and cert_dir.exists():
                cert_dirs = [d for d in cert_dir.iterdir() if d.is_dir()]
            
            # Process all domains (from settings and disk)
            all_domains = set()
            
            # Add domains from settings
            for domain_config in domains:
                domain_name = domain_config.get('domain') if isinstance(domain_config, dict) else domain_config
                if domain_name:
                    all_domains.add(domain_name)
            
            # Add domains from disk
            for cert_dir_path in cert_dirs:
                all_domains.add(cert_dir_path.name)
            
            for domain in all_domains:
                if not domain:
                    continue
                    
                cert_info = get_certificate_info(domain)
                if not cert_info:
                    continue
                
                dns_provider = cert_info.get('dns_provider', 'unknown')
                
                # Count by provider
                provider_counts[dns_provider] = provider_counts.get(dns_provider, 0) + 1
                
                if cert_info.get('exists', False):
                    cert_count += 1
                    
                    # Determine certificate status
                    days_left = cert_info.get('days_left', 0)
                    if days_left is None:
                        status = 'missing'
                    elif days_left < 0:
                        status = 'expired'
                    elif days_left <= renewal_threshold_days:
                        status = 'expiring_soon'
                    else:
                        status = 'valid'
                    
                    status_counts[status] += 1
                    
                    # Set individual certificate metrics
                    if days_left is not None:
                        certificate_expiry_days.labels(
                            domain=domain, 
                            dns_provider=dns_provider
                        ).set(max(0, days_left))
                    
                    # Set renewal timestamps (mock data for now)
                    # In a real implementation, you'd track these from actual renewal events
                    certificate_last_renewal.labels(
                        domain=domain,
                        dns_provider=dns_provider
                    ).set(time.time() - (renewal_threshold_days - days_left) * 24 * 3600 if days_left is not None else 0)
                    
                    certificate_next_renewal.labels(
                        domain=domain,
                        dns_provider=dns_provider
                    ).set(time.time() + (days_left - renewal_threshold_days) * 24 * 3600 if days_left is not None and days_left > renewal_threshold_days else time.time())
                    
                else:
                    status_counts['missing'] += 1
            
            # Set aggregate metrics
            total_certificates.set(cert_count)
            
            # Set provider counts
            for provider, count in provider_counts.items():
                certificates_by_provider.labels(provider=provider).set(count)
            
            # Set status counts
            for status, count in status_counts.items():
                certificates_by_status.labels(status=status).set(count)
                
        except Exception as e:
            logger.error(f"Error collecting certificate metrics: {e}")
    
    def _collect_dns_provider_metrics(self, app_context):
        """Collect DNS provider-related metrics."""
        try:
            settings = app_context.get('settings', {})
            dns_providers = settings.get('dns_providers', {})
            
            for provider, accounts in dns_providers.items():
                account_count = 0
                if isinstance(accounts, dict):
                    account_count = len(accounts) if accounts else 0
                elif accounts:  # Non-empty value indicates configured
                    account_count = 1
                    
                dns_provider_accounts.labels(provider=provider).set(account_count)
                
        except Exception as e:
            logger.error(f"Error collecting DNS provider metrics: {e}")
    
    def _collect_cache_metrics(self, app_context):
        """Collect cache-related metrics."""
        try:
            cache = app_context.get('cache')
            if cache and hasattr(cache, 'get_stats'):
                stats = cache.get_stats()
                cache_entries.set(stats.get('total_entries', 0))
                
        except Exception as e:
            logger.error(f"Error collecting cache metrics: {e}")
    
    def record_certificate_request(self, domain: str, dns_provider: str, success: bool):
        """Record a certificate request."""
        status = 'success' if success else 'failure'
        certificate_requests_total.labels(
            domain=domain,
            dns_provider=dns_provider, 
            status=status
        ).inc()
    
    def record_certificate_renewal(self, domain: str, dns_provider: str, success: bool):
        """Record a certificate renewal."""
        status = 'success' if success else 'failure'
        certificate_renewals_total.labels(
            domain=domain,
            dns_provider=dns_provider,
            status=status
        ).inc()
    
    def record_certificate_creation_time(self, dns_provider: str, duration: float):
        """Record certificate creation duration."""
        certificate_creation_duration.labels(dns_provider=dns_provider).observe(duration)
    
    def record_certificate_renewal_time(self, dns_provider: str, duration: float):
        """Record certificate renewal duration."""
        certificate_renewal_duration.labels(dns_provider=dns_provider).observe(duration)
    
    def record_acme_error(self, error_type: str, domain: str, dns_provider: str):
        """Record an ACME error."""
        acme_errors_total.labels(
            error_type=error_type,
            domain=domain,
            dns_provider=dns_provider
        ).inc()
    
    def record_rate_limit_hit(self, limit_type: str, dns_provider: str):
        """Record a rate limit hit."""
        acme_rate_limit_hits.labels(
            limit_type=limit_type,
            dns_provider=dns_provider
        ).inc()
    
    def record_dns_api_call(self, provider: str, operation: str, success: bool):
        """Record a DNS provider API call."""
        status = 'success' if success else 'failure'
        dns_provider_api_calls.labels(
            provider=provider,
            operation=operation,
            status=status
        ).inc()
    
    def record_background_job(self, job_type: str, duration: float):
        """Record background job execution."""
        background_job_last_run.labels(job_type=job_type).set(time.time())
        background_job_duration.labels(job_type=job_type).observe(duration)
    
    def record_cache_hit(self):
        """Record a cache hit."""
        cache_hits_total.inc()
    
    def record_cache_miss(self):
        """Record a cache miss."""
        cache_misses_total.inc()

# =============================================
# GLOBAL METRICS INSTANCE
# =============================================

# Global metrics collector instance
metrics_collector = CertMateMetricsCollector()

# =============================================
# FLASK INTEGRATION FUNCTIONS
# =============================================

def generate_metrics_response(app_context=None):
    """Generate Prometheus metrics response."""
    if not PROMETHEUS_AVAILABLE:
        return (
            "# Prometheus client library not available\n"
            "# Install with: pip install prometheus_client\n",
            503,
            {'Content-Type': 'text/plain'}
        )
    
    try:
        # Collect latest metrics
        metrics_collector.collect_all_metrics(app_context)
        
        # Generate Prometheus format
        metrics_data = generate_latest()
        
        return (
            metrics_data,
            200,
            {'Content-Type': CONTENT_TYPE_LATEST}
        )
        
    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return (
            f"# Error generating metrics: {e}\n",
            500,
            {'Content-Type': 'text/plain'}
        )

def get_metrics_summary():
    """Get a human-readable summary of key metrics."""
    try:
        if not PROMETHEUS_AVAILABLE:
            return {"error": "Prometheus client library not available"}
        
        # This would return a simplified view for the web UI
        # Implementation would depend on accessing the metric values
        return {
            "prometheus_available": True,
            "metrics_endpoint": "/metrics",
            "last_collection": metrics_collector.last_collection,
            "uptime_seconds": time.time() - metrics_collector.start_time,
        }
        
    except Exception as e:
        logger.error(f"Error getting metrics summary: {e}")
        return {"error": str(e)}

# =============================================
# UTILITY FUNCTIONS  
# =============================================

def is_prometheus_available() -> bool:
    """Check if Prometheus client is available."""
    return PROMETHEUS_AVAILABLE

def get_metrics_collector():
    """Get the global metrics collector instance."""
    return metrics_collector
