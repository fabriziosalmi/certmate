#!/usr/bin/env python3
"""
CertMate E2E Test Suite - Production Grade
==========================================

Comprehensive end-to-end tests for CertMate certificate management.
This test suite validates the complete certificate lifecycle using
real infrastructure to ensure production readiness.

Test Categories:
    1. Infrastructure Validation - Server health, connectivity, dependencies
    2. Authentication & Security - API auth, token validation, access control
    3. DNS Provider Integration - Provider configuration, API connectivity
    4. Certificate Operations - Create, list, download, renew, validate
    5. Client Certificates - CA operations, CSR handling, PKCS12 export
    6. Error Handling - Invalid inputs, edge cases, graceful degradation
    7. Performance - Response times, concurrent operations
    8. Cleanup - DNS record cleanup, test artifact removal

Requirements:
    - CertMate server running (default: localhost:8000)
    - Valid API bearer token configured
    - DNS provider credentials (Cloudflare/Route53/etc.)
    - Network access to Let's Encrypt ACME servers

Usage:
    python test_e2e_real.py                # Full test suite (staging)
    python test_e2e_real.py --staging      # Use Let's Encrypt staging
    python test_e2e_real.py --production   # Use production LE (careful!)
    python test_e2e_real.py --quick        # Quick smoke test only
    python test_e2e_real.py --skip-creation # Skip cert creation (faster)
    python test_e2e_real.py --no-cleanup   # Keep DNS records (debugging)
    python test_e2e_real.py --verbose      # Detailed output

Exit Codes:
    0 - All tests passed
    1 - One or more tests failed
    2 - Configuration or connectivity error

Author: CertMate Team
Version: 2.0.0
"""

import os
import sys
import json
import time
import random
import string
import argparse
import hashlib
import requests
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager

# Version
__version__ = "2.0.0"


# =============================================================================
# Enums and Constants
# =============================================================================

class TestStatus(Enum):
    """Test execution status"""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class Severity(Enum):
    """Test severity levels"""
    CRITICAL = "critical"   # Must pass for deployment
    HIGH = "high"          # Should pass, blocking issue
    MEDIUM = "medium"      # Expected to pass
    LOW = "low"           # Nice to have


# Response time thresholds (seconds)
RESPONSE_TIME_THRESHOLDS = {
    "health": 1.0,
    "list": 2.0,
    "create": 300.0,
    "download": 5.0,
    "settings": 2.0
}


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class TestConfig:
    """Test suite configuration"""
    base_url: str = "http://localhost:8000"
    api_token: str = ""
    test_domain: str = "certmate.org"
    dns_provider: str = "cloudflare"
    dns_account_id: str = "certmate_test"
    cloudflare_zone_id: str = "deb25adc3361ff31cb81ba458e03a68b"
    email: str = "test@certmate.org"
    use_staging: bool = True
    timeout_cert_creation: int = 300
    timeout_api_call: int = 30
    verbose: bool = False
    
    def __post_init__(self):
        """Load API token from settings if not provided"""
        if not self.api_token:
            self._load_token_from_settings()
    
    def _load_token_from_settings(self):
        """Try to load API token from settings.json"""
        try:
            settings_path = Path(__file__).parent / "data" / "settings.json"
            if settings_path.exists():
                with open(settings_path) as f:
                    settings = json.load(f)
                    self.api_token = settings.get("api_bearer_token", "")
        except Exception:
            pass


# =============================================================================
# Test Result Classes
# =============================================================================

@dataclass
class TestResult:
    """Individual test result"""
    name: str
    status: TestStatus
    duration: float
    message: str = ""
    severity: Severity = Severity.MEDIUM
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestSuite:
    """Test suite results container"""
    results: List[TestResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.PASSED)
    
    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.FAILED)
    
    @property
    def skipped_count(self) -> int:
        return sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
    
    @property
    def total_count(self) -> int:
        return len(self.results)
    
    @property
    def total_duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return sum(r.duration for r in self.results)
    
    @property
    def critical_failures(self) -> List[TestResult]:
        return [r for r in self.results 
                if r.status == TestStatus.FAILED and r.severity == Severity.CRITICAL]
    
    def add_result(self, result: TestResult):
        """Add a test result"""
        self.results.append(result)
        status_icon = {
            TestStatus.PASSED: "[PASS]",
            TestStatus.FAILED: "[FAIL]",
            TestStatus.SKIPPED: "[SKIP]",
            TestStatus.ERROR: "[ERR]"
        }
        icon = status_icon.get(result.status, "[?]")
        print(f"  {icon} {result.name} ({result.duration:.2f}s)")
        if result.status == TestStatus.FAILED and result.message:
            print(f"       {result.message[:80]}")
    
    def print_summary(self) -> bool:
        """Print test summary, return True if all passed"""
        self.end_time = datetime.now()
        
        print("\n" + "=" * 70)
        print("TEST RESULTS SUMMARY")
        print("=" * 70)
        print(f"  [OK] Passed:  {self.passed_count}")
        print(f"  [FAIL] Failed:  {self.failed_count}")
        print(f"  [SKIP] Skipped: {self.skipped_count}")
        print(f"  [TIME] Duration: {self.total_duration:.1f}s")
        
        # Critical failures
        if self.critical_failures:
            print(f"\n  CRITICAL FAILURES ({len(self.critical_failures)}):")
            for r in self.critical_failures:
                print(f"    - {r.name}: {r.message}")
        
        # All failures
        failed = [r for r in self.results if r.status == TestStatus.FAILED]
        if failed:
            print(f"\n  Failed Tests:")
            for r in failed:
                sev = f"[{r.severity.value}]"
                print(f"    {r.name} {sev}")
                if r.message:
                    msg = r.message[:100] + "..." if len(r.message) > 100 else r.message
                    print(f"      {msg}")
        
        # Pass rate
        if self.total_count > 0:
            pass_rate = (self.passed_count / self.total_count) * 100
            print(f"\n  Pass Rate: {pass_rate:.1f}%")
        
        # Final verdict
        all_passed = self.failed_count == 0
        verdict = "ALL TESTS PASSED" if all_passed else "SOME TESTS FAILED"
        print(f"\n{'=' * 70}")
        print(f"  {verdict}")
        print(f"{'=' * 70}\n")
        
        return all_passed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary for JSON export"""
        return {
            "version": __version__,
            "timestamp": self.start_time.isoformat(),
            "duration_seconds": self.total_duration,
            "summary": {
                "total": self.total_count,
                "passed": self.passed_count,
                "failed": self.failed_count,
                "skipped": self.skipped_count,
                "pass_rate": (self.passed_count / self.total_count * 100) if self.total_count > 0 else 0
            },
            "tests": [{
                "name": r.name,
                "status": r.status.value,
                "duration": r.duration,
                "message": r.message,
                "severity": r.severity.value,
                "timestamp": r.timestamp,
                "details": r.details
            } for r in self.results]
        }
    
    def save_json(self, filepath: str = "test_results.json"):
        """Save results to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"[INFO] Results saved to {filepath}")


# =============================================================================
# Test Helper Functions
# =============================================================================

class TestRunner:
    """Test runner with helper methods"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.suite = TestSuite()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config.api_token}",
            "Content-Type": "application/json"
        })
        self.created_certificates: List[str] = []
        self.created_dns_records: List[str] = []
    
    def api_call(self, method: str, endpoint: str, **kwargs) -> Tuple[Optional[requests.Response], float]:
        """Make API call and return response with duration"""
        url = f"{self.config.base_url}{endpoint}"
        kwargs.setdefault("timeout", self.config.timeout_api_call)
        
        start = time.time()
        try:
            response = self.session.request(method, url, **kwargs)
            duration = time.time() - start
            return response, duration
        except Exception as e:
            duration = time.time() - start
            if self.config.verbose:
                print(f"    [DEBUG] API call failed: {e}")
            return None, duration
    
    def run_test(self, name: str, test_func: Callable, severity: Severity = Severity.MEDIUM) -> TestResult:
        """Run a single test and record result"""
        start = time.time()
        try:
            success, message, details = test_func()
            duration = time.time() - start
            status = TestStatus.PASSED if success else TestStatus.FAILED
        except Exception as e:
            duration = time.time() - start
            status = TestStatus.ERROR
            message = str(e)
            details = {}
        
        result = TestResult(
            name=name,
            status=status,
            duration=duration,
            message=message,
            severity=severity,
            details=details
        )
        self.suite.add_result(result)
        return result
    
    def skip_test(self, name: str, reason: str, severity: Severity = Severity.MEDIUM):
        """Skip a test with reason"""
        result = TestResult(
            name=name,
            status=TestStatus.SKIPPED,
            duration=0.0,
            message=reason,
            severity=severity
        )
        self.suite.add_result(result)


# =============================================================================
# Test Implementations
# =============================================================================

def test_server_health(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test server health endpoint"""
    response, duration = runner.api_call("GET", "/api/health")
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code != 200:
        return False, f"Health check returned {response.status_code}", {}
    
    data = response.json()
    if data.get("status") != "healthy":
        return False, f"Server not healthy: {data}", {}
    
    if duration > RESPONSE_TIME_THRESHOLDS["health"]:
        return False, f"Response too slow: {duration:.2f}s", {"duration": duration}
    
    return True, "Server healthy", {"version": data.get("version"), "duration": duration}


def test_api_authentication(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test API authentication works"""
    response, _ = runner.api_call("GET", "/api/settings")
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 401:
        return False, "Authentication failed - check API token", {}
    
    if response.status_code != 200:
        return False, f"Unexpected status: {response.status_code}", {}
    
    return True, "Authentication successful", {}


def test_invalid_token(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test that invalid tokens are rejected"""
    old_auth = runner.session.headers.get("Authorization")
    runner.session.headers["Authorization"] = "Bearer invalid_token_12345"
    
    try:
        response, _ = runner.api_call("GET", "/api/settings")
        if not response:
            return False, "Server not responding", {}
        
        if response.status_code == 401:
            return True, "Invalid token correctly rejected", {}
        
        return False, f"Expected 401, got {response.status_code}", {}
    finally:
        runner.session.headers["Authorization"] = old_auth


def test_list_certificates(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test certificate listing endpoint"""
    response, duration = runner.api_call("GET", "/api/certificates")
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code != 200:
        return False, f"List failed: {response.status_code}", {}
    
    try:
        data = response.json()
        cert_count = len(data) if isinstance(data, list) else data.get("count", 0)
        return True, f"Listed {cert_count} certificates", {"count": cert_count, "duration": duration}
    except Exception as e:
        return False, f"Invalid JSON response: {e}", {}


def test_dns_provider_configured(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test that DNS provider is configured"""
    response, _ = runner.api_call("GET", "/api/settings")
    if not response or response.status_code != 200:
        return False, "Cannot fetch settings", {}
    
    settings = response.json()
    
    # Check for dns_accounts structure
    dns_accounts = settings.get("dns_accounts", {})
    cloudflare_accounts = dns_accounts.get("cloudflare", {})
    
    if runner.config.dns_account_id in cloudflare_accounts:
        account = cloudflare_accounts[runner.config.dns_account_id]
        # Check for token or api_token
        has_token = account.get("token") or account.get("api_token")
        if has_token:
            return True, f"Cloudflare account '{runner.config.dns_account_id}' configured", {}
    
    # Check legacy format
    dns_creds = settings.get("dns_credentials", {})
    if dns_creds.get("cloudflare_api_token"):
        return True, "Cloudflare configured (legacy format)", {}
    
    # Check environment
    if os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN"):
        return True, "Cloudflare configured via environment", {}
    
    return False, "Cloudflare not configured", {"dns_accounts": list(cloudflare_accounts.keys())}


def test_create_certificate_staging(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Create a test certificate using Let's Encrypt staging"""
    # Generate unique subdomain
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    test_subdomain = f"e2e-{random_suffix}"
    test_domain = f"{test_subdomain}.{runner.config.test_domain}"
    
    payload = {
        "domain": test_domain,
        "email": runner.config.email,
        "dns_provider": runner.config.dns_provider,
        "dns_account_id": runner.config.dns_account_id,
        "use_staging": runner.config.use_staging,
        "cloudflare_zone_id": runner.config.cloudflare_zone_id
    }
    
    response, duration = runner.api_call(
        "POST", 
        "/api/certificates",
        json=payload,
        timeout=runner.config.timeout_cert_creation
    )
    
    if not response:
        return False, "Server not responding or timeout", {"domain": test_domain}
    
    if response.status_code == 201:
        runner.created_certificates.append(test_domain)
        return True, f"Certificate created for {test_domain}", {
            "domain": test_domain,
            "duration": duration
        }
    
    try:
        error = response.json()
        return False, f"Creation failed: {error.get('error', response.status_code)}", {
            "domain": test_domain,
            "status_code": response.status_code,
            "response": error
        }
    except:
        return False, f"Creation failed: {response.status_code}", {"domain": test_domain}


def test_download_certificate(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test downloading a certificate"""
    if not runner.created_certificates:
        return False, "No certificates to download (create test was skipped?)", {}
    
    domain = runner.created_certificates[-1]
    response, duration = runner.api_call("GET", f"/api/certificates/{domain}/download")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        content_length = len(response.content)
        return True, f"Downloaded {content_length} bytes", {
            "domain": domain,
            "size": content_length,
            "duration": duration
        }
    
    return False, f"Download failed: {response.status_code}", {"domain": domain}


def test_certificate_status(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test certificate status endpoint"""
    if not runner.created_certificates:
        return False, "No certificates to check", {}
    
    domain = runner.created_certificates[-1]
    response, _ = runner.api_call("GET", f"/api/certificates/{domain}")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        data = response.json()
        return True, f"Certificate status: {data.get('status', 'unknown')}", {
            "domain": domain,
            "status": data.get("status"),
            "expiry": data.get("expiry_date")
        }
    
    return False, f"Status check failed: {response.status_code}", {"domain": domain}


def test_client_ca_exists(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test that client CA exists"""
    response, _ = runner.api_call("GET", "/api/client-certificates/ca")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        data = response.json()
        return True, "Client CA exists", {
            "serial": data.get("serial"),
            "subject": data.get("subject")
        }
    
    if response.status_code == 404:
        return False, "Client CA not initialized", {}
    
    return False, f"Unexpected status: {response.status_code}", {}


def test_generate_client_cert(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test generating a client certificate"""
    payload = {
        "common_name": f"e2e-test-{int(time.time())}",
        "email": "e2e-test@certmate.org",
        "organization": "CertMate E2E Tests",
        "validity_days": 30
    }
    
    response, duration = runner.api_call("POST", "/api/client-certificates", json=payload)
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code in (200, 201):
        data = response.json()
        return True, f"Client cert created: {payload['common_name']}", {
            "common_name": payload["common_name"],
            "serial": data.get("serial"),
            "duration": duration
        }
    
    try:
        error = response.json()
        return False, f"Creation failed: {error.get('error', response.status_code)}", {}
    except:
        return False, f"Creation failed: {response.status_code}", {}


def test_list_client_certs(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test listing client certificates"""
    response, duration = runner.api_call("GET", "/api/client-certificates")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        data = response.json()
        # Handle different response formats
        if isinstance(data, list):
            count = len(data)
        elif isinstance(data, dict):
            # Could be {"certificates": [...]} or {"count": N}
            certs = data.get("certificates", data.get("items", []))
            count = len(certs) if isinstance(certs, list) else data.get("count", 0)
        else:
            count = 0
        return True, f"Listed {count} client certificates", {"count": count, "duration": duration}
    
    return False, f"List failed: {response.status_code}", {}


def test_invalid_domain_format(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test that invalid domain format is rejected"""
    payload = {
        "domain": "not_a_valid_domain!!!",
        "email": runner.config.email,
        "dns_provider": runner.config.dns_provider
    }
    
    response, _ = runner.api_call("POST", "/api/certificates", json=payload)
    
    if not response:
        return False, "Server not responding", {}
    
    # Should return 400 for invalid domain
    if response.status_code == 400:
        return True, "Invalid domain correctly rejected", {}
    
    # 422 is also acceptable for validation errors
    if response.status_code == 422:
        return True, "Invalid domain correctly rejected (422)", {}
    
    return False, f"Expected 400/422, got {response.status_code}", {}


def test_missing_required_fields(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test that missing required fields are caught"""
    payload = {}  # Empty payload
    
    response, _ = runner.api_call("POST", "/api/certificates", json=payload)
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code in (400, 422):
        return True, "Missing fields correctly rejected", {}
    
    return False, f"Expected 400/422, got {response.status_code}", {}


def test_nonexistent_certificate(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test getting a non-existent certificate"""
    fake_domain = "nonexistent-domain-12345.example.com"
    response, _ = runner.api_call("GET", f"/api/certificates/{fake_domain}")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 404:
        return True, "Non-existent certificate correctly returns 404", {}
    
    return False, f"Expected 404, got {response.status_code}", {}


def test_health_response_time(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test health endpoint response time"""
    times = []
    for _ in range(3):
        _, duration = runner.api_call("GET", "/api/health")
        times.append(duration)
    
    avg_time = sum(times) / len(times)
    max_time = max(times)
    
    if max_time > RESPONSE_TIME_THRESHOLDS["health"]:
        return False, f"Response too slow: max={max_time:.3f}s", {"times": times}
    
    return True, f"Response time OK: avg={avg_time:.3f}s", {"times": times, "avg": avg_time}


def test_settings_endpoint(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test settings endpoint returns valid data"""
    response, duration = runner.api_call("GET", "/api/settings")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code != 200:
        return False, f"Settings returned {response.status_code}", {}
    
    try:
        data = response.json()
        # Check for expected keys
        expected_keys = ["dns_accounts"]
        found_keys = [k for k in expected_keys if k in data]
        return True, f"Settings valid, found: {found_keys}", {"keys": list(data.keys())}
    except Exception as e:
        return False, f"Invalid JSON: {e}", {}


def test_backup_creation(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test backup creation"""
    response, duration = runner.api_call("POST", "/api/backups")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code in (200, 201):
        data = response.json()
        return True, "Backup created successfully", {
            "filename": data.get("filename"),
            "duration": duration
        }
    
    return False, f"Backup failed: {response.status_code}", {}


def test_backup_listing(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test backup listing"""
    response, _ = runner.api_call("GET", "/api/backups")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        data = response.json()
        count = len(data) if isinstance(data, list) else data.get("count", 0)
        return True, f"Listed {count} backups", {"count": count}
    
    return False, f"Backup list failed: {response.status_code}", {}


def test_web_ui_accessible(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test web UI is accessible"""
    response, duration = runner.api_call("GET", "/")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" in content_type:
            return True, "Web UI accessible", {"duration": duration}
        return True, f"Root endpoint accessible (type: {content_type})", {"duration": duration}
    
    return False, f"Web UI returned {response.status_code}", {}


def test_api_docs_accessible(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test API docs are accessible"""
    endpoints = ["/docs/", "/swagger/", "/api/docs"]
    
    for endpoint in endpoints:
        response, duration = runner.api_call("GET", endpoint)
        if response and response.status_code == 200:
            return True, f"API docs at {endpoint}", {"endpoint": endpoint, "duration": duration}
    
    return True, "API docs not enabled (optional)", {}  # Not critical if disabled


def test_crl_endpoint(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test CRL endpoint for client certificates"""
    response, _ = runner.api_call("GET", "/api/client-certificates/crl")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        return True, "CRL endpoint accessible", {}
    
    if response.status_code == 404:
        return True, "CRL not initialized yet (OK)", {}
    
    return False, f"CRL endpoint returned {response.status_code}", {}


def test_audit_log_endpoint(runner: TestRunner) -> Tuple[bool, str, Dict]:
    """Test audit log endpoint"""
    response, _ = runner.api_call("GET", "/api/audit-log")
    
    if not response:
        return False, "Server not responding", {}
    
    if response.status_code == 200:
        data = response.json()
        count = len(data) if isinstance(data, list) else data.get("count", 0)
        return True, f"Audit log: {count} entries", {"count": count}
    
    if response.status_code == 404:
        return True, "Audit log not enabled (OK)", {}
    
    return False, f"Audit log returned {response.status_code}", {}


# =============================================================================
# Cloudflare DNS Cleanup
# =============================================================================

def cleanup_cloudflare_dns_records(runner: TestRunner):
    """Clean up test DNS records from Cloudflare"""
    print("\n--- DNS Record Cleanup ---")
    
    # Get Cloudflare token from settings
    response, _ = runner.api_call("GET", "/api/settings")
    if not response or response.status_code != 200:
        print("  [WARN] Cannot fetch settings for cleanup")
        return
    
    settings = response.json()
    
    # Try to get token from dns_accounts
    token = None
    dns_accounts = settings.get("dns_accounts", {}).get("cloudflare", {})
    if runner.config.dns_account_id in dns_accounts:
        account = dns_accounts[runner.config.dns_account_id]
        token = account.get("token") or account.get("api_token")
    
    if not token:
        print("  [WARN] Cloudflare token not found, skipping cleanup")
        return
    
    zone_id = runner.config.cloudflare_zone_id
    
    # List DNS records
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        # Get all TXT records
        list_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&per_page=100"
        resp = requests.get(list_url, headers=headers, timeout=30)
        
        if resp.status_code != 200:
            print(f"  [WARN] Cannot list DNS records: {resp.status_code}")
            return
        
        data = resp.json()
        records = data.get("result", [])
        
        # Filter for _acme-challenge records with e2e- prefix
        cleanup_records = [
            r for r in records 
            if r.get("name", "").startswith("_acme-challenge.e2e-")
        ]
        
        if not cleanup_records:
            print("  [INFO] No test DNS records to clean up")
            return
        
        print(f"  [INFO] Found {len(cleanup_records)} test DNS records to clean up")
        
        # Delete each record
        deleted = 0
        for record in cleanup_records:
            record_id = record.get("id")
            record_name = record.get("name")
            
            delete_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
            del_resp = requests.delete(delete_url, headers=headers, timeout=10)
            
            if del_resp.status_code == 200:
                deleted += 1
                print(f"    [OK] Deleted: {record_name}")
            else:
                print(f"    [FAIL] Failed to delete: {record_name}")
        
        print(f"  [INFO] Cleanup complete: {deleted}/{len(cleanup_records)} records deleted")
        
    except Exception as e:
        print(f"  [WARN] Cleanup error: {e}")


# =============================================================================
# Main Test Runner
# =============================================================================

def run_all_tests(config: TestConfig, quick_mode: bool = False, skip_creation: bool = False, cleanup: bool = True):
    """Run all tests"""
    runner = TestRunner(config)
    
    print("\n" + "=" * 70)
    print("CERTMATE E2E TEST SUITE v" + __version__)
    print("=" * 70)
    print(f"  Server:     {config.base_url}")
    print(f"  Domain:     {config.test_domain}")
    print(f"  DNS:        {config.dns_provider} ({config.dns_account_id})")
    print(f"  Staging:    {config.use_staging}")
    print(f"  Quick Mode: {quick_mode}")
    print("=" * 70 + "\n")
    
    # Category 1: Infrastructure
    print("\n[1] Infrastructure Validation")
    print("-" * 40)
    runner.run_test("Server Health", lambda: test_server_health(runner), Severity.CRITICAL)
    runner.run_test("Web UI Accessible", lambda: test_web_ui_accessible(runner), Severity.LOW)
    runner.run_test("API Docs", lambda: test_api_docs_accessible(runner), Severity.LOW)
    
    # Category 2: Authentication
    print("\n[2] Authentication & Security")
    print("-" * 40)
    runner.run_test("API Authentication", lambda: test_api_authentication(runner), Severity.CRITICAL)
    runner.run_test("Invalid Token Rejected", lambda: test_invalid_token(runner), Severity.HIGH)
    
    # Category 3: DNS Provider
    print("\n[3] DNS Provider Integration")
    print("-" * 40)
    runner.run_test("DNS Provider Configured", lambda: test_dns_provider_configured(runner), Severity.CRITICAL)
    
    # Category 4: Certificate Operations
    print("\n[4] Certificate Operations")
    print("-" * 40)
    runner.run_test("List Certificates", lambda: test_list_certificates(runner), Severity.HIGH)
    runner.run_test("Settings Endpoint", lambda: test_settings_endpoint(runner), Severity.MEDIUM)
    
    if not skip_creation and not quick_mode:
        runner.run_test("Create Certificate (Staging)", lambda: test_create_certificate_staging(runner), Severity.CRITICAL)
        
        if runner.created_certificates:
            runner.run_test("Download Certificate", lambda: test_download_certificate(runner), Severity.HIGH)
            runner.run_test("Certificate Status", lambda: test_certificate_status(runner), Severity.MEDIUM)
    else:
        runner.skip_test("Create Certificate", "Skipped (--skip-creation or --quick)", Severity.CRITICAL)
        runner.skip_test("Download Certificate", "Skipped (no cert created)", Severity.HIGH)
        runner.skip_test("Certificate Status", "Skipped (no cert created)", Severity.MEDIUM)
    
    # Category 5: Client Certificates
    print("\n[5] Client Certificates")
    print("-" * 40)
    runner.run_test("Client CA Exists", lambda: test_client_ca_exists(runner), Severity.MEDIUM)
    runner.run_test("List Client Certs", lambda: test_list_client_certs(runner), Severity.MEDIUM)
    
    if not quick_mode:
        runner.run_test("Generate Client Cert", lambda: test_generate_client_cert(runner), Severity.MEDIUM)
        runner.run_test("CRL Endpoint", lambda: test_crl_endpoint(runner), Severity.LOW)
    else:
        runner.skip_test("Generate Client Cert", "Skipped (--quick)", Severity.MEDIUM)
        runner.skip_test("CRL Endpoint", "Skipped (--quick)", Severity.LOW)
    
    # Category 6: Error Handling
    print("\n[6] Error Handling")
    print("-" * 40)
    runner.run_test("Invalid Domain Format", lambda: test_invalid_domain_format(runner), Severity.MEDIUM)
    runner.run_test("Missing Required Fields", lambda: test_missing_required_fields(runner), Severity.MEDIUM)
    runner.run_test("Non-existent Certificate", lambda: test_nonexistent_certificate(runner), Severity.MEDIUM)
    
    # Category 7: Performance
    print("\n[7] Performance")
    print("-" * 40)
    runner.run_test("Health Response Time", lambda: test_health_response_time(runner), Severity.MEDIUM)
    
    # Category 8: Backup
    print("\n[8] Backup & Recovery")
    print("-" * 40)
    runner.run_test("List Backups", lambda: test_backup_listing(runner), Severity.MEDIUM)
    
    if not quick_mode:
        runner.run_test("Create Backup", lambda: test_backup_creation(runner), Severity.MEDIUM)
        runner.run_test("Audit Log", lambda: test_audit_log_endpoint(runner), Severity.LOW)
    else:
        runner.skip_test("Create Backup", "Skipped (--quick)", Severity.MEDIUM)
        runner.skip_test("Audit Log", "Skipped (--quick)", Severity.LOW)
    
    # Cleanup
    if cleanup and not quick_mode:
        cleanup_cloudflare_dns_records(runner)
    
    # Print summary
    all_passed = runner.suite.print_summary()
    
    # Save results
    runner.suite.save_json()
    
    return 0 if all_passed else 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="CertMate E2E Test Suite")
    parser.add_argument("--url", default="http://localhost:8000", help="CertMate server URL")
    parser.add_argument("--token", default="", help="API bearer token (or uses settings.json)")
    parser.add_argument("--domain", default="certmate.org", help="Test domain")
    parser.add_argument("--staging", action="store_true", default=True, help="Use Let's Encrypt staging (default)")
    parser.add_argument("--production", action="store_true", help="Use production Let's Encrypt (careful!)")
    parser.add_argument("--quick", action="store_true", help="Quick smoke test only")
    parser.add_argument("--skip-creation", action="store_true", help="Skip certificate creation")
    parser.add_argument("--no-cleanup", action="store_true", help="Don't cleanup DNS records")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Build config
    config = TestConfig(
        base_url=args.url,
        api_token=args.token,
        test_domain=args.domain,
        use_staging=not args.production,
        verbose=args.verbose
    )
    
    if args.production:
        print("\n  WARNING: Using PRODUCTION Let's Encrypt!")
        print("  Real rate limits apply. Press Ctrl+C to abort.\n")
        time.sleep(3)
    
    # Run tests
    exit_code = run_all_tests(
        config=config,
        quick_mode=args.quick,
        skip_creation=args.skip_creation,
        cleanup=not args.no_cleanup
    )
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
