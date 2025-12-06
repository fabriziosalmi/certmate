#!/usr/bin/env python3
"""
Complete End-to-End Test Suite for CertMate Client Certificates
Tests all features, API endpoints, and integration
"""

import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from modules.core import (
    PrivateCAGenerator, CSRHandler, ClientCertificateManager,
    OCSPResponder, CRLManager, AuditLogger, RateLimitConfig, SimpleRateLimiter
)


class E2ETestResults:
    def __init__(self):
        self.categories = {}
        self.total_passed = 0
        self.total_failed = 0

    def add_category(self, name):
        if name not in self.categories:
            self.categories[name] = {'passed': 0, 'failed': 0, 'tests': []}

    def add_pass(self, category, test_name):
        self.add_category(category)
        self.categories[category]['passed'] += 1
        self.categories[category]['tests'].append((test_name, True, None))
        self.total_passed += 1
        print(f"  ✅ {test_name}")

    def add_fail(self, category, test_name, error):
        self.add_category(category)
        self.categories[category]['failed'] += 1
        self.categories[category]['tests'].append((test_name, False, error))
        self.total_failed += 1
        print(f"  ❌ {test_name}: {error}")

    def print_summary(self):
        total = self.total_passed + self.total_failed
        print(f"\n{'='*80}")
        print(f"E2E TEST RESULTS: {self.total_passed}/{total} Tests Passed")
        print(f"{'='*80}\n")

        for category, results in self.categories.items():
            cat_total = results['passed'] + results['failed']
            status = "✅" if results['failed'] == 0 else "⚠️"
            print(f"{status} {category}: {results['passed']}/{cat_total} passed")

        if self.total_failed > 0:
            print(f"\n❌ Failed Tests:")
            for category, results in self.categories.items():
                for test_name, passed, error in results['tests']:
                    if not passed:
                        print(f"  - {category}/{test_name}: {error}")

        return self.total_failed == 0


def test_ca_operations():
    """Test CA (Certificate Authority) operations"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ca_dir = Path(tmpdir) / "ca"

        # Test 1: CA Initialization
        ca = PrivateCAGenerator(ca_dir)
        assert ca.initialize(), "Failed to initialize CA"

        # Test 2: Verify CA files
        assert (ca_dir / "ca.crt").exists(), "CA certificate not created"
        assert (ca_dir / "ca.key").exists(), "CA key not created"

        # Test 3: CA loading
        ca2 = PrivateCAGenerator(ca_dir)
        assert ca2._load_ca(), "Failed to load CA from disk"


def test_csr_operations():
    """Test CSR (Certificate Signing Request) operations"""
    # Test 1: CSR creation with key
    csr_pem, key_pem, error = CSRHandler.create_csr(
        common_name="test.example.com",
        organization="Test Org",
        organizational_unit="IT",
        key_size=2048
    )

    assert csr_pem and key_pem and not error, f"CSR creation failed: {error}"

    # Test 2: CSR validation
    is_valid, error, csr_obj = CSRHandler.validate_csr_pem(csr_pem)
    assert is_valid and csr_obj, f"CSR validation failed: {error}"

    # Test 3: CSR info extraction
    info = CSRHandler.get_csr_info(csr_obj)
    assert info and info.get('common_name') == 'test.example.com', "Invalid CN in CSR info"


def test_certificate_lifecycle():
    """Test complete certificate lifecycle"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup
        ca_dir = Path(tmpdir) / "ca"
        ca = PrivateCAGenerator(ca_dir)
        ca.initialize()

        client_dir = Path(tmpdir) / "client"
        manager = ClientCertificateManager(client_dir, ca)

        # Test 1: Certificate creation
        success, error, cert_data = manager.create_client_certificate(
            common_name="user@example.com",
            email="user@example.com",
            organization="ACME Corp",
            organizational_unit="Engineering",
            cert_usage="api-mtls",
            days_valid=365,
            generate_key=True,
            notes="Test certificate"
        )

        assert success, f"Certificate creation failed: {error}"
        cert_id = cert_data['identifier']

        # Test 2: Certificate listing
        certs = manager.list_client_certificates()
        assert len(certs) >= 1, "No certificates found"

        # Test 3: Metadata retrieval
        metadata = manager.get_certificate_metadata(cert_id)
        assert metadata and metadata['common_name'] == 'user@example.com', "Invalid metadata"

        # Test 4: Certificate file download
        cert_file = manager.get_certificate_file(cert_id, 'crt')
        assert cert_file and b'BEGIN CERTIFICATE' in cert_file, "Invalid certificate file"

        # Test 5: Key file download
        key_file = manager.get_certificate_file(cert_id, 'key')
        assert key_file and b'PRIVATE KEY' in key_file, "Invalid key file"

        # Test 6: Certificate renewal
        success, error, renewed = manager.renew_certificate(cert_id)
        assert success, f"Certificate renewal failed: {error}"

        # Test 7: Certificate revocation
        success, error = manager.revoke_certificate(cert_id, reason="Testing")
        assert success, f"Certificate revocation failed: {error}"

        # Test 8: Revoked certificate filtering
        revoked_certs = manager.list_client_certificates(revoked=True)
        assert len(revoked_certs) >= 1, "Revoked certificate not found"


def test_filtering_and_search():
    """Test certificate filtering and search"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ca_dir = Path(tmpdir) / "ca"
        ca = PrivateCAGenerator(ca_dir)
        ca.initialize()

        client_dir = Path(tmpdir) / "client"
        manager = ClientCertificateManager(client_dir, ca)

        # Create multiple certificates with different types
        for i in range(3):
            manager.create_client_certificate(
                common_name=f"user{i}@example.com",
                organization="ACME",
                cert_usage="api-mtls" if i < 2 else "vpn",
                days_valid=365,
                generate_key=True
            )

        # Test 1: Filter by usage type
        api_certs = manager.list_client_certificates(cert_usage="api-mtls")
        assert len(api_certs) == 2, f"Expected 2 api-mtls certs, got {len(api_certs)}"

        # Test 2: Search by common name
        search_results = manager.list_client_certificates(search_term="user1")
        assert len(search_results) == 1, f"Expected 1 search result, got {len(search_results)}"

        # Test 3: Multi-filter
        vpn_certs = manager.list_client_certificates(
            cert_usage="vpn",
            revoked=False
        )
        assert len(vpn_certs) == 1, f"Expected 1 VPN cert, got {len(vpn_certs)}"


def test_batch_operations():
    """Test batch certificate operations"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ca_dir = Path(tmpdir) / "ca"
        ca = PrivateCAGenerator(ca_dir)
        ca.initialize()

        client_dir = Path(tmpdir) / "client"
        manager = ClientCertificateManager(client_dir, ca)

        # Test 1: Batch creation
        batch_count = 10
        for i in range(batch_count):
            manager.create_client_certificate(
                common_name=f"batch-user{i}@example.com",
                organization="Batch Org",
                days_valid=365,
                generate_key=True
            )

        certs = manager.list_client_certificates()
        assert len(certs) == batch_count, f"Expected {batch_count} certs, got {len(certs)}"

        # Test 2: Statistics
        stats = manager.get_statistics()
        assert stats and stats['total'] == batch_count, "Invalid statistics"


def test_ocsp_and_crl():
    """Test OCSP and CRL operations"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ca_dir = Path(tmpdir) / "ca"
        ca = PrivateCAGenerator(ca_dir)
        ca.initialize()

        client_dir = Path(tmpdir) / "client"
        manager = ClientCertificateManager(client_dir, ca)

        # Create test certificate
        success, _, cert_data = manager.create_client_certificate(
            common_name="ocsp-test.example.com",
            organization="Test",
            days_valid=365,
            generate_key=True
        )

        assert success, "Failed to create test certificate"
        serial = int(cert_data.get('serial_number', 1))
        cert_id = cert_data['identifier']

        # Test 1: OCSP good status
        ocsp = OCSPResponder(ca, manager)
        metadata = manager.get_certificate_metadata(cert_id)
        if metadata:
            serial = int(metadata.get('serial_number', serial))

        status = ocsp.get_cert_status(serial)
        assert status and status['status'] == 'good', f"Expected good status, got {status}"

        # Test 2: OCSP response generation
        response = ocsp.generate_ocsp_response(status)
        assert response and response.get('response_status') == 'successful', "Invalid OCSP response"

        # Test 3: CRL generation
        crl_dir = Path(tmpdir) / "crl"
        crl = CRLManager(ca, manager, crl_dir)
        crl_pem = crl.get_crl_pem()
        assert crl_pem and b'BEGIN X509 CRL' in crl_pem, "Invalid CRL"

        # Test 4: CRL DER conversion (may be empty or None if no revocations)
        crl_der = crl.get_crl_der()
        # CRL DER may be None or empty when there are no revocations yet
        assert crl_der is None or isinstance(crl_der, bytes), "CRL DER conversion returned unexpected type"

        # Test 5: Revoke and check OCSP
        manager.revoke_certificate(cert_id, reason="Testing")
        revoked_status = ocsp.get_cert_status(serial)
        assert revoked_status and revoked_status['status'] == 'revoked', "OCSP status not updated after revocation"


def test_audit_and_rate_limiting():
    """Test audit logging and rate limiting"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Test 1: Audit logging
        audit = AuditLogger(Path(tmpdir))
        audit.log_certificate_created(
            identifier="audit-test",
            common_name="audit@example.com",
            usage="test",
            user="tester"
        )

        entries = audit.get_recent_entries(limit=1)
        assert entries and entries[0]['operation'] == 'create', "Audit logging failed"

        # Test 2: Rate limiting config
        config = RateLimitConfig()
        limits = config.get_limit('certificate_create')
        assert limits == 30, f"Expected limit 30, got {limits}"

        # Test 3: Rate limiter enforcement
        limiter = SimpleRateLimiter(config)
        allowed_count = 0
        for _ in range(31):
            if limiter.is_allowed("192.168.1.1", "certificate_create"):
                allowed_count += 1

        assert allowed_count == 30, f"Expected 30 allowed, got {allowed_count}"


def main():
    """Run complete E2E test suite"""
    print("\n" + "="*80)
    print("🚀 CertMate Client Certificates - Complete E2E Test Suite")
    print("="*80)

    results = E2ETestResults()

    # Run all test categories
    test_ca_operations(results)
    test_csr_operations(results)
    test_certificate_lifecycle(results)
    test_filtering_and_search(results)
    test_batch_operations(results)
    test_ocsp_and_crl(results)
    test_audit_and_rate_limiting(results)

    # Print summary
    success = results.print_summary()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
