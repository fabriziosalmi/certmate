#!/usr/bin/env python3
"""
Comprehensive test suite for client certificate functionality
Tests Phase 1-3 implementation (CA, Client Certs, OCSP/CRL)
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.core.private_ca import PrivateCAGenerator
from modules.core.csr_handler import CSRHandler
from modules.core.client_certificates import ClientCertificateManager
from modules.core.ocsp_crl import OCSPResponder, CRLManager


class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def add_pass(self, test_name):
        self.passed += 1
        print(f"  ✅ {test_name}")

    def add_fail(self, test_name, error):
        self.failed += 1
        self.errors.append((test_name, error))
        print(f"  ❌ {test_name}: {error}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Test Results: {self.passed}/{total} passed")
        if self.failed > 0:
            print(f"\nFailed Tests:")
            for name, error in self.errors:
                print(f"  - {name}: {error}")
        print(f"{'='*60}")
        return self.failed == 0


def test_private_ca():
    """Test PrivateCAGenerator"""
    print("\n🔐 Testing PrivateCAGenerator...")
    results = TestResults()

    with tempfile.TemporaryDirectory() as tmpdir:
        ca_dir = Path(tmpdir) / "ca"

        try:
            # Test CA initialization
            ca = PrivateCAGenerator(ca_dir)
            if ca.initialize():
                results.add_pass("CA initialization")
            else:
                results.add_fail("CA initialization", "Failed to initialize CA")

            # Check CA files exist (correct filenames)
            if (ca_dir / "ca.crt").exists():
                results.add_pass("CA certificate created")
            else:
                results.add_fail("CA certificate", "cert file not found")

            if (ca_dir / "ca.key").exists():
                results.add_pass("CA private key created")
            else:
                results.add_fail("CA private key", "key file not found")

            # Check metadata
            if (ca_dir / "ca_metadata.json").exists():
                results.add_pass("CA metadata created")
            else:
                results.add_fail("CA metadata", "metadata file not found")

            # Test CA load
            ca2 = PrivateCAGenerator(ca_dir)
            if ca2._load_ca():
                results.add_pass("CA loading")
            else:
                results.add_fail("CA loading", "Failed to load existing CA")

        except Exception as e:
            results.add_fail("CA tests", str(e))

    return results


def test_csr_handler():
    """Test CSRHandler"""
    print("\n📝 Testing CSRHandler...")
    results = TestResults()

    try:
        # Test CSR creation (returns csr_pem, key_pem, error)
        csr_pem, key_pem, error = CSRHandler.create_csr(
            common_name="test.example.com",
            organization="Test Org",
            key_size=2048
        )

        if csr_pem and key_pem and not error:
            results.add_pass("CSR creation with private key")
        else:
            results.add_fail("CSR creation", f"Empty PEM data or error: {error}")

        # Verify CSR is valid PEM
        if csr_pem.startswith(b'-----BEGIN'):
            results.add_pass("CSR PEM format validation")
        else:
            results.add_fail("CSR PEM format", "Invalid PEM header")

        # Verify key is valid PEM
        if key_pem.startswith(b'-----BEGIN'):
            results.add_pass("Key PEM format validation")
        else:
            results.add_fail("Key PEM format", "Invalid PEM header")

        # Test CSR validation
        is_valid, error, csr_obj = CSRHandler.validate_csr_pem(csr_pem)
        if is_valid and csr_obj:
            results.add_pass("CSR PEM validation")
        else:
            results.add_fail("CSR validation", f"CSR validation failed: {error}")

        # Test CSR info extraction
        if csr_obj:
            info = CSRHandler.get_csr_info(csr_obj)
            if info and info.get('common_name') == 'test.example.com':
                results.add_pass("CSR info extraction")
            else:
                results.add_fail("CSR info extraction", f"Invalid info: {info}")
        else:
            results.add_fail("CSR info extraction", "Could not load CSR object")

    except Exception as e:
        results.add_fail("CSR handler tests", str(e))

    return results


def test_client_certificate_manager():
    """Test ClientCertificateManager"""
    print("\n🎫 Testing ClientCertificateManager...")
    results = TestResults()

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Initialize CA
            ca_dir = Path(tmpdir) / "ca"
            ca = PrivateCAGenerator(ca_dir)
            ca.initialize()

            # Initialize client cert manager
            client_dir = Path(tmpdir) / "client"
            manager = ClientCertificateManager(client_dir, ca)

            # Test certificate creation
            success, error, cert_data = manager.create_client_certificate(
                common_name="user1.example.com",
                email="user1@example.com",
                organization="Test Org",
                cert_usage="api-mtls",
                days_valid=365,
                generate_key=True
            )

            if success and cert_data:
                results.add_pass("Certificate creation")
                identifier = cert_data['identifier']
            else:
                results.add_fail("Certificate creation", error)
                return results

            # Test certificate listing
            certs = manager.list_client_certificates()
            if len(certs) == 1:
                results.add_pass("Certificate listing")
            else:
                results.add_fail("Certificate listing", f"Expected 1, got {len(certs)}")

            # Test certificate filtering by usage
            certs_mtls = manager.list_client_certificates(cert_usage="api-mtls")
            if len(certs_mtls) == 1:
                results.add_pass("Certificate filtering by usage")
            else:
                results.add_fail("Certificate filtering", f"Expected 1, got {len(certs_mtls)}")

            # Test metadata retrieval
            metadata = manager.get_certificate_metadata(identifier)
            if metadata and metadata['common_name'] == 'user1.example.com':
                results.add_pass("Certificate metadata retrieval")
            else:
                results.add_fail("Metadata retrieval", f"Invalid metadata: {metadata}")

            # Test certificate download
            cert_file = manager.get_certificate_file(identifier, 'crt')
            if cert_file and b'BEGIN CERTIFICATE' in cert_file:
                results.add_pass("Certificate file download (CRT)")
            else:
                results.add_fail("Certificate download", "Invalid certificate content")

            key_file = manager.get_certificate_file(identifier, 'key')
            if key_file and b'BEGIN' in key_file and b'PRIVATE KEY' in key_file:
                results.add_pass("Certificate file download (KEY)")
            else:
                results.add_fail("Key download", "Invalid key content")

            # Test certificate revocation
            success, error = manager.revoke_certificate(identifier, reason="Testing")
            if success:
                results.add_pass("Certificate revocation")
            else:
                results.add_fail("Certificate revocation", error)

            # Test revoked filter
            certs_revoked = manager.list_client_certificates(revoked=True)
            if len(certs_revoked) == 1:
                results.add_pass("Revoked certificate filtering")
            else:
                results.add_fail("Revoked filter", f"Expected 1, got {len(certs_revoked)}")

            # Create another certificate for renewal test
            success, error, cert_data2 = manager.create_client_certificate(
                common_name="user2.example.com",
                email="user2@example.com",
                organization="Test Org",
                cert_usage="vpn",
                days_valid=365,
                generate_key=True
            )
            if success:
                identifier2 = cert_data2['identifier']

                # Test renewal
                success, error, renewed_data = manager.renew_certificate(identifier2)
                if success:
                    results.add_pass("Certificate renewal")
                else:
                    results.add_fail("Certificate renewal", error)

            # Test statistics
            stats = manager.get_statistics()
            if stats and 'total' in stats:
                results.add_pass("Certificate statistics")
            else:
                results.add_fail("Statistics", f"Invalid stats: {stats}")

        except Exception as e:
            results.add_fail("Manager tests", str(e))

    return results


def test_ocsp_responder():
    """Test OCSPResponder"""
    print("\n🔍 Testing OCSPResponder...")
    results = TestResults()

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Setup
            ca_dir = Path(tmpdir) / "ca"
            ca = PrivateCAGenerator(ca_dir)
            ca.initialize()

            client_dir = Path(tmpdir) / "client"
            manager = ClientCertificateManager(client_dir, ca)

            # Create a certificate
            success, error, cert_data = manager.create_client_certificate(
                common_name="test.example.com",
                email="test@example.com",
                organization="Test",
                cert_usage="api-mtls",
                days_valid=365,
                generate_key=True
            )

            if not success:
                results.add_fail("OCSP setup", "Failed to create certificate")
                return results

            serial = int(cert_data.get('serial_number', 1))

            # Initialize OCSP responder
            ocsp = OCSPResponder(ca, manager)

            # Test good status - first verify certificate exists
            certs = manager.list_client_certificates()
            if len(certs) > 0:
                # Get the actual serial from metadata
                metadata = manager.get_certificate_metadata(cert_data['identifier'])
                if metadata:
                    serial = int(metadata.get('serial_number', serial))
                    status = ocsp.get_cert_status(serial)
                    if status and status['status'] == 'good':
                        results.add_pass("OCSP good status query")
                    else:
                        results.add_fail("OCSP good status", f"Unexpected: {status}")
                else:
                    results.add_fail("OCSP metadata", "Could not get certificate metadata")
            else:
                results.add_fail("OCSP setup", "Certificate not created")

            # Test unknown status
            unknown_status = ocsp.get_cert_status(9999)
            if unknown_status and unknown_status['status'] == 'unknown':
                results.add_pass("OCSP unknown status query")
            else:
                results.add_fail("OCSP unknown status", f"Unexpected: {unknown_status}")

            # Revoke and test revoked status
            manager.revoke_certificate(cert_data['identifier'], reason="Test")

            # Re-query OCSP for revoked status
            revoked_status = ocsp.get_cert_status(serial)
            if revoked_status and revoked_status['status'] == 'revoked':
                results.add_pass("OCSP revoked status query")
            else:
                results.add_fail("OCSP revoked status", f"Expected revoked, got: {revoked_status}")

            # Test OCSP response generation
            response = ocsp.generate_ocsp_response(status)
            if response and response.get('response_status') == 'successful':
                results.add_pass("OCSP response generation")
            else:
                results.add_fail("OCSP response", f"Invalid response: {response}")

        except Exception as e:
            results.add_fail("OCSP tests", str(e))

    return results


def test_crl_manager():
    """Test CRLManager"""
    print("\n📋 Testing CRLManager...")
    results = TestResults()

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Setup
            ca_dir = Path(tmpdir) / "ca"
            ca = PrivateCAGenerator(ca_dir)
            ca.initialize()

            client_dir = Path(tmpdir) / "client"
            manager = ClientCertificateManager(client_dir, ca)

            # Create and revoke certificates
            success, error, cert_data1 = manager.create_client_certificate(
                common_name="cert1.example.com",
                organization="Test",
                cert_usage="api-mtls",
                days_valid=365,
                generate_key=True
            )

            success, error, cert_data2 = manager.create_client_certificate(
                common_name="cert2.example.com",
                organization="Test",
                cert_usage="vpn",
                days_valid=365,
                generate_key=True
            )

            if not (success and cert_data1 and cert_data2):
                results.add_fail("CRL setup", "Failed to create certificates")
                return results

            # Revoke both
            manager.revoke_certificate(cert_data1['identifier'])
            manager.revoke_certificate(cert_data2['identifier'])

            # Initialize CRL manager
            crl_dir = Path(tmpdir) / "crl"
            crl = CRLManager(ca, manager, crl_dir)

            # Test revoked serials retrieval
            revoked = crl.get_revoked_serials()
            if len(revoked) == 2:
                results.add_pass("CRL revoked serials retrieval")
            else:
                results.add_fail("Revoked serials", f"Expected 2, got {len(revoked)}")

            # Test CRL update
            crl_pem = crl.update_crl()
            if crl_pem and b'BEGIN X509 CRL' in crl_pem:
                results.add_pass("CRL generation")
            else:
                results.add_fail("CRL generation", "Invalid CRL content")

            # Test CRL PEM retrieval
            crl_pem = crl.get_crl_pem()
            if crl_pem and b'BEGIN X509 CRL' in crl_pem:
                results.add_pass("CRL PEM retrieval")
            else:
                results.add_fail("CRL PEM retrieval", "Invalid PEM")

            # Test CRL DER conversion
            crl_der = crl.get_crl_der()
            if crl_der and len(crl_der) > 0:
                results.add_pass("CRL DER conversion")
            else:
                results.add_fail("CRL DER", "Invalid DER content")

            # Test CRL info
            info = crl.get_crl_info()
            if info and info.get('status') == 'available':
                results.add_pass("CRL info retrieval")
            else:
                results.add_fail("CRL info", f"Invalid info: {info}")

        except Exception as e:
            results.add_fail("CRL tests", str(e))

    return results


def test_batch_operations():
    """Test batch certificate creation"""
    print("\n📦 Testing Batch Operations...")
    results = TestResults()

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            ca_dir = Path(tmpdir) / "ca"
            ca = PrivateCAGenerator(ca_dir)
            ca.initialize()

            client_dir = Path(tmpdir) / "client"
            manager = ClientCertificateManager(client_dir, ca)

            # Create multiple certificates
            certs_created = 0
            for i in range(5):
                success, error, cert_data = manager.create_client_certificate(
                    common_name=f"user{i}.example.com",
                    email=f"user{i}@example.com",
                    organization="Test Org",
                    cert_usage="api-mtls" if i % 2 == 0 else "vpn",
                    days_valid=365,
                    generate_key=True
                )
                if success:
                    certs_created += 1

            if certs_created == 5:
                results.add_pass("Batch certificate creation (5 certs)")
            else:
                results.add_fail("Batch creation", f"Created {certs_created}/5")

            # Test search
            certs = manager.list_client_certificates(search_term="user2")
            if len(certs) == 1:
                results.add_pass("Certificate search by CN")
            else:
                results.add_fail("Search", f"Expected 1, got {len(certs)}")

            # Test multi-filter
            certs = manager.list_client_certificates(cert_usage="api-mtls", revoked=False)
            if len(certs) >= 2:
                results.add_pass("Multi-filter certificate listing")
            else:
                results.add_fail("Multi-filter", f"Expected >=2, got {len(certs)}")

        except Exception as e:
            results.add_fail("Batch tests", str(e))

    return results


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("🧪 CertMate Client Certificate Comprehensive Test Suite")
    print("="*60)

    all_results = []

    # Run test groups
    all_results.append(test_private_ca())
    all_results.append(test_csr_handler())
    all_results.append(test_client_certificate_manager())
    all_results.append(test_ocsp_responder())
    all_results.append(test_crl_manager())
    all_results.append(test_batch_operations())

    # Summary
    total_passed = sum(r.passed for r in all_results)
    total_failed = sum(r.failed for r in all_results)
    total = total_passed + total_failed

    print("\n" + "="*60)
    print(f"📊 Overall Results: {total_passed}/{total} tests passed")
    print("="*60)

    if total_failed > 0:
        print(f"\n⚠️  {total_failed} test(s) failed. Please review above.")
        return 1
    else:
        print(f"\n✅ All {total} tests passed!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
