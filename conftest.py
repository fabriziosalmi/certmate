"""
Pytest configuration for CertMate test suite.

Separates offline unit/integration tests from e2e tests that require
a running CertMate server on localhost:8000.
"""

# Files that require a running CertMate server — exclude from default `pytest` runs.
# Run them directly: python test_e2e_real.py, python test_e2e_complete.py, etc.
collect_ignore = [
    "test_e2e_real.py",
    "test_all_endpoints.py",
    "test_route53_cert.py",
    "test_dns_provider_detection.py",
    "test_ui_e2e.py",
    "test_actual_settings.py",
]
