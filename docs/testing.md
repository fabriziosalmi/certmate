# Testing Guide

This guide covers CertMate's testing framework, including unit tests, integration tests, and API endpoint validation.

---

## Quick Start

```bash
# Activate virtual environment
source .venv/bin/activate

# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest

# Run tests with coverage
pytest --cov=. --cov-report=html
```

---

## Test Structure

```
Root directory:
  conftest.py                              # Collection config and shared fixtures
  pytest.ini                               # Test configuration and markers
  test_certificate_creation.py             # Certificate creation tests
  test_certificate_listing.py              # Certificate listing tests
  test_client_certificates_comprehensive.py # Client cert lifecycle tests
  test_dns_accounts.py                     # Multi-account operations
  test_dns_provider.py                     # Basic provider functionality
  test_dns_provider_inheritance.py         # Config inheritance
  test_domain_alias.py                     # Domain alias tests
  test_infisical_backend.py               # Infisical storage backend
  test_shell_executor.py                   # Shell execution tests
  test_e2e_complete.py                     # End-to-end test suite
```

---

## Running Tests

### Common Commands

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest test_certificate_creation.py

# Run a specific test function
pytest test_certificate_creation.py::test_specific_function -v -s

# Run tests matching a pattern
pytest -k "dns_provider"

# Run with coverage report
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

### Using Make

```bash
make test              # Run all tests
make test-unit         # Unit tests only
make test-integration  # Integration tests only
make test-coverage     # Tests with coverage
make check             # All quality checks
```

---

## Test Categories

Tests are organized with pytest markers:

```bash
# Unit tests (fast, no external services)
pytest -m "not integration and not slow"

# Integration tests
pytest -m integration

# API tests
pytest -m api

# DNS provider tests
pytest -m dns

# End-to-end tests (require running server)
pytest -m e2e
```

### E2E without Docker

By default the e2e fixtures build the Docker image and manage a container
for the whole session. When Docker isn't available (CI sandboxes,
restricted networks), point the suite at an already-running instance:

```bash
# Terminal 1: run CertMate however you like
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 app:app

# Terminal 2: target it (skips all Docker lifecycle management)
CERTMATE_E2E_BASE_URL=http://localhost:18888 pytest -m "e2e and not ui"
```

The real-issuance tests additionally need `CLOUDFLARE_API_TOKEN` and a
`CERTMATE_TEST_DOMAIN` you control, and burn real Let's Encrypt
certificates — they skip automatically when the token is absent. The
target instance must start from a clean data directory: e2e tests assume
first-boot state, so reuse across runs causes auth-dependent failures.

---

## API Endpoint Testing

### Quick Test Script

Use `quick_test.sh` for fast pre-commit endpoint validation:

```bash
# Run before every commit
./quick_test.sh

# Test only public endpoints
./quick_test.sh --public-only
```

This script:
- Checks if the server is running
- Auto-loads API token from `data/settings.json`
- Tests all endpoint categories
- Provides clear pass/fail output

### Running the test suite

The suite is pytest, split by marker (see `pytest.ini`): `unit`,
`integration`, `api`, `dns`, `e2e` (needs a running server), `ui`
(Playwright, needs a browser and a container).

```bash
make test                # unit + integration
make test-unit
make test-coverage       # --cov=modules, HTML + XML reports

# Or directly, e.g. everything that does not need a browser:
pytest -m "not ui"
pytest -m "not ui and not e2e" -q
```

CI runs `pytest -m "not ui"` on Python 3.12 with a coverage floor; the UI
suite runs in its own workflow, and the real-certificate end-to-end gate runs
against Let's Encrypt staging before a release.

### Tested Endpoints

| Category | Endpoints |
|----------|-----------|
| **Health** | `GET /api/health`, `GET /health` |
| **Settings** | `GET /api/settings`, `GET /api/settings/dns-providers`, `POST /api/settings` |
| **Certificates** | `GET /api/certificates`, `POST /api/certificates/create`, download, renew |
| **Cache** | `GET /api/cache/stats`, `POST /api/cache/clear` |
| **Backup** | `GET /api/backups`, `POST /api/backups/create` |
| **Web Interface** | `/`, `/settings`, `/help`, `/docs/`, `/api/swagger.json` |

### Expected Status Codes

- **200/201**: Success
- **400/422**: Expected validation errors (normal for test payloads)
- **404**: Expected for non-existent resources
- **401**: Invalid/missing API token
- **500**: Application bug (investigate)

---

## Writing Tests

### Test Structure

```python
import pytest
from unittest.mock import patch, MagicMock

def test_function_name(client, sample_settings):
    """Test description."""
    # Arrange
    setup_data = {...}

    # Act
    response = client.get('/api/endpoint')

    # Assert
    assert response.status_code == 200
    assert 'expected_key' in response.json()
```

### Using Fixtures

```python
def test_with_app_context(app):
    """Test that requires app context."""
    with app.app_context():
        pass

def test_api_endpoint(client):
    """Test API endpoint."""
    response = client.get('/api/test')
    assert response.status_code == 200

def test_with_mock_data(mock_certificate_data):
    """Test with mock data."""
    assert mock_certificate_data['domain'] == 'test.example.com'
```

### Mocking External Services

```python
@patch('app.requests.get')
def test_external_api(mock_get, client):
    """Test external API call."""
    mock_get.return_value.json.return_value = {'status': 'success'}
    response = client.post('/api/certificate/request')
    assert response.status_code == 200
```

---

## Continuous Integration

### GitHub Actions

The CI pipeline runs on every push and pull request:

1. **Multiple Python Versions**: Tests on Python 3.9, 3.11, 3.12
2. **Code Quality**: Linting with flake8
3. **Security**: Scanning with bandit
4. **Tests**: Full test suite with coverage
5. **Docker**: Test Docker build
6. **Coverage**: Upload to Codecov

### Before pushing

There is no pre-commit configuration in this repository; run the same gates CI
runs:

```bash
make lint                # flake8, failing set only
pytest -m "not ui" -q    # what CI runs
```

A release runs considerably more — see `scripts/release.sh`, which gates on
flake8, bandit, the unit and integration suites, the Playwright UI suite, a
real certificate issued against Let's Encrypt staging, and a Docker build.

---

## Coverage Requirements

- CI enforces a floor of **65%** over `modules/` (`--cov-fail-under`, a ratchet
  — raise it, never lower it to make a build pass). The number today is
  comfortably above it.
- All new features must include tests.

---

## Best Practices

### Do

- Write tests for all new features
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Use appropriate test markers
- Keep tests isolated and independent

### Don't

- Test implementation details
- Use real API keys in tests
- Make tests dependent on each other
- Ignore test failures
- Skip writing tests for "simple" code

---

## Debugging Tests

```bash
# Verbose with print statements
pytest -v -s

# Debug specific test
pytest test_api.py::test_specific -v -s

# Using pdb
def test_debug_example():
    import pdb; pdb.set_trace()
    # Test code here
```

---

## Performance Testing

```python
import pytest
import concurrent.futures

@pytest.mark.slow
def test_api_load(client):
    """Test API under load."""
    def make_request():
        return client.get('/api/certificates')

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request) for _ in range(100)]
        responses = [f.result() for f in futures]

    assert all(r.status_code == 200 for r in responses)
```

---

## Exit Codes

- **0**: All tests passed
- **1**: Some tests failed

---

<div align="center">

[← Back to Documentation](./README.md) • [Architecture →](./architecture.md) • [API Reference →](./api.md)

</div>
