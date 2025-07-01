# Testing Guide for CertMate

This document describes the testing framework and best practices for CertMate.

## Overview

CertMate uses a comprehensive testing framework to ensure code quality and prevent regressions. Every commit should pass all tests before being merged.

## Test Structure

```
tests/
├── __init__.py
├── conftest.py              # Test configuration and fixtures
├── test_app.py             # Flask application tests
├── test_api.py             # API endpoint tests
├── test_certificate_management.py  # Certificate handling tests
├── test_dns_providers_integration.py  # DNS provider tests
└── fixtures/
    ├── __init__.py
    └── sample_settings.json
```

## Running Tests

### Quick Start

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

### Using Make Commands

```bash
# Run all tests
make test

# Run only unit tests
make test-unit

# Run only integration tests
make test-integration

# Run tests with coverage
make test-coverage

# Run tests in watch mode
make test-watch

# Run all quality checks
make check
```

### Pre-commit Script

Run the comprehensive pre-commit check:

```bash
./test-before-commit.sh
```

This script runs:
- Dependency installation
- Code linting
- Security checks
- Full test suite
- Coverage reporting
- TODO/FIXME detection

## Test Categories

Tests are organized with pytest markers:

### Unit Tests
```bash
pytest -m "not integration and not slow"
```
Fast tests that don't require external services.

### Integration Tests
```bash
pytest -m integration
```
Tests that interact with external services or complex components.

### API Tests
```bash
pytest -m api
```
Tests for REST API endpoints.

### DNS Provider Tests
```bash
pytest -m dns
```
Tests for DNS provider integrations.

## Test Configuration

### pytest.ini
Configuration file with test settings, coverage options, and markers.

### conftest.py
Contains shared fixtures:
- `app`: Flask application instance for testing
- `client`: Test client for API requests
- `runner`: CLI test runner
- `sample_settings`: Mock configuration data
- `mock_certificate_data`: Sample certificate data

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

### Fixtures Usage
```python
def test_with_app_context(app):
    """Test that requires app context."""
    with app.app_context():
        # Test code here
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

## Continuous Integration

### GitHub Actions
The CI pipeline runs on every push and pull request:

1. **Multiple Python Versions**: Tests on Python 3.9, 3.11, 3.12
2. **Code Quality**: Linting with flake8
3. **Security**: Security scanning with bandit
4. **Tests**: Full test suite with coverage
5. **Docker**: Test Docker build
6. **Coverage**: Upload to Codecov

### Pre-commit Hooks
Install pre-commit hooks to run checks automatically:

```bash
pip install pre-commit
pre-commit install
```

Hooks include:
- Code formatting (black, isort)
- Linting (flake8)
- Security checks (bandit)
- Test execution

## Coverage Requirements

- Maintain minimum 80% code coverage
- All new features must include tests
- Critical paths must have 95%+ coverage

### Viewing Coverage
```bash
# Generate HTML coverage report
pytest --cov=. --cov-report=html

# Open coverage report
open htmlcov/index.html
```

## Test Data Management

### Fixtures
- Use fixtures for reusable test data
- Mock external dependencies
- Create isolated test environments

### Test Database
Tests use temporary directories and mock data to avoid affecting production data.

## Best Practices

### DO:
- Write tests for all new features
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Use appropriate test markers
- Keep tests isolated and independent

### DON'T:
- Test implementation details
- Use real API keys in tests
- Make tests dependent on each other
- Ignore test failures
- Skip writing tests for "simple" code

## Debugging Tests

### Verbose Output
```bash
pytest -v -s  # Show print statements
```

### Debug Specific Test
```bash
pytest tests/test_api.py::test_specific_function -v -s
```

### Using pdb
```python
def test_debug_example():
    import pdb; pdb.set_trace()
    # Test code here
```

## Performance Testing

### Load Testing
For API endpoints that need performance testing:

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

## Maintenance

### Regular Tasks
- Update test dependencies monthly
- Review and update test coverage goals
- Clean up obsolete tests
- Update CI configuration as needed

### Adding New Test Types
When adding new features:
1. Create corresponding test files
2. Add appropriate markers
3. Update this documentation
4. Add to CI pipeline if needed

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [Flask testing](https://flask.palletsprojects.com/en/2.3.x/testing/)
- [Python testing best practices](https://docs.python-guide.org/writing/tests/)
