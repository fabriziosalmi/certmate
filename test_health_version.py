"""
Test for issue #57: /health endpoint must return the correct version.
Validates that the version comes from app.__version__ and not hardcoded.
"""
import pytest
from unittest.mock import patch, MagicMock
import json


def test_health_returns_version():
    """Issue #57: /health must include the correct version from app.__version__."""
    from app import __version__

    # Verify __version__ is defined and looks like a semver string
    assert __version__ is not None
    assert isinstance(__version__, str)
    parts = __version__.split('.')
    assert len(parts) == 3, f"Version should be semver (x.y.z), got: {__version__}"
    for part in parts:
        assert part.isdigit(), f"Version part '{part}' is not numeric in {__version__}"

    # Verify it's NOT the old hardcoded value
    assert __version__ != '1.2.1', "Version is still the old hardcoded 1.2.1"


def test_health_endpoint_includes_version():
    """Issue #57: /health JSON response must contain 'version' field."""
    import importlib
    import app as app_module

    # Create a minimal Flask test client
    certmate = app_module.CertMateApp()
    client = certmate.app.test_client()

    response = client.get('/health')
    assert response.status_code == 200

    data = json.loads(response.data)
    assert 'status' in data
    assert data['status'] == 'healthy'
    assert 'version' in data, "/health response missing 'version' field (issue #57)"
    assert data['version'] == app_module.__version__
