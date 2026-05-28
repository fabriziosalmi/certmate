"""Pin the /api/certificates routing contract after removing the dead
``list_certificates_web`` web route.

Background: ``modules/web/cert_routes.py`` used to define
``list_certificates_web`` decorated with BOTH ``/api/certificates`` and
``/api/web/certificates`` (GET). On ``/api/certificates`` it was shadowed by
the Flask-RESTX ``CertificateList`` resource (endpoint
``certificates_certificate_list``); on the bare ``/api/web/certificates`` it
was the live handler but always 500'd because it called the non-existent
``CertificateManager.list_certificates()``. The route was removed; this test
locks in that:

  * the function/endpoint is gone,
  * ``GET /api/certificates`` is still served by the RESTX resource, and
  * the bare ``GET /api/web/certificates`` is no longer routable, while the
    sibling ``POST /api/web/certificates/create`` group route survives.
"""
from pathlib import Path

import pytest
import werkzeug.exceptions

from modules.core.factory import create_app


pytestmark = [pytest.mark.unit]


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Boot the real app with all of its data/cert/log/backup directories
    anchored under ``tmp_path`` so ``create_app()`` never writes into the repo.

    Uses the same path-anchor trick as ``tests/test_factory_directories.py``:
    point ``modules.core.factory.__file__`` at a fake ``factory.py`` inside a
    temp project tree, so ``setup_directories`` resolves all dirs relative to
    that tree instead of the real checkout.
    """
    project_root = tmp_path / "certmate"
    module_dir = project_root / "modules" / "core"
    module_dir.mkdir(parents=True)
    fake_factory_file = module_dir / "factory.py"
    fake_factory_file.write_text("# test path anchor\n")
    monkeypatch.setattr("modules.core.factory.__file__", str(fake_factory_file))

    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("TESTING", "true")

    application, container = create_app()

    # Sanity: directories really landed under tmp_path, not the repo.
    # setup_directories resolves dirs from the monkeypatched factory.__file__.
    assert Path(container.cert_dir).resolve().is_relative_to(tmp_path)

    return application


def test_list_certificates_web_view_function_removed(app):
    """The dead web handler must not be registered as a view function."""
    assert 'list_certificates_web' not in app.view_functions


def test_api_certificates_served_by_restx(app):
    """GET /api/certificates resolves to the RESTX CertificateList resource."""
    adapter = app.url_map.bind('localhost')
    endpoint, _ = adapter.match('/api/certificates', method='GET')
    assert endpoint == 'certificates_certificate_list'


def test_bare_web_certificates_no_longer_routable(app):
    """The bare GET /api/web/certificates route was removed -> not routable."""
    adapter = app.url_map.bind('localhost')
    with pytest.raises(
        (werkzeug.exceptions.NotFound, werkzeug.exceptions.MethodNotAllowed)
    ):
        adapter.match('/api/web/certificates', method='GET')


def test_sibling_create_route_still_resolves(app):
    """Removing the list route must not disturb the /api/web/certificates/*
    group: POST /api/web/certificates/create still maps to its handler."""
    adapter = app.url_map.bind('localhost')
    endpoint, _ = adapter.match('/api/web/certificates/create', method='POST')
    assert endpoint == 'create_certificate_web'
