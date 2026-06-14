"""Cross-validate that every certificate-storage backend is wired across all
backend-set surfaces.

The DNS subsystem is guarded by test_provider_wiring_consistency.py +
test_frontend_provider_coverage.py. Storage had no equivalent: the
s3_compatible backend (#304) is wired by hand into ~6 independent backend-set
literals, and the next backend (or a typo dropping one from a list) could ship
a backend that is selectable in the UI but 400s on config/test/migrate, or is
dispatched but never offered — with no failing test. This ratchet pins them to
the canonical set (what StorageManager can actually dispatch).
"""
import inspect
import re
from pathlib import Path

import pytest

from modules.core import storage_backends as sb

pytestmark = [pytest.mark.unit]

_ROOT = Path(__file__).resolve().parent.parent


def _read(rel):
    return (_ROOT / rel).read_text()


def _canonical():
    """Backends StorageManager._initialize_backend can dispatch — the source of truth."""
    src = inspect.getsource(sb.StorageManager._initialize_backend)
    return set(re.findall(r"backend_type == '([a-z0-9_-]+)'", src))


def _literal_after(text, marker, open_b, close_b):
    """Quoted lowercase identifiers inside the bracketed literal that follows
    *marker* (bracket-matched so nested structures are handled)."""
    start = text.index(marker)
    k = text.index(open_b, start)
    depth = 0
    end = k
    for end in range(k, len(text)):
        if text[end] == open_b:
            depth += 1
        elif text[end] == close_b:
            depth -= 1
            if depth == 0:
                break
    return set(re.findall(r"'([a-z0-9_-]+)'", text[k:end + 1]))


def _model_enum():
    from flask import Flask
    from flask_restx import Api
    from modules.api.models import create_api_models
    api = Api(Flask(__name__))
    create_api_models(api)
    return set(api.models['StorageConfig']['backend'].enum)


# Guard against a broken regex making every assertion vacuously pass.
def test_canonical_set_is_sane():
    canonical = _canonical()
    assert {'local_filesystem', 'aws_secrets_manager', 's3_compatible'} <= canonical
    assert len(canonical) >= 6


def test_api_model_enum_matches_dispatch():
    enum = _model_enum()
    canonical = _canonical()
    assert enum == canonical, (
        f"StorageConfig.backend enum (api/models.py) != dispatchable backends: "
        f"missing={sorted(canonical - enum)} extra={sorted(enum - canonical)}"
    )


def test_resources_available_backends_matches_dispatch():
    src = _read('modules/api/resources.py')
    available = _literal_after(src, "'available_backends': [", '[', ']')
    canonical = _canonical()
    assert available == canonical, (
        f"resources.py StorageBackendInfo available_backends != dispatchable: "
        f"missing={sorted(canonical - available)} extra={sorted(available - canonical)}"
    )


def test_resources_valid_backends_matches_dispatch():
    src = _read('modules/api/resources.py')
    valid = _literal_after(src, "valid_backends = [", '[', ']')
    canonical = _canonical()
    assert valid == canonical, (
        f"resources.py StorageBackendConfig valid_backends != dispatchable: "
        f"missing={sorted(canonical - valid)} extra={sorted(valid - canonical)}"
    )


def test_resources_migrate_backend_classes_matches_dispatch():
    src = _read('modules/api/resources.py')
    classes = _literal_after(src, "backend_classes = {", '{', '}')
    canonical = _canonical()
    # local_filesystem is built specially in _build_backend, not via backend_classes.
    assert classes == canonical - {'local_filesystem'} or classes == canonical, (
        f"resources.py migrate backend_classes != dispatchable: "
        f"missing={sorted((canonical - {'local_filesystem'}) - classes)} extra={sorted(classes - canonical)}"
    )


def test_settings_storage_select_matches_dispatch():
    html = _read('templates/partials/settings_storage.html')
    m = re.search(r'id="storage-backend".*?</select>', html, re.S)
    assert m, "could not locate the storage-backend <select> in settings_storage.html"
    options = set(re.findall(r'<option value="([a-z0-9_-]+)"', m.group(0)))
    canonical = _canonical()
    assert options == canonical, (
        f"settings_storage.html backend <select> != dispatchable: "
        f"missing={sorted(canonical - options)} extra={sorted(options - canonical)}"
    )


def test_settings_js_panel_map_matches_dispatch():
    js = _read('static/js/settings.js')
    panel_keys = set(re.findall(r"'([a-z0-9_-]+)':\s*'storage-[a-z0-9-]+-config'", js))
    canonical = _canonical()
    assert panel_keys == canonical, (
        f"settings.js storage panel map != dispatchable: "
        f"missing={sorted(canonical - panel_keys)} extra={sorted(panel_keys - canonical)}"
    )
