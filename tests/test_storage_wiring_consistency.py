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


# The proper nouns each dispatched backend is documented under. Product names
# stay in English in every translation, which is what makes them checkable
# across all five guides.
#
# `local_filesystem` is deliberately absent: it is the only one whose name is a
# common noun, and the translations render it as "Filesystem locale",
# "Lokales Dateisystem", "Sistema de archivos local". Requiring the English
# string there failed four correct documents — my check, not their prose. It is
# also the default and appears in every guide's opening paragraph, so it is not
# the one at risk of going undocumented.
_UNTRANSLATED_NAME = {"local_filesystem"}
_DOC_NAMES = {
    "azure_keyvault": "Azure Key Vault",
    "aws_secrets_manager": "AWS Secrets Manager",
    "hashicorp_vault": "HashiCorp Vault",
    "infisical": "Infisical",
    "s3_compatible": "S3-compatible",
}


def test_every_dispatched_backend_has_a_documented_name():
    """Both directions.

    A dispatched backend with no name here silently stops being covered by the
    guide check. A name here for a backend that is no longer dispatched is the
    opposite failure — the guide would be required to document something that
    does not exist, and nobody would know why (Copilot, #557).
    """
    canonical = _canonical()
    named = set(_DOC_NAMES) | _UNTRANSLATED_NAME
    missing = sorted(canonical - named)
    assert not missing, (
        f"these backends are dispatched but have no documented name here: "
        f"{missing}. Add them, and add them to the architecture guide."
    )
    stale = sorted(named - canonical)
    assert not stale, (
        f"these have a documented name here but are no longer dispatched: "
        f"{stale}. Remove them, or the guide is asked to describe a backend "
        f"the application cannot use."
    )


def _guides():
    """Every document that states the backend list, in every language.

    architecture.md and the docs landing README both enumerate them. Only the
    former was covered at first, and the Italian README slipped through with
    five backends and abbreviated names while the other four were corrected —
    the translations blind spot, inside the very patch that fixed it.
    """
    found = [p for p in _ROOT.glob("docs/**/architecture.md")]
    found += [p for p in _ROOT.glob("docs/**/README.md")]
    return sorted(str(p.relative_to(_ROOT)) for p in found)


@pytest.mark.parametrize("guide", _guides())
def test_the_architecture_guide_lists_every_backend(guide):
    """The seventh surface, and the only one that was not pinned.

    This file already cross-validates the API model enum, the resources'
    available/valid/migrate lists, the settings select and the settings JS
    panel map against the dispatch. The documentation was not among them, and
    it had fallen a whole backend behind: `s3_compatible` ships with a class,
    three test files and a settings-UI panel, and the architecture guide listed
    "4 cloud backends" without it — in all five languages.
    """
    text = _read(guide)
    # _canonical() reflects over the dispatch source; computed once rather than
    # per entry inside the comprehension.
    canonical = _canonical()
    missing = [
        f"{key} ({name})" for key, name in sorted(_DOC_NAMES.items())
        if key in canonical and name not in text
    ]
    assert not missing, (
        f"{guide} does not mention {missing}. A backend the application "
        f"dispatches, the API accepts and the settings page offers, described "
        f"nowhere."
    )
