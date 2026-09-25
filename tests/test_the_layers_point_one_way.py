"""`modules/core` imported `modules/api` and `modules/web`, and now does not.

#668: the composition root lived in `modules/core/factory.py` and imported the
two layers above it to register them on the Flask app. `docs/architecture.md`
drew that as "the one edge in the system" and argued it was deliberate — a
composition root has to know what it composes, and the alternatives are a
layer that constructs its own dependencies or a registry hiding the same edge
behind indirection.

The argument was sound and the conclusion was not: a composition root does not
have to live *inside* one of the layers it composes. It is `modules/factory.py`
now, one directory up, and the exception is gone rather than documented.

The cycle that made it look unavoidable was **one function wide**.
`api/client_certificates.py` imported `error_code_for_status` back from the
root, so `core → api → core` closed through the composition root itself. That
function derives `NOT_FOUND` from 404 and never belonged there; it is
`modules/core/http_errors.py`.

This file is what keeps the diagram true. It reads imports rather than
importing anything, so a violation is a failing assertion rather than a
circular-import crash at some later, less obvious place.
"""
import ast
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
MODULES = REPO / 'modules'

# What each package may import. `core` is the bottom: it may import itself and
# nothing else of ours. `api` and `web` sit on it. `modules/factory.py` — the
# composition root — is above all three and may import any of them, which is
# the whole reason it moved out of `core`.
ALLOWED = {
    'core': {'core'},
    'api': {'core', 'api'},
    'web': {'core', 'web', 'api'},
}


def _package_of(path):
    """'core' / 'api' / 'web', or None for a module at the `modules/` root."""
    relative = path.relative_to(MODULES)
    return relative.parts[0] if len(relative.parts) > 1 else None


def _imported_packages(path):
    """Which of our packages a file imports, from absolute and relative forms.

    Both spellings are in the tree: `from modules.core.metrics import ...` and
    `from .core.oidc import ...`, the second one inside function bodies. A
    check that read only module-level imports would miss the deferred ones,
    and deferring an import is exactly how an upward edge gets added without
    anybody noticing — it does not even show up as a circular import.
    """
    tree = ast.parse(path.read_text(encoding='utf-8'))
    found = set()
    package = _package_of(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 0:
                parts = (node.module or '').split('.')
                if parts[:1] == ['modules'] and len(parts) > 1:
                    found.add(parts[1])
                continue
            # Relative. level 1 from modules/x/y.py means modules/x/, level 2
            # means modules/. The name after the dots, when there is one, is
            # what it reaches into.
            head = (node.module or '').split('.')[0]
            if node.level == 1 and package is None and head:
                found.add(head)
            elif node.level == 2 and package is not None and head:
                found.add(head)
            elif node.level == 1 and package is not None:
                found.add(package)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split('.')
                if parts[:1] == ['modules'] and len(parts) > 1:
                    found.add(parts[1])
    return {name for name in found if name in ALLOWED}


def _files(package=None):
    root = MODULES / package if package else MODULES
    pattern = '**/*.py' if package else '*.py'
    return sorted(p for p in root.glob(pattern) if p.name != '__init__.py')


# --- the direction ---------------------------------------------------------

@pytest.mark.parametrize('package', sorted(ALLOWED))
def test_no_module_imports_a_layer_above_it(package):
    """THE regression, for all three packages at once."""
    offenders = []
    for path in _files(package):
        for imported in sorted(_imported_packages(path) - ALLOWED[package]):
            offenders.append(f'{path.relative_to(REPO)} imports modules.{imported}')

    assert offenders == [], (
        f'modules/{package}/ may import {sorted(ALLOWED[package])} and nothing '
        f'else of ours:\n  ' + '\n  '.join(offenders))


def test_core_does_not_import_the_api_or_the_web_layer():
    """The specific edge #668 was about, named rather than only covered by the
    parametrised test above — so a failure says what broke."""
    reaching_up = []
    for path in _files('core'):
        for imported in sorted(_imported_packages(path) & {'api', 'web'}):
            reaching_up.append(f'{path.relative_to(REPO)} -> modules.{imported}')

    assert reaching_up == [], (
        'the composition root is in modules/factory.py; core must not reach '
        'back up:\n  ' + '\n  '.join(reaching_up))


def test_the_composition_root_is_above_the_layers():
    """And it is the root: it composes all three, which is why it is allowed
    to import all three and why it cannot live inside one of them."""
    root = MODULES / 'factory.py'

    assert root.exists(), 'modules/factory.py is gone'
    assert not (MODULES / 'core' / 'factory.py').exists(), (
        'the old location is back; two composition roots is worse than an '
        'upward import')
    assert _imported_packages(root) >= {'core', 'api', 'web'}


def test_the_function_that_closed_the_cycle_has_its_own_home():
    """It was the whole cycle. If it goes back into the root, the root becomes
    something `api` has a reason to import again."""
    from modules.core.http_errors import error_code_for_status

    assert error_code_for_status(404, 'Not Found') == 'NOT_FOUND'
    assert error_code_for_status(599, '') == 'HTTP_599'

    factory = (MODULES / 'factory.py').read_text(encoding='utf-8')
    assert 'def error_code_for_status' not in factory


# --- what the move must not have broken -----------------------------------

def test_the_state_directories_still_resolve_beside_the_package():
    """The landmine in this move, and the reason it is worth a test of its own.

    `resolve_state_directories` derives the default certificate, data, backup
    and log directories from `Path(__file__).parent.parent.parent` — three
    levels up from `modules/core/factory.py`. The file is one level higher
    now, so three levels up is the directory ABOVE the checkout: every default
    path would have moved, silently, and an upgraded instance would have come
    up unable to find a single certificate.

    Asserted against the directory that contains `modules/` rather than
    against a count of `.parent` calls, so it fails if the file moves again.
    """
    from modules import factory

    # Against the anchor the module actually has, not against the repository
    # root: the suite's own isolation fixture repoints `factory.__file__` at a
    # temporary tree precisely so a test run cannot write into the checkout
    # (#702). The invariant is the same either way — the base is the directory
    # that CONTAINS `modules/` — and stating it this way is what makes the
    # test fail if the file moves again rather than if the fixture changes.
    base = pathlib.Path(factory.__file__).resolve().parent.parent

    with pytest.MonkeyPatch.context() as patch:
        for name in ('CERTMATE_CERT_DIR', 'CERTMATE_DATA_DIR',
                     'CERTMATE_BACKUP_DIR', 'CERTMATE_LOGS_DIR'):
            patch.delenv(name, raising=False)
        resolved = factory.resolve_state_directories()

    assert resolved['cert_dir'] == base / 'certificates'
    assert resolved['data_dir'] == base / 'data'
    assert resolved['backup_dir'] == base / 'backups'
    assert resolved['logs_dir'] == base / 'logs'
    assert base.name != 'modules', (
        'the base is inside the package rather than beside it, which is what '
        'counting one level too many looks like')


def test_the_templates_and_static_directories_still_resolve():
    """The second anchor in the same file, for the same reason. A wrong base
    here is a Flask app that renders nothing and serves no CSS — visible
    immediately, unlike the state directories, but from the same edit."""
    import inspect

    from modules import factory

    source = inspect.getsource(factory.create_app)
    assert 'factory_path.parent.parent' in source
    assert 'factory_path.parent.parent.parent' not in source, (
        'the project-root anchor still counts three levels, which was right '
        'when this file was in modules/core/')
    assert (REPO / 'templates').is_dir()
    assert (REPO / 'static').is_dir()
