"""Running the tests must not modify the working tree's runtime directories.

`setup_directories` resolves `certificates/`, `data/`, `backups/` and `logs/`
from `modules.core.factory.__file__` — three levels up — and honours no
override. So any in-process `create_app()` reads and writes the checkout's own
directories, whatever `tmp_path` or env var the test set up. Thirteen test
files do that, and several believed they were isolated: they set `DATA_DIR`,
`CERTMATE_DATA_DIR`, `CERTMATE_LOGS_DIR`, none of which that function reads.

Two consequences, and the second is the one that matters:

* running the suite mutates the developer's own instance, and
* a test can pass on state an earlier run left behind — an assertion that
  passes for that reason looks exactly like one that passes because the code
  is right.

`tests/conftest.py` anchors `factory.__file__` at a temporary tree for the
whole session, which is how the rest of this repo already isolates
(test_csp_img_src_airgap.py, test_advertised_endpoints_exist.py). This file
guards that anchor, because the property is invisible: it regresses silently
the moment a fixture builds an app before the anchor is in place, which is
exactly how it was broken to begin with (#702).
"""
import os
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_DIRS = ('certificates', 'data', 'backups', 'logs')


def _build_an_app(tmp_path):
    """Whatever this leaves behind is what a test leaves behind."""
    from modules.core import factory
    factory._flask_app = None
    app, container = factory.create_app(test_config={'TESTING': True})
    if container.scheduler:
        container.scheduler.shutdown(wait=False)
    return container


def test_building_an_app_stays_out_of_the_checkout(tmp_path):
    """The property itself, asserted on the paths the app actually resolves.

    Cheaper and far more specific than diffing directory trees: if these point
    inside the working copy, everything else in this file is academic.
    """
    container = _build_an_app(tmp_path)

    for attribute in ('cert_dir', 'data_dir', 'backup_dir', 'logs_dir'):
        resolved = getattr(container, attribute, None)
        assert resolved, f'container exposes no {attribute}'
        resolved = Path(resolved).resolve()
        assert REPO_ROOT not in resolved.parents and resolved != REPO_ROOT, (
            f'{attribute} resolved to {resolved}, inside the checkout — '
            f'running the suite would read and write the developer\'s own '
            f'instance'
        )


def test_the_anchor_is_actually_in_place():
    """CONTROL: names the mechanism, so a failure says what to fix.

    Without this, the check above could pass because `create_app` changed
    rather than because the isolation works, and the next person would have no
    idea where to look.
    """
    from modules.core import factory

    anchored = Path(factory.__file__).resolve()
    assert REPO_ROOT not in anchored.parents, (
        f'modules.core.factory.__file__ is {anchored} — the session anchor in '
        f'tests/conftest.py is not in effect, so every in-process create_app() '
        f'is writing to the working tree'
    )


def test_the_templates_the_anchor_points_at_still_exist():
    """The anchor relocates more than the data directories.

    `factory.__file__` also locates `templates/` and `static/` (factory.py
    around :1305). An anchor without them breaks every page-rendering test —
    and only warns at startup, so the first symptom is a confusing failure
    somewhere else entirely.
    """
    root = Path(__file__).resolve()
    from modules.core import factory
    anchored_root = Path(factory.__file__).resolve().parent.parent.parent

    for shared in ('templates', 'static'):
        assert (anchored_root / shared).is_dir(), (
            f'{shared}/ is missing from the anchored tree at {anchored_root}; '
            f'template rendering will fail in a way that does not name this '
            f'as the cause'
        )
    assert root.exists()


def test_the_runtime_directories_are_git_ignored():
    """Belt and braces for the day the anchor is broken again.

    If these were tracked, a broken anchor would not merely dirty the working
    copy — it would put test output in a commit.
    """
    import subprocess

    for name in RUNTIME_DIRS:
        target = REPO_ROOT / name
        if not target.exists():
            continue
        result = subprocess.run(
            ['git', 'check-ignore', '-q', str(target)],
            cwd=str(REPO_ROOT), capture_output=True)
        assert result.returncode == 0, (
            f'{name}/ is not git-ignored; anything a test writes there can be '
            f'committed by accident'
        )
        assert os.path.isdir(target)


def test_the_isolation_fixture_is_session_scoped():
    """CONTROL for the regression that actually happened.

    The checks above pass from inside a file whose own fixtures do not race the
    anchor — so they cannot see the failure mode this had: as a FUNCTION-scoped
    autouse fixture, a fixture defined in a test module runs first, and the app
    is built against the real tree before the anchor is applied. Measured, not
    assumed, by making the two print their order.

    Nothing in a per-test assertion can observe that from a file that is not
    itself affected, so the scope is pinned directly. If it is ever loosened,
    this says why it must not be.
    """
    from tests import conftest as suite_conftest

    fixture = getattr(suite_conftest, '_isolate_runtime_dirs')
    # pytest 9 exposes the marker as `_fixture_function_marker`; older
    # versions used `_pytestfixturefunction`. Read whichever is there rather
    # than pinning one, so this guard survives a pytest upgrade instead of
    # turning into a false alarm about the thing it is guarding.
    marker = (getattr(fixture, '_fixture_function_marker', None)
              or getattr(fixture, '_pytestfixturefunction', None))
    assert marker is not None, (
        f'_isolate_runtime_dirs is no longer a recognisable pytest fixture '
        f'({type(fixture).__name__}); this guard cannot see its scope'
    )
    assert marker.scope == 'session', (
        f'the runtime-directory anchor is {marker.scope}-scoped. At function '
        f'scope it loses to fixtures defined in test modules, which then build '
        f'the app against the checkout before the anchor exists — the exact '
        f'shape of #702.'
    )
    assert marker.autouse is True, (
        'the anchor must be autouse; a fixture nobody requests protects nothing'
    )
