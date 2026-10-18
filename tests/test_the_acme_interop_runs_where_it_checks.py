"""The ACME interoperability run starts on the pull requests that can change what it checks.

tests/interop/run.sh runs weekly on main and, through
scripts/acme_paths_changed.py, on a pull request that touches the ACME server,
what it leans on, the image, or the run itself. The filter fails open, so the
list has to name paths that exist, and a pull request that touches none of
them has to be able to skip it.
"""
import importlib.util
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('acme_paths_changed', REPO / 'scripts' / 'acme_paths_changed.py')
acmefilter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acmefilter)


def _job():
    return yaml.safe_load((REPO / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8'))['jobs']['acme-interop']


def test_the_job_calls_the_filter_and_runs_the_harness_only_when_it_says_so():
    steps = _job()['steps']
    scope = next(s for s in steps if s.get('id') == 'scope')
    assert 'scripts/acme_paths_changed.py' in scope['run']
    harness = next(s for s in steps if s.get('run') == 'tests/interop/run.sh')
    assert harness['if'] == "steps.scope.outputs.acme == 'true'"
    assert 'pull_request' in _job()['if'] and 'schedule' in _job()['if']


def test_the_job_fetches_the_history_the_diff_needs():
    """A shallow checkout has no base to diff against: the filter would see an
    empty diff and run every time, which is safe and pointless."""
    checkout = _job()['steps'][0]
    assert checkout['with']['fetch-depth'] == 0


def test_every_watched_path_still_exists():
    for pattern in acmefilter.PATTERNS:
        if pattern.endswith('/*'):
            found = (REPO / pattern[:-2]).is_dir()
        else:
            found = any(REPO.glob(pattern))
        assert found, f'{pattern!r} no longer exists, so changes to it would skip the run'


def test_every_acme_module_is_watched():
    modules = sorted(str(p.relative_to(REPO)) for p in (REPO / 'modules').rglob('acme*.py'))
    assert len(modules) >= 8, modules       # CONTROL: the glob still finds the ACME server
    unwatched = [m for m in modules if not acmefilter.matches(m)]
    assert unwatched == [], f'changed without the interoperability run: {unwatched}'


@pytest.mark.parametrize('path, watched', [
    ('modules/core/acme_server.py', True),
    ('modules/core/acme_store.py', True),
    ('modules/web/acme_routes.py', True),
    ('modules/core/private_ca.py', True),
    ('modules/core/pinned_https.py', True),
    ('modules/core/rate_limit.py', True),
    ('modules/factory.py', True),
    ('Dockerfile', True),
    ('requirements.lock', True),
    ('tests/interop/run.sh', True),
    ('tests/interop/front.conf', True),
    ('.github/workflows/ci.yml', True),
    ('scripts/acme_paths_changed.py', True),
    ('modules/core/certificates.py', False),
    ('modules/web/settings_routes.py', False),
    ('templates/index.html', False),
    ('docs/acme-server.md', False),
    ('requirements-test.txt', False),
    ('README.md', False),
])
def test_the_matcher_watches_what_the_run_is_made_of(path, watched):
    assert acmefilter.matches(path) is watched


def test_an_uncomputable_diff_runs_it():
    assert acmefilter.decide([]) == (True, [])


def test_a_change_elsewhere_skips_it():
    """CONTROL: the filter must still be able to say no."""
    assert acmefilter.decide(['modules/core/certificates.py', 'docs/api.md']) == (False, [])
