"""The per-module coverage floors, and the ways they could stop being a gate.

`scripts/check_coverage_floors.py` is the durable half of #662. The tests that
raised coverage are worth little on their own: coverage decays, and a single
project-wide `--cov-fail-under` cannot notice one module going dark — that is
precisely how `resources_ca.py` reached 11% while the project number stayed
green.

So the floors are the thing that has to keep working, and a checker has three
ways to stop checking while still exiting zero:

* a module drops below its floor and nothing says so;
* a module with a floor disappears from the report, taking its floor with it;
* a new module in the layer arrives with no floor at all.

Each is asserted here, because a gate that passes without gating is the
recurring shape of defect this project keeps finding — and this file's whole
job is to be the one that does not have it.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER = REPO_ROOT / 'scripts' / 'check_coverage_floors.py'


def _floors():
    namespace = {}
    exec(compile(CHECKER.read_text(encoding='utf-8'), str(CHECKER), 'exec'),
         namespace)
    return namespace['FLOORS']


def _report(overrides=None, drop=None, extra=None):
    """A coverage report shaped like the one pytest-cov writes."""
    files = {
        name: {'summary': {'percent_covered': float(floor) + 5.0,
                           'num_statements': 100, 'covered_lines': int(floor) + 5}}
        for name, floor in _floors().items()
    }
    for name, value in (overrides or {}).items():
        files[name]['summary']['percent_covered'] = value
    for name in (drop or []):
        files.pop(name)
    for name, value in (extra or {}).items():
        files[name] = {'summary': {'percent_covered': value,
                                   'num_statements': 50, 'covered_lines': 5}}
    return {'files': files, 'totals': {'percent_covered': 80.0}}


def _run(report, tmp_path):
    path = tmp_path / 'coverage.json'
    path.write_text(json.dumps(report), encoding='utf-8')
    return subprocess.run([sys.executable, str(CHECKER), str(path)],
                          capture_output=True, text=True)


def test_a_report_that_meets_every_floor_passes(tmp_path):
    """CONTROL first: a checker that failed on everything would satisfy every
    case below while blocking every build."""
    result = _run(_report(), tmp_path)
    assert result.returncode == 0, result.stderr


def test_a_module_below_its_floor_fails(tmp_path):
    result = _run(_report(overrides={'modules/api/resources_ca.py': 11.0}),
                  tmp_path)
    assert result.returncode == 1
    assert 'resources_ca' in result.stderr


def test_a_module_that_vanishes_from_the_report_fails(tmp_path):
    """Renaming or deleting a file must not silently retire its floor."""
    result = _run(_report(drop=['modules/web/settings_routes.py']), tmp_path)
    assert result.returncode == 1
    assert 'settings_routes' in result.stderr
    assert 'does not appear' in result.stderr


def test_a_new_http_module_without_a_floor_fails(tmp_path):
    """A new endpoint module must not arrive unguarded — that is how the worst
    offender got to 11% in the first place."""
    result = _run(_report(extra={'modules/api/resources_brandnew.py': 12.0}),
                  tmp_path)
    assert result.returncode == 1
    assert 'resources_brandnew' in result.stderr


def test_an_empty_report_is_an_error_not_a_pass(tmp_path):
    """A run that measured nothing must not read as a run that met every floor."""
    result = _run({'files': {}, 'totals': {}}, tmp_path)
    assert result.returncode == 2
    assert 'no files' in result.stderr


def test_a_missing_report_is_an_error(tmp_path):
    result = subprocess.run(
        [sys.executable, str(CHECKER), str(tmp_path / 'nope.json')],
        capture_output=True, text=True)
    assert result.returncode == 2


def test_every_floor_names_a_file_that_exists(tmp_path):
    """The floors list is maintained by hand; this keeps it honest against the
    tree rather than only against a report."""
    missing = [name for name in _floors() if not (REPO_ROOT / name).exists()]
    assert not missing, (
        f'these modules have floors but no longer exist: {missing}'
    )


def test_every_http_module_has_a_floor():
    """The other direction, checked against the tree rather than a report, so a
    new module is caught even before anyone runs coverage."""
    floors = set(_floors())
    on_disk = {
        str(path.relative_to(REPO_ROOT))
        for directory in ('modules/api', 'modules/web')
        for path in (REPO_ROOT / directory).glob('*.py')
    }
    assert not (on_disk - floors), (
        f'these HTTP-layer modules have no coverage floor: '
        f'{sorted(on_disk - floors)}'
    )


def test_the_checker_is_wired_into_ci():
    """A floor nobody runs is documentation."""
    workflow = (REPO_ROOT / '.github' / 'workflows' / 'ci.yml').read_text(
        encoding='utf-8')
    assert 'check_coverage_floors.py' in workflow, (
        'the floors are not enforced by the everyday gate, which is the half '
        'of #662 that matters'
    )
    assert '--cov-report=json' in workflow, (
        'the checker needs the JSON report the test step must produce'
    )
