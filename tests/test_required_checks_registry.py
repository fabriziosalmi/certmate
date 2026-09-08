"""The set of merge-gating CI jobs must be visible in the repository.

Branch protection lives in GitHub's settings. Nobody without admin rights can
read it, nothing records why a job is or is not in it, and it drifts silently.
An audit found what that costs here: the repository ran a Playwright UI suite,
a Trivy image scan, a CSS staleness gate and an MCP suite on every pull
request, and none of them could block a merge. Five contexts gated; four jobs
did the work and were thrown away.

`.github/required-checks.yml` is the reviewable copy of that decision. GitHub
does not read it — protection still has to be set through the API — so on its
own it is a comment that goes stale. These tests are what make it worth having:

* every job that can run on a pull request is classified, so a new job cannot
  arrive without someone saying whether it gates;
* every classified job still exists, so deleting or renaming one is caught;
* the context strings match what GitHub will actually publish, including the
  matrix suffix — a required context that no job ever reports leaves every
  pull request pending forever, which is the failure mode that hurts most;
* nothing quietly drops out of the gating set.

The one thing they cannot check is the live protection setting, which needs an
admin token. `.github/required-checks.yml` carries the command that applies it.
"""
import importlib.util
import itertools
import re
import sys
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / '.github' / 'workflows'
REGISTRY = REPO / '.github' / 'required-checks.yml'


def _load_script(name):
    """`scripts/` is not a package; load the module from its path."""
    spec = importlib.util.spec_from_file_location(
        name, REPO / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


uifilter = _load_script('ui_paths_changed')

# What branch protection required on 2026-09-08, before this file existed. A
# gate may be added, and one may be removed deliberately by editing this list —
# but not by an edit to the registry alone.
GATING_FLOOR = {
    'build', 'test (3.12)', 'Analyze python', 'Analyze javascript', 'emoji',
}


def _load(path):
    return yaml.safe_load(path.read_text())


def _triggers(workflow):
    """`on:` parses as the boolean True under YAML 1.1, not the string 'on'."""
    return workflow.get(True) or workflow.get('on') or {}


def _skipped_on_pull_request(condition):
    """True when a job's `if` can only hold for events other than a PR.

    `github.event_name != 'schedule'` still runs on a pull request; a guard
    built only from `== 'schedule'` / `== 'workflow_dispatch'` never does.
    """
    if not condition:
        return False
    equals = re.findall(r"github\.event_name\s*==\s*'([a-z_]+)'",
                        ' '.join(str(condition).split()))
    return bool(equals) and 'pull_request' not in equals


def _contexts(job_id, job):
    """The check names GitHub publishes for one job definition.

    GitHub appends the matrix values in parentheses only when the job has no
    explicit `name:`. With one, the interpolated name is used verbatim. Both
    halves are visible in this repository today: `test` has no name and reports
    as `test (3.12)`, while `analyze` is named `Analyze ${{ matrix.language }}`
    and reports as `Analyze python` with no suffix.
    """
    name = job.get('name')
    matrix = (job.get('strategy') or {}).get('matrix') or {}
    dims = {k: v for k, v in matrix.items()
            if isinstance(v, list) and k not in ('include', 'exclude')}
    if not dims:
        return [name or job_id]
    out = []
    for combo in itertools.product(*dims.values()):
        values = dict(zip(dims, combo))
        if name:
            label = name
            for key, value in values.items():
                label = label.replace('${{ matrix.%s }}' % key, str(value))
                label = label.replace('${{matrix.%s}}' % key, str(value))
        else:
            label = '%s (%s)' % (job_id, ', '.join(str(v) for v in combo))
        out.append(label)
    return out


def pull_request_jobs():
    """Every (workflow file, job id, job body) that a pull request can run."""
    found = []
    for path in sorted(WORKFLOWS.glob('*.yml')):
        workflow = _load(path)
        if 'pull_request' not in _triggers(workflow):
            continue
        for job_id, job in (workflow.get('jobs') or {}).items():
            if _skipped_on_pull_request(job.get('if')):
                continue
            found.append((path.name, job_id, job))
    return found


@pytest.fixture(scope='module')
def registry():
    return _load(REGISTRY)


@pytest.fixture(scope='module')
def entries(registry):
    return [dict(e, gating=True) for e in registry['gating']] + \
           [dict(e, gating=False) for e in registry['advisory']]


def test_every_pull_request_job_is_classified(entries):
    """A new job cannot arrive without someone deciding whether it gates."""
    classified = {(e['workflow'], e['job']) for e in entries}
    actual = {(wf, job_id) for wf, job_id, _ in pull_request_jobs()}

    missing = actual - classified
    assert not missing, (
        'these jobs run on pull requests but .github/required-checks.yml does '
        'not say whether they gate a merge: '
        + ', '.join(sorted('%s:%s' % m for m in missing))
    )


def test_every_classified_job_still_exists(entries):
    classified = {(e['workflow'], e['job']) for e in entries}
    actual = {(wf, job_id) for wf, job_id, _ in pull_request_jobs()}

    stale = classified - actual
    assert not stale, (
        'these entries name a job that no longer runs on pull requests: '
        + ', '.join(sorted('%s:%s' % s for s in stale))
    )


def test_contexts_match_what_github_will_publish(entries):
    """The failure this guards is silent and total: a required context that no
    job ever reports keeps every pull request pending, with a green board."""
    published = {}
    for wf, job_id, job in pull_request_jobs():
        for context in _contexts(job_id, job):
            published[context] = (wf, job_id)

    for entry in entries:
        assert entry['context'] in published, (
            '%s declares context %r, but %s:%s publishes %r'
            % (REGISTRY.name, entry['context'], entry['workflow'],
               entry['job'],
               _contexts(entry['job'],
                         _load(WORKFLOWS / entry['workflow'])
                         ['jobs'][entry['job']]))
        )


def test_a_matrix_job_declares_every_context_it_publishes(entries):
    """Half a matrix is worse than none: bumping Python to 3.12 and 3.13 with
    only `test (3.12)` required means the new one gates nothing."""
    declared = {e['context'] for e in entries}
    for wf, job_id, job in pull_request_jobs():
        for context in _contexts(job_id, job):
            assert context in declared, (
                '%s:%s publishes context %r, which is in neither list'
                % (wf, job_id, context)
            )


def test_the_gating_set_never_silently_shrinks(registry):
    gating = {e['context'] for e in registry['gating']}
    lost = GATING_FLOOR - gating
    assert not lost, (
        'these contexts gated merges before the registry existed and are no '
        'longer listed as gating: ' + ', '.join(sorted(lost))
    )


def test_every_advisory_job_says_why_it_does_not_gate(registry):
    """Advisory is a decision, not a default. Whoever reads this file next
    should be able to disagree with the reason."""
    for entry in registry['advisory'] + registry['external']:
        why = (entry.get('why') or '').strip()
        assert len(why) > 40, (
            '%s is advisory with no usable reason: %r'
            % (entry['context'], why)
        )


def test_external_contexts_are_kept_separate_from_workflow_jobs(registry):
    """Codecov and the code-scanning umbrella report on every pull request and
    gate nothing, which is exactly the situation this file exists to record —
    but they come from GitHub Apps, so no workflow file mentions them and the
    cross-checks above are structurally blind to them. They get their own
    section rather than being quietly omitted."""
    for entry in registry['external']:
        assert entry.get('source'), (
            '%s does not say which app posts it' % entry['context'])
        assert 'workflow' not in entry, (
            '%s names a workflow; if a job in this repository posts it, it '
            'belongs in gating or advisory where it can be cross-checked'
            % entry['context'])

    published = {c for wf, job_id, job in pull_request_jobs()
                 for c in _contexts(job_id, job)}
    overlap = {e['context'] for e in registry['external']} & published
    assert not overlap, (
        'these are listed as external but a workflow job publishes them: '
        + ', '.join(sorted(overlap))
    )


def test_no_context_is_declared_twice(entries, registry):
    seen = [e['context'] for e in entries] + \
           [e['context'] for e in registry['external']]
    assert len(seen) == len(set(seen)), 'duplicate context in %s' % REGISTRY.name


def test_the_ui_gate_is_required_and_the_ui_job_is_not(registry):
    """The specific arrangement that makes a path-limited suite gateable.
    Requiring `ui` directly would leave every non-frontend PR pending."""
    gating = {e['context'] for e in registry['gating']}
    advisory = {e['context'] for e in registry['advisory']}
    assert 'ui-gate' in gating
    assert 'ui' in advisory

    ui = _load(WORKFLOWS / 'ui-tests.yml')
    assert 'paths' not in _triggers(ui)['pull_request'], (
        'the path filter is back on the trigger, so the whole workflow — '
        'ui-gate included — does not start on most PRs, and every PR that '
        'requires ui-gate hangs'
    )
    assert ui['jobs']['ui-gate']['if'] == 'always()'


def test_the_workflow_calls_the_filter_it_is_documented_to_call():
    source = (WORKFLOWS / 'ui-tests.yml').read_text()
    assert 'scripts/ui_paths_changed.py' in source, (
        'the changes job no longer runs the filter these tests cover'
    )


def test_the_ui_path_list_still_names_real_paths():
    """The filter used to be a trigger, where a renamed directory failed
    loudly (the workflow stopped running and someone noticed). Here it fails
    open — the suite is skipped and the gate reports a pass — so the list has
    to be checked against the tree."""
    assert {'templates/*', 'static/*', 'tests/test_ui.py'} <= set(uifilter.PATTERNS)
    for pattern in uifilter.PATTERNS:
        target = REPO / pattern.rstrip('/*')
        assert target.exists(), (
            '%r no longer exists, so changes to it would skip the UI suite'
            % pattern
        )


@pytest.mark.parametrize('path, watched', [
    ('templates/index.html', True),
    ('templates/partials/settings_deploy.html', True),
    ('static/js/settings-deploy.js', True),
    ('static/css/dist/output.css', True),
    ('Dockerfile', True),
    ('tests/conftest.py', True),
    ('.github/workflows/ui-tests.yml', True),
    ('scripts/ui_paths_changed.py', True),
    ('modules/core/auth.py', False),
    ('tests/test_ui_helpers.py', False),
    ('README.md', False),
    ('Dockerfile.dev', False),
    ('staticfiles/app.js', False),
])
def test_the_matcher_agrees_with_what_the_trigger_used_to_do(path, watched):
    assert uifilter.matches(path) is watched


def test_an_uncomputable_diff_runs_the_suite():
    """Failing open here would report a UI pass on a PR nobody looked at. An
    empty diff means the base was not fetched far more often than it means a
    PR changed nothing."""
    assert uifilter.decide([]) == (True, [])


def test_a_backend_only_change_skips_the_suite():
    """CONTROL: the filter must still be capable of saying no, or the whole
    point of moving it (sparing the single self-hosted host) is lost."""
    run, hit = uifilter.decide(['modules/core/auth.py', 'README.md'])
    assert (run, hit) == (False, [])


# --- controls on the helpers themselves ---------------------------------
# These tests exist because the checks above are only as good as the two
# functions they rest on, and a wrong helper would report a clean registry.

@pytest.mark.parametrize('condition, skipped', [
    (None, False),
    ("github.event_name != 'schedule'", False),
    ("needs.changes.outputs.ui == 'true'", False),
    ('always()', False),
    ("github.event_name == 'schedule'", True),
    ("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
     True),
    ("github.event_name == 'pull_request'", False),
])
def test_the_pull_request_guard_reader_is_right(condition, skipped):
    assert _skipped_on_pull_request(condition) is skipped


@pytest.mark.parametrize('job_id, job, expected', [
    ('emoji', {}, ['emoji']),
    ('mcp', {'name': 'MCP server'}, ['MCP server']),
    ('test', {'strategy': {'matrix': {'python-version': ['3.12']}}},
     ['test (3.12)']),
    ('test', {'strategy': {'matrix': {'python-version': ['3.12', '3.13']}}},
     ['test (3.12)', 'test (3.13)']),
    ('analyze', {'name': 'Analyze ${{ matrix.language }}',
                 'strategy': {'matrix': {'language': ['python', 'javascript']}}},
     ['Analyze python', 'Analyze javascript']),
])
def test_the_context_deriver_matches_githubs_naming(job_id, job, expected):
    assert _contexts(job_id, job) == expected


def test_the_classification_check_would_actually_fail(monkeypatch, entries):
    """CONTROL: prove the missing-job assertion is reachable. Two of these
    suites have passed while measuring nothing; this one says why it passes."""
    monkeypatch.setattr(
        sys.modules[__name__], 'pull_request_jobs',
        lambda: [('ci.yml', 'a-job-nobody-classified', {})])
    with pytest.raises(AssertionError, match='a-job-nobody-classified'):
        test_every_pull_request_job_is_classified(entries)
