"""A scheduled check that fails is turned into an issue, except where the issue would say too much.

The weekly run went red on four of its last six runs and nobody was told. The
workflow now reports each non-sensitive scheduled check; `advisories` is
excluded because its failure means an advisory is open and not yet written down.
These tests keep the workflow and the script in step, and run the script against
a fake `gh`.
"""
import importlib.util
import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / '.github' / 'workflows' / 'ci.yml'

pytestmark = [pytest.mark.unit]


def _load():
    spec = importlib.util.spec_from_file_location('report_scheduled_result', ROOT / 'scripts' / 'report_scheduled_result.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reporter = _load()


def _jobs():
    return yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))['jobs']


def _scheduled_only(jobs):
    return {name for name, job in jobs.items() if 'schedule' in str(job.get('if', '')) and "!= 'schedule'" not in str(job.get('if', ''))
            and name != 'report-scheduled'}


class FakeGh:
    """Records every call; `open_titles` is what `gh issue list` reports as open."""

    def __init__(self, open_titles=()):
        self.calls = []
        self.open = {number: title for number, title in enumerate(open_titles, start=100)}

    def __call__(self, *arguments):
        self.calls.append(arguments)
        if arguments[:2] == ('issue', 'list'):
            import json
            return json.dumps([{'number': n, 'title': t} for n, t in self.open.items()])
        return ''

    def verbs(self):
        return [call[:2] for call in self.calls if call[:2] != ('issue', 'list')]


# --- the workflow and the script agree on what is reported -------------------

def test_every_scheduled_only_job_is_reported_or_explicitly_not():
    scheduled = _scheduled_only(_jobs())
    assert scheduled, 'found no scheduled-only job: the detection is broken, not the workflow'
    assert scheduled == set(reporter.REPORTED) | set(reporter.NOT_REPORTED)


def test_advisories_is_not_reported_and_says_why():
    assert 'advisories' in reporter.NOT_REPORTED
    assert 'advisories' not in reporter.REPORTED
    assert reporter.NOT_REPORTED['advisories'].strip()


def test_the_reporting_job_waits_for_exactly_the_reported_jobs():
    job = _jobs()['report-scheduled']
    assert set(job['needs']) == set(reporter.REPORTED)
    assert 'advisories' not in str(job)


def test_the_reporting_job_runs_on_the_schedule_only_with_the_narrowest_write():
    job = _jobs()['report-scheduled']
    assert 'always()' in job['if'] and "== 'schedule'" in job['if']
    assert job['permissions'] == {'contents': 'read', 'issues': 'write'}


def test_the_job_reports_every_reported_job_with_its_own_result():
    steps = ' '.join(step.get('run', '') for step in _jobs()['report-scheduled']['steps'])
    for name in reporter.REPORTED:
        assert f'report_scheduled_result.py {name} "${{{{ needs.{name}.result }}}}"' in steps


# --- the script ---------------------------------------------------------------

def test_a_failure_opens_one_issue_naming_the_job_and_the_run():
    gh = FakeGh()
    assert reporter.report('wiki', 'failure', 'https://example/run/1', run=gh) == 'opened'
    (verb, *rest), = [c for c in gh.calls if c[:2] == ('issue', 'create')]
    assert reporter.title_for('wiki') in rest
    assert 'https://example/run/1' in rest[rest.index('--body') + 1]


def test_a_failure_while_the_issue_is_open_comments_instead_of_opening_another():
    gh = FakeGh([reporter.title_for('wiki')])
    assert reporter.report('wiki', 'failure', 'u', run=gh) == 'commented'
    assert gh.verbs() == [('issue', 'comment')]


def test_a_pass_closes_the_open_issue():
    gh = FakeGh([reporter.title_for('wiki')])
    assert reporter.report('wiki', 'success', 'u', run=gh) == 'closed'
    assert gh.verbs() == [('issue', 'close')]


def test_a_pass_with_nothing_open_does_nothing():
    gh = FakeGh()
    assert reporter.report('wiki', 'success', 'u', run=gh) == 'nothing'
    assert gh.verbs() == []


@pytest.mark.parametrize('result', ['skipped', 'cancelled', ''])
def test_a_run_that_did_not_reach_the_check_says_nothing_about_it(result):
    gh = FakeGh([reporter.title_for('wiki')])
    assert reporter.report('wiki', result, 'u', run=gh) == 'nothing'
    assert gh.verbs() == []


def test_another_jobs_issue_is_not_taken_for_this_ones():
    gh = FakeGh([reporter.title_for('ca-endpoints'), 'Scheduled check failed: wiki-endpoints'])
    assert reporter.report('wiki', 'failure', 'u', run=gh) == 'opened'


@pytest.mark.parametrize('job', ['advisories', 'test', 'nonsense'])
def test_a_job_that_is_not_reported_is_refused_before_any_call(job):
    gh = FakeGh()
    with pytest.raises(ValueError):
        reporter.report(job, 'failure', 'u', run=gh)
    assert gh.calls == []
