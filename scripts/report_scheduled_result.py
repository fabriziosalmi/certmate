#!/usr/bin/env python3
"""Turn the result of a scheduled check into an issue, because a red scheduled run is read by nobody.

The weekly run of ci.yml (Mondays 06:00 UTC) went red on 4 of its last 6 runs
and nothing happened: a failed scheduled workflow notifies whoever last edited
its cron line, and that is not a standing reader. An issue in this repository
is.

    report_scheduled_result.py <job> <result> [--run-url URL]

<result> is the job's `needs.<job>.result`. One open issue per job:

* `failure`: open it, or add a line to it when it is already open (a standing
  failure says so each week, with the run that saw it);
* `success`: close it, saying which run found the check green again;
* anything else (`skipped`, `cancelled`): nothing. A run that did not reach the
  check says nothing about it.

WHICH JOBS. This opens a public issue, so it is for checks whose failure is
fine to say in public: whether a CA's directory is reachable, whether the wiki
has drifted from the repository. `advisories` is deliberately NOT here: a
failure there means a dependency advisory is open and not yet written down, and
an issue titled so would say it to everyone before it is fixed. It stays a red
run until it has a private channel. REPORTED and NOT_REPORTED below are the
whole list of scheduled-only jobs, and a test fails when a job is in neither.

stdlib only; talks to GitHub through the `gh` CLI (GH_TOKEN and GH_REPO in the
environment, as the workflow provides them).
"""
import argparse
import json
import subprocess
import sys

# Scheduled-only jobs whose failure may be said in public.
REPORTED = ('ca-endpoints', 'wiki', 'wiki-endpoints')
# Scheduled-only jobs that are not, and why.
NOT_REPORTED = {
    'advisories': 'a failure means an advisory is open and not yet written down: not for a public issue',
}


def title_for(job):
    return f'Scheduled check failed: {job}'


def gh(*arguments):
    """Run `gh`; the one place that talks to GitHub, replaced in the tests."""
    result = subprocess.run(['gh', *arguments], capture_output=True, text=True)  # noqa: S603,S607
    if result.returncode != 0:
        raise RuntimeError(f'gh {" ".join(arguments[:2])} failed: {result.stderr.strip()[:300]}')
    return result.stdout


def open_issue(job, run=gh):
    """The number of the open issue for `job`, or None."""
    listed = json.loads(run('issue', 'list', '--state', 'open', '--limit', '200',
                            '--json', 'number,title') or '[]')
    return next((item['number'] for item in listed if item['title'] == title_for(job)), None)


def report(job, result, run_url, run=gh):
    """What was done, in a word: opened, commented, closed or nothing."""
    if job not in REPORTED:
        raise ValueError(f'{job} is not a job this reports: {NOT_REPORTED.get(job, "it is not a known scheduled job")}')
    existing = open_issue(job, run)
    where = f'Run: {run_url}' if run_url else 'Run: (no URL given)'
    if result == 'success':
        if existing is None:
            return 'nothing'
        run('issue', 'close', str(existing), '--comment', f'The check passed again. {where}')
        return 'closed'
    if result != 'failure':
        return 'nothing'
    if existing is None:
        body = (f'The scheduled `{job}` check of the weekly CI run failed.\n\n{where}\n\n'
                f'This issue closes itself when the check passes again.')
        run('issue', 'create', '--title', title_for(job), '--body', body)
        return 'opened'
    run('issue', 'comment', str(existing), '--body', f'Still failing. {where}')
    return 'commented'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('job')
    parser.add_argument('result')
    parser.add_argument('--run-url', default='')
    arguments = parser.parse_args(argv)
    try:
        print(f'{arguments.job}: {report(arguments.job, arguments.result, arguments.run_url)}')
    except (ValueError, RuntimeError) as error:
        print(f'::error::{error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
