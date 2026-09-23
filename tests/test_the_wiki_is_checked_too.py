"""The wiki checker must exist, something must run it, and it must refuse to
report success when it read nothing.

CertMate documents its API in four places. Three of them are in this
repository and two tests cover them in both directions:
test_advertised_endpoints_exist.py asks whether every documented endpoint
exists, and test_the_api_surface_is_documented.py asks the reverse. The fourth
is the wiki, a separate git repository, and neither test can see it.

It rotted accordingly. Twenty-seven days and seven releases after its last
edit, the Multi-Account Support section of DNS-Providers.md carried six
copy-pasteable curl commands that all answered 404 - against a prefix that does
not exist and a `default-account` endpoint that never has. This repository
carries a test asserting that `default-account` has never existed. It could not
see the page that documented it, and the website links readers straight to that
page.

This file asserts the wiring and the refusal to pass quietly, not the
comparison logic. That was verified by running the script against the wiki
before the fix, where it names the offending line, and after, where it exits 0
having read 62 stated endpoints.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / 'scripts' / 'check_wiki_endpoints.py'
WORKFLOW = REPO / '.github' / 'workflows' / 'ci.yml'


def test_the_checker_exists():
    assert SCRIPT.exists(), f'{SCRIPT.relative_to(REPO)} is missing'


def test_something_runs_it():
    text = WORKFLOW.read_text(encoding='utf-8')
    assert 'check_wiki_endpoints.py' in text, (
        'no workflow runs scripts/check_wiki_endpoints.py, so the wiki is '
        'unchecked again'
    )
    assert 'wiki.git' in text, (
        'the workflow does not fetch the wiki; the checker would have nothing '
        'to read'
    )


def test_it_runs_on_a_schedule_rather_than_on_every_push():
    """Editing the wiki does not run this workflow, so a merge gate would only
    ever check the wiki at the moments it had not changed. Weekly is the shape
    that can actually catch a wiki edit, and it is what `advisories` does for
    the same kind of reason."""
    text = WORKFLOW.read_text(encoding='utf-8')
    block = text.split('wiki-endpoints:', 1)[1][:400]
    assert "github.event_name == 'schedule'" in block, (
        'the wiki job does not run on the schedule, so nothing will check the '
        'wiki between one manual run and the next'
    )


def test_it_refuses_to_pass_on_a_wiki_it_did_not_read(tmp_path):
    """The failure this job exists to prevent is a check that reports success
    on documentation nothing looked at. An empty directory is that case."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path)],
        capture_output=True, text=True, cwd=REPO,
    )

    assert result.returncode != 0, (
        'the checker reported success on a directory with no wiki in it'
    )
    assert 'no .md files' in result.stderr


def test_the_verbs_are_unioned_across_matching_rules():
    """The trap this script fell into on its first run, kept as a rule.

    `/api/certificates/create` and `/api/certificates/<domain>` have the same
    shape, so taking the verbs of the FIRST matching rule reports a documented
    `GET /api/certificates/<domain>` as a path that "accepts POST". That
    produced three false positives out of six findings before it was fixed, and
    test_advertised_endpoints_exist.py carries the same warning about the same
    mistake.
    """
    source = SCRIPT.read_text(encoding='utf-8')
    body = re.search(r'def verbs_for\(.*?\n(?=\n\ndef )', source, re.S)
    assert body, 'verbs_for() is gone; this control no longer checks anything'
    assert 'verbs |=' in body.group(0), (
        'verbs_for() no longer unions the verbs of every matching rule, so it '
        'will report correct documentation as wrong'
    )


def test_a_wiki_placeholder_does_not_match_a_fixed_route_segment():
    """A placeholder in the wiki stands for a value, not for a route's fixed
    name. Matching both ways made `/api/{x}/create` look served because
    `/api/certificates/create` is, which is exactly the kind of invented path
    this checker exists to catch."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('check_wiki_endpoints', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    table = {'/api/certificates/create': {'POST'}, '/api/certificates/<X>': {'GET'}}
    # A worked example still resolves to the parameterised route...
    assert module.verbs_for('/api/certificates/example.com', table) == (True, {'GET'})
    # ...a wiki placeholder matches a route placeholder...
    assert module.verbs_for('/api/certificates/<X>', table) == (True, {'GET'})
    # ...and never a fixed segment it merely lines up with.
    assert module.verbs_for('/api/<X>/create', table) == (False, set())
