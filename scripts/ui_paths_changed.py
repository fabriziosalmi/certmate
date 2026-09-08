#!/usr/bin/env python3
"""Decide whether a pull request can affect the Playwright UI suite.

This used to be a `paths:` filter on `ui-tests.yml`'s trigger. That made the
whole workflow — and therefore any gate job inside it — fail to start on most
pull requests, so the UI suite could never be a required check: a required
context that never reports leaves the pull request pending forever.

Moving the filter here keeps the same limit (the suite is heavy and the
self-hosted host is single) while letting `ui-gate` run every time and answer
"skipped, and that is a pass". Being a real file rather than a heredoc, the
path list has one home and the matching is under test — see
tests/test_required_checks_registry.py.

Usage:
    ui_paths_changed.py <base-sha>      # writes `ui=true|false` on stdout
"""
import fnmatch
import subprocess
import sys

# A change to any of these can change what the UI suite sees. A trailing `/*`
# means "this directory and everything under it".
PATTERNS = [
    'templates/*',
    'static/*',
    'tests/test_ui.py',
    'tests/conftest.py',
    'Dockerfile',
    '.github/workflows/ui-tests.yml',
    'scripts/ui_paths_changed.py',
]


def matches(path, patterns=PATTERNS):
    """True when `path` is one of the watched files or lives under one of the
    watched directories.

    `fnmatch`'s `*` crosses `/`, so `templates/*` covers `templates/a/b.html`
    as well as `templates/index.html` — which is what the trigger did.
    """
    return any(path == p or fnmatch.fnmatch(path, p) for p in patterns)


def decide(changed):
    """Whether to run the suite, given the files a pull request touched.

    An empty list means the diff could not be computed — an unfetched base,
    most often — not that nothing changed. Run the suite rather than report a
    pass nobody measured.
    """
    if not changed:
        return True, []
    hit = [f for f in changed if matches(f)]
    return bool(hit), hit


def changed_files(base_sha):
    return subprocess.run(
        ['git', 'diff', '--name-only', f'{base_sha}...HEAD'],
        capture_output=True, text=True, check=True).stdout.split()


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    changed = changed_files(argv[1])
    run, hit = decide(changed)
    print(f'ui={"true" if run else "false"}')
    print(f'::notice::UI suite {"runs" if run else "skipped"}; '
          f'{len(changed)} file(s) changed, {len(hit)} of them frontend',
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
