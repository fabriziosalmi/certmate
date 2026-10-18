#!/usr/bin/env python3
"""Decide whether a pull request can change what the ACME interoperability run checks.

tests/interop/run.sh builds CertMate's image and has lego and acme.sh register,
get, renew and revoke certificates against its ACME server. It runs weekly on
main, and on a pull request only when the pull request touches what the run
is made of: running it on every pull request would pull three images from
Docker Hub for changes it cannot see, and running it only weekly found a
regression up to a week after it was merged.

The same shape as scripts/ui_paths_changed.py, for the same reason: the job
always starts, and answers "not run" when nothing it checks changed.

Usage:
    acme_paths_changed.py <base-sha>      # writes `acme=true|false` on stdout
"""
import fnmatch
import subprocess
import sys

# What the run is made of. A trailing `/*` means "this directory and
# everything under it".
#
# The ACME server is modules/core/acme_* and modules/web/acme_routes.py. The
# glob also takes acme_profiles.py, which is the ACME client's: a run too many
# costs a few minutes, a server module left out would cost a regression. Three
# modules the server leans on: private_ca.py makes its CA, pinned_https.py
# guards the address http-01 fetches, and rate_limit.py holds the limit on
# /acme/. factory.py wires the routes and the limiter. The image is built from
# the Dockerfile and the default requirement set.
PATTERNS = [
    'modules/core/acme_*',
    'modules/web/acme_routes.py',
    'modules/core/private_ca.py',
    'modules/core/pinned_https.py',
    'modules/core/rate_limit.py',
    'modules/factory.py',
    'Dockerfile',
    'requirements.txt',
    'requirements.lock',
    'requirements.constraints',
    'tests/interop/*',
    '.github/workflows/ci.yml',
    'scripts/acme_paths_changed.py',
]


def matches(path, patterns=PATTERNS):
    """True when `path` is one of the watched files or lives under one of the
    watched directories. `fnmatch`'s `*` crosses `/`."""
    return any(path == p or fnmatch.fnmatch(path, p) for p in patterns)


def decide(changed):
    """Whether to run, given the files a pull request touched.

    An empty list means the diff could not be computed, an unfetched base most
    often, not that nothing changed: run rather than report a pass nobody
    measured.
    """
    if not changed:
        return True, []
    hit = [f for f in changed if matches(f)]
    return bool(hit), hit


def changed_files(base_sha):
    return subprocess.run(  # noqa: S603  git on the PATH of a CI runner, a fixed argument list
        ['git', 'diff', '--name-only', f'{base_sha}...HEAD'],  # noqa: S607
        capture_output=True, text=True, check=True).stdout.split()


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    changed = changed_files(argv[1])
    run, hit = decide(changed)
    print(f'acme={"true" if run else "false"}')
    print(f'::notice::ACME interoperability run {"runs" if run else "skipped"}; '
          f'{len(changed)} file(s) changed, {len(hit)} of them what it checks',
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
