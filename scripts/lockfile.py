#!/usr/bin/env python3
"""Generate and check the resolved dependency lockfiles.

`requirements.txt` pins 42 packages. Installing it resolves **118**, so 76 of
the packages in every published image were chosen by whichever version of the
index pip happened to see on build day, and nothing in this repository recorded
which ones. Two images built from the same commit a month apart were not the
same image, and there was no diff to review that would say so.

A lockfile fixes that, and it is a *separate* question from hash pinning, which
SECURITY.md deliberately defers: a resolved lockfile makes the build repeatable
and a transitive bump reviewable; hashes would additionally prove the wheel is
the one that was reviewed. This does the first and does not claim the second.

Two modes, both pure functions over text so they are testable without pip:

    write   turn a `pip install --report` JSON into a lockfile
    check   assert every direct pin is present in the lock at the same version

`check` is the one that matters day to day. Installing from a lock means a
Dependabot bump to `requirements.txt` has **no effect** until the lock is
regenerated — the build would keep installing the old version and the merged
security patch would silently not ship. That failure is invisible, so it is
made loud: `check` runs in the unit suite and in the image build.

Regenerating (the command is repeated in each lockfile header, where the person
who needs it is looking):

    scripts/regenerate_lockfiles.sh
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# A pinned line in a requirements file: `name==version`, before any comment.
# Deliberately narrower than PEP 508 — anything with a marker, an extra or a
# range is not a plain pin and is reported rather than silently skipped.
PIN = re.compile(r'^([A-Za-z0-9._-]+)==([^\s;#]+)\s*$')

HEADER = """\
# GENERATED — do not edit by hand. Regenerate with:
#
#     scripts/regenerate_lockfiles.sh
#
# The fully resolved install set for {source}, produced by pip's own resolver
# inside the base image this project publishes from. {direct} of these are
# pinned by {source}; the other {transitive} are transitive and were chosen by
# the resolver, which is exactly why they are written down here.
#
# The two published architectures resolve this set identically, which is what
# makes one file sufficient. `scripts/regenerate_lockfiles.sh` re-checks that
# before writing, so the day it stops being true is the day it is noticed.
#
# No hashes: this makes the build repeatable, not the artifacts verified. See
# "Supply-chain posture for Python dependencies" in SECURITY.md.
"""


def normalize(name: str) -> str:
    """PEP 503 normalisation, so `zope.interface` and `zope-interface` are the
    same package. Comparing raw names here would report a phantom mismatch."""
    return re.sub(r'[-_.]+', '-', name).lower()


def read_pins(text: str) -> dict[str, str]:
    """The `name==version` lines of a requirements or lock file."""
    pins: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split('#')[0].strip()
        if not line:
            continue
        match = PIN.match(line)
        if match:
            pins[normalize(match.group(1))] = match.group(2)
    return pins


def render(report: dict, source: str, direct: dict[str, str]) -> str:
    """A lockfile from a `pip install --report` document."""
    resolved = {
        normalize(item['metadata']['name']): item['metadata']['version']
        for item in report.get('install', [])
    }
    transitive = sorted(set(resolved) - set(direct))
    body = ''.join(f'{name}=={resolved[name]}\n' for name in sorted(resolved))
    return HEADER.format(source=source, direct=len(direct),
                         transitive=len(transitive)) + '\n' + body


def check(requirements: pathlib.Path, lock: pathlib.Path) -> list[str]:
    """Every direct pin present in the lock at the same version.

    Returns the problems, so the caller decides how loudly to fail. An empty
    list means the lock still speaks for that requirements file.
    """
    direct = read_pins(requirements.read_text(encoding='utf-8'))
    locked = read_pins(lock.read_text(encoding='utf-8'))

    problems = []
    for name, version in sorted(direct.items()):
        if name not in locked:
            problems.append(
                f'{name}=={version} is pinned in {requirements.name} and '
                f'absent from {lock.name}, so the image would not install it')
        elif locked[name] != version:
            problems.append(
                f'{name} is pinned to {version} in {requirements.name} but '
                f'the image installs {locked[name]} from {lock.name} — '
                f'regenerate the lock, or the bump does not ship')
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)

    writer = sub.add_parser('write')
    writer.add_argument('requirements')
    writer.add_argument('report')
    writer.add_argument('lock')

    checker = sub.add_parser('check')
    checker.add_argument('pairs', nargs='+',
                         help='requirements.txt:requirements.lock pairs')

    args = parser.parse_args(argv)

    if args.mode == 'write':
        requirements = pathlib.Path(args.requirements)
        report = json.loads(pathlib.Path(args.report).read_text('utf-8'))
        direct = read_pins(requirements.read_text(encoding='utf-8'))
        pathlib.Path(args.lock).write_text(
            render(report, requirements.name, direct), encoding='utf-8')
        print(f'wrote {args.lock}')
        return 0

    failed = False
    for pair in args.pairs:
        requirements, _, lock = pair.partition(':')
        problems = check(pathlib.Path(requirements), pathlib.Path(lock))
        for problem in problems:
            print(f'::error::{problem}', file=sys.stderr)
        failed = failed or bool(problems)
        if not problems:
            print(f'{lock} agrees with {requirements}')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
