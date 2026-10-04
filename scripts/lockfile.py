#!/usr/bin/env python3
"""Generate and check the resolved dependency lockfiles.

`requirements.txt` pins 42 packages. Installing it resolves **118**, so 76 of
the packages in every published image were chosen by whichever version of the
index pip happened to see on build day, and nothing in this repository recorded
which ones. Two images built from the same commit a month apart were not the
same image, and there was no diff to review that would say so.

A lockfile fixes that. It also carries the sha256 of every file the
index publishes for each pinned version, and the image installs it with
`--require-hashes`: a wheel that is not one of those files is refused. This
was deferred for a while (SECURITY.md, "Supply-chain posture") because the
extras layer installs *on top of* the lock with `-c`, and pip turns hash
checking on for a whole install when any line carries a hash, refusing the
unhashed extras. The answer is a second file: `<lock>.constraints`, the same
pins without hashes, for every layer installed on top (extras, tests). Each
pip invocation is then either fully hashed or not hashed at all, never half.

Modes, all pure functions over text so they are testable without pip:

    write   turn what `uv pip compile --generate-hashes` resolved into a lock
            (and, with --constraints, its constraints file)
    check   every direct pin present in the lock at the same version; every
            pin in the lock hashed; the constraints file equal to the lock

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
import pathlib
import re
import sys

# A pinned line in a requirements file: `name==version`, before any comment.
# Deliberately narrower than PEP 508 — anything with a marker, an extra or a
# range is not a plain pin and is reported rather than silently skipped.
PIN = re.compile(r'^([A-Za-z0-9._-]+)==([^\s;#]+)\s*$')
HASH = re.compile(r'^--hash=(sha256:[0-9a-f]{64})$')

HEADER = """\
# GENERATED — do not edit by hand. Regenerate with:
#
#     scripts/regenerate_lockfiles.sh
#
# The fully resolved install set for {source}, resolved by uv for the two
# published architectures. {direct} of these are
# pinned by {source}; the other {transitive} are transitive and were chosen by
# the resolver, which is exactly why they are written down here. The image
# installs them with pip.
#
# The two published architectures resolve this set identically, which is what
# makes one file sufficient. `scripts/regenerate_lockfiles.sh` re-checks that
# before writing, so the day it stops being true is the day it is noticed.
#
# A regeneration starts from the pins already in this file and moves only what
# the change under review requires: it does not re-resolve the transitive set.
#
# Each pin carries the sha256 of every file the index publishes for that
# version, for both architectures, and the image installs this file with
# --require-hashes: a file that is not one of these is refused. Anything
# installed on top of it (extras, test requirements) uses {constraints}, the
# same pins without hashes. See "Supply-chain posture for Python dependencies"
# in SECURITY.md.
"""

CONSTRAINTS_HEADER = """\
# GENERATED — do not edit by hand. Regenerate with:
#
#     scripts/regenerate_lockfiles.sh
#
# The pins of {lock}, without its hashes. For a layer installed on top of that
# lock with -c (an extras set, the test requirements): pip turns hash checking
# on for a whole install when any line carries a hash, so constraining with the
# lock itself would refuse every unhashed package in the layer. The pins here
# are the lock's, so the layer still cannot move one.
#
# Never install from this file: install {lock}, with --require-hashes.
"""


def normalize(name: str) -> str:
    """PEP 503 normalisation, so `zope.interface` and `zope-interface` are the
    same package. Comparing raw names here would report a phantom mismatch."""
    return re.sub(r'[-_.]+', '-', name).lower()


def read_entries(text: str) -> dict[str, tuple[str, list[str]]]:
    """`name -> (version, hashes)` from a requirements or lock file.

    Reads both shapes: one `name==version` per line, and the hashed form uv
    writes, where a pin ends in a backslash and its `--hash=` lines follow."""
    entries: dict[str, tuple[str, list[str]]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.split('#')[0].strip()
        if line.endswith('\\'):
            line = line[:-1].strip()
        if not line:
            continue
        hashed = HASH.match(line)
        if hashed:
            if current is not None:
                entries[current][1].append(hashed.group(1))
            continue
        match = PIN.match(line)
        if match:
            current = normalize(match.group(1))
            entries[current] = (match.group(2), [])
        else:
            current = None
    return entries


def read_pins(text: str) -> dict[str, str]:
    """The `name==version` lines of a requirements or lock file."""
    return {name: version for name, (version, _) in read_entries(text).items()}


def constraints_path(lock: pathlib.Path) -> pathlib.Path:
    return lock.with_suffix('.constraints')


def render(resolved: dict[str, str], source: str, direct: dict[str, str],
           hashes: dict[str, list[str]] | None = None,
           constraints: str = 'the .constraints file beside it') -> str:
    """A lockfile from `name -> version` pins (and their hashes), with the
    header that says how to regenerate it. Hashes are sorted so that a
    regeneration that changes nothing produces no diff."""
    resolved = {normalize(name): version for name, version in resolved.items()}
    hashes = {normalize(name): sorted(set(found)) for name, found in (hashes or {}).items()}
    transitive = sorted(set(resolved) - set(direct))
    body = []
    for name in sorted(resolved):
        found = hashes.get(name)
        if not found:
            body.append(f'{name}=={resolved[name]}\n')
            continue
        lines = [f'{name}=={resolved[name]}'] + [f'    --hash={h}' for h in found]
        body.append(' \\\n'.join(lines) + '\n')
    return HEADER.format(source=source, direct=len(direct), transitive=len(transitive),
                         constraints=constraints) + '\n' + ''.join(body)


def render_constraints(resolved: dict[str, str], lock: str) -> str:
    resolved = {normalize(name): version for name, version in resolved.items()}
    body = ''.join(f'{name}=={resolved[name]}\n' for name in sorted(resolved))
    return CONSTRAINTS_HEADER.format(lock=lock) + '\n' + body


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


def check_hashes(lock: pathlib.Path) -> list[str]:
    """Every pin in the lock carries at least one hash.

    One unhashed line makes `--require-hashes` refuse the whole file at build
    time; this says so at review time instead, with the package's name."""
    return [f'{name}=={version} in {lock.name} has no --hash, so the image '
            f'cannot install the lock with --require-hashes — regenerate it'
            for name, (version, found) in sorted(read_entries(lock.read_text('utf-8')).items())
            if not found]


def check_constraints(lock: pathlib.Path, constraints: pathlib.Path) -> list[str]:
    """The constraints file holds exactly the lock's pins.

    It is generated from the lock; a hand edit or a regeneration that wrote one
    and not the other would let a layer installed on top move a pin the lock
    holds, which is what the constraint exists to prevent."""
    if not constraints.exists():
        return [f'{constraints.name} is missing: the layers installed on top of '
                f'{lock.name} have nothing to be constrained by — regenerate']
    locked = read_pins(lock.read_text('utf-8'))
    pinned = read_pins(constraints.read_text('utf-8'))
    if locked == pinned:
        return []
    differ = sorted(set(locked.items()) ^ set(pinned.items()))
    return [f'{constraints.name} does not hold the pins of {lock.name} '
            f'(first differences: {differ[:3]}) — regenerate']


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)

    writer = sub.add_parser('write')
    writer.add_argument('requirements')
    writer.add_argument('resolved', help='what `uv pip compile --generate-hashes` wrote')
    writer.add_argument('lock')
    writer.add_argument('--constraints', action='store_true',
                        help='also write <lock>.constraints, for layers installed on top')

    checker = sub.add_parser('check')
    checker.add_argument('pairs', nargs='+',
                         help='requirements.txt:requirements.lock pairs; a lock with a '
                              '.constraints file beside it is checked against it')

    args = parser.parse_args(argv)

    if args.mode == 'write':
        requirements = pathlib.Path(args.requirements)
        lock = pathlib.Path(args.lock)
        entries = read_entries(pathlib.Path(args.resolved).read_text('utf-8'))
        resolved = {name: version for name, (version, _) in entries.items()}
        direct = read_pins(requirements.read_text(encoding='utf-8'))
        missing = sorted(set(direct) - set(resolved))
        if missing:
            print(f'::error::the resolution is missing pinned packages: {missing}', file=sys.stderr)
            return 1
        unhashed = sorted(name for name, (_, found) in entries.items() if not found)
        if unhashed:
            print(f'::error::the resolution has no hashes for {unhashed[:5]}: '
                  f'run uv pip compile with --generate-hashes', file=sys.stderr)
            return 1
        hashes = {name: found for name, (_, found) in entries.items()}
        lock.write_text(render(resolved, requirements.name, direct, hashes,
                               constraints=constraints_path(lock).name if args.constraints
                               else 'nothing: nothing is installed on top of it'),
                        encoding='utf-8')
        print(f'wrote {lock}')
        if args.constraints:
            constraints_path(lock).write_text(render_constraints(resolved, lock.name), encoding='utf-8')
            print(f'wrote {constraints_path(lock)}')
        return 0

    failed = False
    for pair in args.pairs:
        requirements, _, lock = pair.partition(':')
        lock_path = pathlib.Path(lock)
        problems = check(pathlib.Path(requirements), lock_path) + check_hashes(lock_path)
        if constraints_path(lock_path).exists():
            problems += check_constraints(lock_path, constraints_path(lock_path))
        for problem in problems:
            print(f'::error::{problem}', file=sys.stderr)
        failed = failed or bool(problems)
        if not problems:
            print(f'{lock} agrees with {requirements}')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
