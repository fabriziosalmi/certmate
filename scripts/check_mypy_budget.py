#!/usr/bin/env python3
"""A mypy ratchet per file: error counts that only go down, and zero for every file not listed.

The proposal was `strict = true`. Measured on `modules/` and `app.py` (103 files, 52,387 lines)
that is 3,242 errors, 82% of them annotations that do not exist yet, with 6 files clean, so a
gate written that way starts red and stays red, which is the same as no gate. mypy in its
default mode finds 102 errors in 33 files without being asked for a single annotation, and the
interesting ones are values that can be None being used. That is what this holds.

The shape is the one the complexity, exception and ruff budgets already have. Every file with
errors has an entry with the count it measures; every other file is enforced at zero. Four ways
to fail, each a way a ratchet has quietly stopped ratcheting in this repository:

* a file the baseline does not name gains an error: a new offender;
* a file's count goes UP: the direction the ratchet is for;
* a count goes DOWN and the entry is not lowered: it stays a ceiling above what the code
  reaches, and the next regression hides under the slack;
* an entry matches nothing: a deletion or a rename would otherwise drop a ceiling silently.

What mypy reports depends on the versions of the packages it reads. So the numbers belong to one
mypy release AND one interpreter (3.12, the one the image runs), and CI runs this in its own job on
the locked set (requirements.lock), not on the test job's unpinned transitive dependencies. Another
version is a failure that asks for a re-measurement, not a number to trust.

The modules already clean under `--strict` are listed in mypy.ini with its flags written out, so
they stay clean; a module joins that list when it is annotated.

Usage:  check_mypy_budget.py            check the tree against the baseline
        check_mypy_budget.py --print    print the baseline for the tree as it is now
"""
from __future__ import annotations

import collections
import re
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The mypy and the interpreter these counts were measured with. mypy is pinned in requirements-test.txt.
MYPY_VERSION = '2.4.0'
PYTHON_MINOR = (3, 12)

# file -> errors.
BASELINE: dict[str, int] = {
    'modules/api/resource_context.py': 1, 'modules/api/resources_health.py': 3, 'modules/core/audit.py': 1,
    'modules/core/audit_chain.py': 1, 'modules/core/audit_signing.py': 8, 'modules/core/audit_verify.py': 1,
    'modules/core/ca_manager.py': 5, 'modules/core/cert_probe.py': 1, 'modules/core/certificates.py': 6,
    'modules/core/client_certificates.py': 10, 'modules/core/crypto_report.py': 1, 'modules/core/csr_handler.py':
    3, 'modules/core/dns_strategies.py': 1, 'modules/core/events.py': 5, 'modules/core/key_formats.py': 2,
    'modules/core/metrics.py': 10, 'modules/core/notifier.py': 3, 'modules/core/private_ca.py': 14,
    'modules/core/rate_limit.py': 1, 'modules/core/settings.py': 1, 'modules/core/shell.py': 1,
    'modules/core/storage_backends.py': 2, 'modules/core/structured_logging.py': 3, 'modules/core/utils.py': 3,
    'modules/core/zombie.py': 2, 'modules/factory.py': 4, 'modules/web/routes.py': 2
}

ERROR = re.compile(r'^(?P<file>[^:\s][^:]*\.py):(?P<line>\d+)(?::\d+)?: error: (?P<message>.*)$')


def _mypy(*args: str, cwd: Path = REPO) -> subprocess.CompletedProcess:
    # The interpreter running this and fixed module and option names: nothing here comes from outside.
    return subprocess.run([sys.executable, '-m', 'mypy', *args], cwd=cwd, capture_output=True, text=True)  # noqa: S603


def installed_version() -> str:
    done = _mypy('--version')
    if done.returncode != 0:
        sys.exit(f'mypy is not installed ({done.stderr.strip() or done.stdout.strip()}). '
                 f'It is pinned in requirements-test.txt.')
    return done.stdout.split()[1]


def measure(cwd: Path = REPO, *args: str) -> tuple[dict[str, int], dict[str, list[str]], list[str]]:
    """Errors per file, the first few lines of each, and anything mypy could not check at all."""
    done = _mypy('--no-color-output', '--no-error-summary', '--no-pretty', '--no-incremental', *args, cwd=cwd)
    counts: collections.Counter = collections.Counter()
    where: dict[str, list[str]] = collections.defaultdict(list)
    unchecked = []
    for line in done.stdout.splitlines():
        found = ERROR.match(line)
        if not found:
            continue
        message = found.group('message')
        # A syntax error (exit code 2, error code [syntax]), "Source file found twice": mypy did not
        # analyse the file, so every count is for less than the tree. Not an error to budget.
        if message.rstrip().endswith('[syntax]') or message.startswith(('Source file found twice', 'Cannot find ')):
            unchecked.append(f"{found.group('file')}:{found.group('line')} {message}")
            continue
        counts[found.group('file')] += 1
        if len(where[found.group('file')]) < 3:
            where[found.group('file')].append(f"{found.group('file')}:{found.group('line')}")
    if done.returncode not in (0, 1) and not unchecked:
        sys.exit(f'mypy failed ({done.returncode}): {(done.stderr or done.stdout).strip()[:400]}')
    return dict(counts), dict(where), unchecked


def evaluate(counts: dict[str, int], where: dict[str, list[str]], baseline: dict[str, int],
             unchecked: list[str] = (), installed: str = MYPY_VERSION, expected: str = MYPY_VERSION,
             python_minor: tuple[int, int] = PYTHON_MINOR, expected_python: tuple[int, int] = PYTHON_MINOR) -> list[str]:
    problems = []
    if installed != expected:
        problems.append(
            f'mypy {installed} is installed and the baseline was measured with {expected}: re-measure '
            f'(`python scripts/check_mypy_budget.py --print`) and change MYPY_VERSION, BASELINE and the pin '
            f'in requirements-test.txt together.')
    if python_minor != expected_python:
        problems.append(
            f'this is Python {python_minor[0]}.{python_minor[1]} and the baseline was measured under '
            f'{expected_python[0]}.{expected_python[1]}: what mypy reports depends on the interpreter\'s '
            f'packages. Run it under {expected_python[0]}.{expected_python[1]}, on the locked set.')
    problems.extend(f'mypy could not check {each}' for each in unchecked)
    for path in sorted(set(counts) | set(baseline)):
        now, allowed = counts.get(path, 0), baseline.get(path)
        sample = ', '.join(where.get(path, []))
        if allowed is None:
            problems.append(f'{path}: {now} new error(s), and the baseline has no entry for it (first: {sample}). '
                            f'Fix them; adding an entry is a decision to keep an error.')
        elif now > allowed:
            problems.append(f'{path}: errors went from {allowed} to {now} (first: {sample}). The baseline only goes down.')
        elif now == 0:
            problems.append(f'{path}: is clean and the baseline still has an entry of {allowed}: delete it.')
        elif now < allowed:
            problems.append(f'{path}: is at {now}, below its entry of {allowed}: lower the entry, or the next '
                            f'regression hides under the slack.')
    return problems


def render(counts: dict[str, int]) -> str:
    rows = ', '.join(f"'{path}': {n}" for path, n in sorted(counts.items()))
    lines = ['BASELINE: dict[str, int] = {']
    lines.extend(f'    {row}' for row in textwrap.wrap(rows, width=110, break_long_words=False))
    lines.append('}')
    return '\n'.join(lines)


def main() -> int:
    version = installed_version()
    counts, where, unchecked = measure()
    if sys.argv[1:] == ['--print']:
        print(f'MYPY_VERSION = {version!r}\nPYTHON_MINOR = {sys.version_info[:2]!r}\n')
        print(render(counts))
        return 0
    problems = evaluate(counts, where, BASELINE, unchecked, installed=version, python_minor=sys.version_info[:2])
    if not problems:
        print(f'Mypy budget OK: {sum(counts.values())} errors in {len(counts)} files, none above its entry and '
              f'no file outside the baseline.')
        return 0
    print(f'Mypy budget: {len(problems)} problem(s).\n')
    for problem in problems:
        print(f'  - {problem}')
    print('\nThe baseline is in scripts/check_mypy_budget.py; the configuration is in mypy.ini.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
