#!/usr/bin/env python3
"""A ruff ratchet per (area, rule): counts that only go down, and zero for everything else.

The proposal was to switch `E F W B I S C4 UP RUF` on and fail on anything. Measured, that is
12,780 findings on day one, 10,420 of them `assert` in a pytest suite, so a gate written that
way is either red forever or switched off, which is the same. An `ignore` list is the usual
answer and has the flaw this repository has met in every other gate: an ignored rule is free to
grow. #652's `--exit-zero` and #667's single complexity pin were both that.

So this is the shape the complexity and exception budgets already have. Every (area, rule) the
tree violates today has an entry with the count it measures; every other rule, hundreds of
them, is enforced at zero from the first day. Four ways to fail, each one a way a ratchet
has quietly stopped ratcheting here before:

* a rule the baseline does not name appears in an area: a new offender, the case an ignore list
  cannot see;
* a count goes UP: the direction the ratchet exists for;
* a count goes DOWN and the entry is not lowered: it would stay a ceiling above what the code
  reaches, and the next regression would hide under the slack;
* an entry matches nothing: a deletion or a rename would otherwise drop a ceiling silently.

The area is the first path component (`modules`, `tests`, `scripts`, `clients`), or `.` for a
file in the root. The numbers belong to one ruff release, because rules change between
releases: another version is a failure that asks for a re-measurement, not a number to trust.
The baseline is for burning down, by rule family, mechanical ones first; it is never raised to
accommodate new code.

Usage:  check_ruff_budget.py            check the tree against the baseline
        check_ruff_budget.py --print    print the baseline for the tree as it is now
"""
from __future__ import annotations

import collections
import json
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The ruff these counts were measured with, pinned in requirements-test.txt.
RUFF_VERSION = '0.16.10'

# area -> rule -> count.
BASELINE: dict[str, dict[str, int]] = {
    '.': {
        'I001': 1, 'S104': 1
    },
    'clients': {
        'B904': 1, 'I001': 3, 'RUF012': 1, 'RUF022': 1, 'UP006': 25, 'UP035': 6, 'UP037': 3, 'UP045': 38
    },
    'modules': {
        'B007': 1, 'B023': 1, 'B027': 2, 'B039': 1, 'B904': 36, 'B905': 3, 'C408': 1, 'C414': 1, 'C420': 4,
        'E401': 2, 'E501': 43, 'F541': 7, 'I001': 87, 'RUF002': 1, 'RUF005': 8, 'RUF010': 39, 'RUF012': 19,
        'RUF013': 9, 'RUF015': 1, 'RUF019': 1, 'RUF021': 1, 'RUF022': 1, 'RUF051': 1, 'RUF059': 2, 'RUF100':
        4, 'S101': 1, 'S104': 2, 'S105': 6, 'S303': 1, 'S310': 10, 'S311': 1, 'S603': 1, 'S607': 1, 'S608':
        1, 'UP006': 294, 'UP007': 3, 'UP012': 1, 'UP015': 20, 'UP017': 47, 'UP031': 2, 'UP035': 31, 'UP037':
        1, 'UP041': 4, 'UP045': 243, 'W291': 12, 'W293': 330
    },
    'scripts': {
        'B007': 1, 'B904': 5, 'B905': 2, 'E501': 2, 'I001': 1, 'RUF005': 1, 'RUF100': 1, 'S113': 5, 'S310':
        5, 'S603': 3, 'S607': 2, 'UP017': 1, 'UP037': 1, 'W293': 12
    },
    'tests': {
        'B007': 4, 'B009': 1, 'B034': 1, 'B904': 1, 'B905': 7, 'C401': 1, 'C408': 7, 'C410': 1, 'C416': 4,
        'C420': 1, 'E401': 1, 'E402': 2, 'E501': 15, 'E702': 20, 'E741': 9, 'F541': 2, 'I001': 274,
        'RUF002': 2, 'RUF005': 10, 'RUF007': 1, 'RUF012': 14, 'RUF013': 1, 'RUF015': 5, 'RUF043': 14,
        'RUF059': 97, 'RUF100': 24, 'UP015': 1, 'UP017': 67, 'UP031': 29, 'UP032': 1, 'UP041': 1, 'W292': 2,
        'W293': 37
    },
}


def _ruff(*args: str, cwd: Path = REPO) -> subprocess.CompletedProcess:
    # The interpreter running this and fixed module and option names: nothing here comes from outside.
    return subprocess.run([sys.executable, '-m', 'ruff', *args], cwd=cwd, capture_output=True, text=True)  # noqa: S603


def installed_version() -> str:
    done = _ruff('--version')
    if done.returncode != 0:
        sys.exit(f'ruff is not installed ({done.stderr.strip() or done.stdout.strip()}). '
                 f'It is pinned in requirements-test.txt.')
    return done.stdout.split()[-1]


def measure(root: Path = REPO) -> tuple[dict[tuple[str, str], int], dict[tuple[str, str], list[str]], list[str]]:
    """Counts per (area, rule), a few locations of each, and any file ruff could not parse."""
    done = _ruff('check', '.', '--output-format', 'json', '--no-cache', cwd=root)
    if done.returncode not in (0, 1):
        sys.exit(f'ruff failed ({done.returncode}): {done.stderr.strip()}')
    counts: collections.Counter = collections.Counter()
    where: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    unparsable = []
    for item in json.loads(done.stdout or '[]'):
        path = Path(item['filename']).resolve().relative_to(root.resolve())
        place = f"{path}:{item['location']['row']}"
        # ruff reports a file it cannot parse as a finding whose code is "invalid-syntax" (older
        # releases left the code empty). It is not a rule to budget: the file was not analysed, so
        # every count below is for less than the tree.
        if not item.get('code') or item['code'] == 'invalid-syntax':
            unparsable.append(f"{place} {item.get('message', '')}")
            continue
        area = path.parts[0] if len(path.parts) > 1 else '.'
        key = (area, item['code'])
        counts[key] += 1
        if len(where[key]) < 3:
            where[key].append(place)
    return dict(counts), dict(where), unparsable


def evaluate(counts: dict[tuple[str, str], int], where: dict[tuple[str, str], list[str]],
             baseline: dict[str, dict[str, int]], unparsable: list[str] = (),
             installed: str = RUFF_VERSION, expected: str = RUFF_VERSION) -> list[str]:
    problems = []
    if installed != expected:
        problems.append(
            f'ruff {installed} is installed and the baseline was measured with {expected}: rules change '
            f'between releases, so re-measure (`python scripts/check_ruff_budget.py --print`) and change '
            f'RUFF_VERSION, BASELINE and the pin in requirements-test.txt together.')
    problems.extend(f'ruff cannot parse {each}' for each in unparsable)
    entries = {(area, rule): n for area, rules in baseline.items() for rule, n in rules.items()}
    for key in sorted(set(counts) | set(entries)):
        area, rule = key
        now, allowed = counts.get(key, 0), entries.get(key)
        sample = ', '.join(where.get(key, []))
        if allowed is None:
            problems.append(f'{area}: {now} new {rule} finding(s), and the baseline has no entry for it '
                            f'(first: {sample}). Fix them; adding an entry is a decision to keep a violation.')
        elif now > allowed:
            problems.append(f'{area}: {rule} went from {allowed} to {now} (first: {sample}). The baseline '
                            f'only goes down.')
        elif now == 0:
            problems.append(f'{area}: {rule} is at 0 and the baseline still has an entry of {allowed}: delete it.')
        elif now < allowed:
            problems.append(f'{area}: {rule} is at {now}, below its entry of {allowed}: lower the entry, or '
                            f'the next regression hides under the slack.')
    return problems


def render(counts: dict[tuple[str, str], int]) -> str:
    areas: dict[str, dict[str, int]] = collections.defaultdict(dict)
    for (area, rule), n in counts.items():
        areas[area][rule] = n
    lines = ['BASELINE: dict[str, dict[str, int]] = {']
    for area in sorted(areas):
        body = ', '.join(f"'{rule}': {areas[area][rule]}" for rule in sorted(areas[area]))
        lines.append(f"    '{area}': {{")
        lines.extend(f'        {row}' for row in textwrap.wrap(body, width=100, break_long_words=False))
        lines.append('    },')
    lines.append('}')
    return '\n'.join(lines)


def main() -> int:
    version = installed_version()
    counts, where, unparsable = measure()
    if sys.argv[1:] == ['--print']:
        print(f'RUFF_VERSION = {version!r}\n')
        print(render(counts))
        return 0
    problems = evaluate(counts, where, BASELINE, unparsable, installed=version)
    if not problems:
        total = sum(counts.values())
        print(f'Ruff budget OK: {total} findings in {len(counts)} (area, rule) entries, none above its '
              f'entry and nothing outside the baseline.')
        return 0
    print(f'Ruff budget: {len(problems)} problem(s).\n')
    for problem in problems:
        print(f'  - {problem}')
    print('\nThe baseline is in scripts/check_ruff_budget.py; the rules are in ruff.toml.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
