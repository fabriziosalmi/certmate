#!/usr/bin/env python3
"""A complexity budget per function, instead of one number for the whole tree.

CI used to run `flake8 --select=C901 --max-complexity=115`. That number is the
tree's real worst — `register_settings_routes` — and a test keeps it from
drifting above what the tree contains, so it is not a lax pin in the way the
old 559 was.

It is still a gate that cannot fail on anything anyone is likely to write. One
number for 1,700 functions has to be set by the worst of them, so everything
below the worst is ungated: a new function at 100, or a second closure at 90,
enters the codebase with the lint step green. The pin protects the record for
the single worst function and nothing else.

So the ceiling is per function. Everything gets `GENERAL_LIMIT`; the thirteen
functions already above it are listed here with the value they measure today,
and each is checked against its own entry rather than against the worst.

Four failure modes, all of them ones this repository has actually met:

* a function not in the budget goes over the general limit — the case the
  single pin could not see, and the reason this exists;
* a budgeted function gets worse than its entry — the ratchet's own direction;
* a budgeted function gets BETTER and the entry is not lowered — how 559
  survived #667 by nine months, in a comment that read like an enforced limit;
* a budget entry matching nothing — a rename or a deletion would otherwise
  drop a ceiling silently, and the check would go on passing over less.

The entries are not targets. Twelve of the thirteen are route-registration
closures: N handlers nested inside one registration function, the same shape as
the 559-complexity closure #667 decomposed. Their number goes down when one is
decomposed, never up to accommodate another handler.

Usage:  check_complexity_budget.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# What any function may reach without being named here. Chosen as the lowest
# value that does not require decomposing something today: the fourteenth
# worst function in the tree is at exactly 40.
GENERAL_LIMIT = 40

# 'path::function': measured complexity. Lower an entry when the function gets
# simpler; delete it when it drops to GENERAL_LIMIT or below. Adding an entry
# is a decision to keep a function complex, and belongs in review.
BUDGET = {
    # The twelve route-registration closures.
    'modules/web/settings_routes.py::register_settings_routes': 115,
    'modules/web/misc_routes.py::register_misc_routes': 104,
    'modules/api/client_certificates.py::create_client_certificate_resources': 89,
    'modules/api/resources_storage.py::create_storage_resources': 68,
    'modules/api/resources_lifecycle.py::create_lifecycle_resources': 61,
    'modules/web/cert_routes.py::register_cert_routes': 60,
    'modules/api/resources_downloads.py::create_download_resources': 55,
    'modules/api/resources_settings.py::create_settings_resources': 54,
    'modules/api/resources_backup.py::create_backup_resources': 53,
    'modules/api/resources_certificates.py::create_certificates_resources': 48,
    'modules/api/resources_inventory.py::create_inventory_resources': 46,
    # The two that are genuinely one algorithm each, and the ones worth
    # decomposing first: everything above is a container for handlers, these
    # two are a single unit a reader has to hold in their head at once.
    'modules/core/settings.py::SettingsManager.load_settings': 50,
    'modules/core/file_operations.py::FileOperations.restore_unified_backup': 46,
}

REPORT = re.compile(
    r"^\./?(?P<path>[^:]+):\d+:\d+: C901 '(?P<name>[^']+)' "
    r"is too complex \((?P<score>\d+)\)$")


def measure(limit: int = GENERAL_LIMIT) -> dict[str, int]:
    """Every function over `limit`, as flake8 computes it.

    Run rather than reimplemented: an independent complexity calculation would
    disagree with the linter at the margins, and the number that matters is the
    one the lint step produces.
    """
    result = subprocess.run(
        [sys.executable, '-m', 'flake8', '.', '--select=C901',
         f'--max-complexity={limit}'],
        cwd=REPO, capture_output=True, text=True, timeout=900)

    if 'No module named flake8' in result.stderr:
        raise SystemExit(
            'flake8 is not installed, so the complexity budget cannot be '
            'checked. It is a declared test dependency precisely so this '
            'cannot pass quietly.')
    # 0 = nothing over the limit, 1 = violations reported. Anything else is
    # flake8 failing to run, which is not the same as a clean tree.
    if result.returncode not in (0, 1):
        raise SystemExit(
            f'flake8 exited {result.returncode} without producing a report:\n'
            f'{result.stderr.strip()}')

    measured = {}
    for line in result.stdout.splitlines():
        match = REPORT.match(line.strip())
        if not match:
            raise SystemExit(
                f'unparsed line from flake8, so the budget would be compared '
                f'against an incomplete measurement:\n  {line}')
        measured[f"{match.group('path')}::{match.group('name')}"] = int(
            match.group('score'))
    return measured


def evaluate(measured: dict[str, int], budget: dict[str, int],
             limit: int) -> list[str]:
    """The problems, in the order a reader should act on them."""
    problems = []

    for key, score in sorted(measured.items()):
        if key not in budget:
            problems.append(
                f'{key} is at {score}, over the limit of {limit}, and has no '
                f'budget entry.\n'
                f'    Decompose it. Adding it to BUDGET in '
                f'scripts/check_complexity_budget.py is a decision to keep it '
                f'this complex and needs to be argued in review.')
        elif score > budget[key]:
            problems.append(
                f'{key} got worse: {budget[key]} -> {score}.\n'
                f'    Its budget is a ceiling that only comes down.')
        elif score < budget[key]:
            problems.append(
                f'{key} got better: {budget[key]} -> {score}. Lower its entry '
                f'to {score}.\n'
                f'    A ceiling left above what the code reaches is how the '
                f'old single pin survived at five times the real worst.')

    for key, pinned in sorted(budget.items()):
        if key not in measured:
            problems.append(
                f'{key} has a budget entry of {pinned} but flake8 reports '
                f'nothing for it.\n'
                f'    Either it is now at or below {limit} and the entry '
                f'should be deleted, or it was renamed or removed and the '
                f'entry is guarding nothing.')

    return problems


def main() -> int:
    problems = evaluate(measure(), BUDGET, GENERAL_LIMIT)
    if not problems:
        print(f'Complexity budget OK: nothing over {GENERAL_LIMIT} outside '
              f'the {len(BUDGET)} budgeted functions, and every entry matches '
              f'what the tree measures.')
        return 0

    print(f'Complexity budget: {len(problems)} problem(s).\n')
    for problem in problems:
        print(f'  - {problem}')
    print(f'\nGeneral limit is {GENERAL_LIMIT}; the budget is in '
          f'scripts/check_complexity_budget.py.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
