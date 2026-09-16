#!/usr/bin/env python3
"""A budget for broad exception handlers, instead of a number that only grows.

#671 counted 397 `except Exception` handlers, 7 silent `pass` bodies and 1 bare
`except:`. Measured again today, with the AST rather than grep: **425** broad
handlers, **0** silent bodies among them, **0** bare. Two of the three numbers
were fixed and the third grew by 28 while the issue stayed open, because
nothing measured it between one reading and the next.

So the two that reached zero become rules, and the one that grows becomes a
ratchet. Same shape as scripts/check_complexity_budget.py, for the same reason:
one number for the whole tree is set by its worst file, and everything below
the worst is ungated.

`except Exception` is not a defect on its own. A supervisor loop, a health
probe, a best-effort cache write: all of them genuinely want to survive
anything. What is a defect is the count climbing without anyone choosing it,
and a handler that swallows the exception without recording it, which is why
the second rule is absolute rather than budgeted.

Five failure modes, all of them ones this repository has met:

* a bare `except:` appears. There were none left; this keeps it that way.
* a broad handler whose body is only `pass`. The exception is not handled, it
  is discarded, and nothing downstream can tell the difference between "this
  worked" and "this failed and we decided not to say".
* the total grows past the pin. This is the number #671 is about.
* a file not in the budget goes over GENERAL_LIMIT, or a budgeted file exceeds
  its own entry. Locality: the total alone cannot tell one file improving from
  another getting worse.
* a budgeted file gets BETTER and its entry is not lowered. This is how the
  complexity pin at 559 survived its own fix for nine months, reading like an
  enforced limit while enforcing nothing.

The entries are not targets. They are what the tree measures today, and they
move down.

Usage:  check_exception_budget.py
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# What an unbudgeted file may reach. The lowest round value that requires no
# change today: the thirteenth-worst file sits at 10.
GENERAL_LIMIT = 10

# Every broad handler in the tree. Pinned because this is the number #671
# names, and because a per-file budget alone cannot stop a new file adding
# GENERAL_LIMIT more.
TOTAL_LIMIT = 425

# Files already over GENERAL_LIMIT, with what they measure today.
BUDGET = {
    'modules/core/storage_backends.py': 65,
    'modules/core/certificates.py': 44,
    'modules/core/file_operations.py': 16,
    'modules/web/misc_routes.py': 16,
    'modules/api/resources_health.py': 15,
    'modules/core/auth.py': 13,
    'modules/core/factory.py': 13,
    'modules/web/settings_routes.py': 13,
    'modules/api/client_certificates.py': 12,
    'modules/core/client_certificates.py': 11,
    'modules/core/private_ca.py': 11,
    'modules/core/settings.py': 11,
}


def _sources() -> list[Path]:
    return sorted(list((REPO / 'modules').rglob('*.py')) + [REPO / 'app.py'])


def _is_broad(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return False
    raised = handler.type
    parts = raised.elts if isinstance(raised, ast.Tuple) else [raised]
    return any(ast.unparse(part) in ('Exception', 'BaseException') for part in parts)


def measure() -> tuple[dict[str, int], list[str], list[str]]:
    """Broad handlers per file, plus every bare and every silent-broad site."""
    per_file: dict[str, int] = {}
    bare: list[str] = []
    silent: list[str] = []
    for path in _sources():
        relative = path.relative_to(REPO).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except SyntaxError as error:
            # Not this gate's job to report, but dying with a bare traceback
            # here reads as "the budget script is broken" rather than "that
            # file does not parse". Say which it is.
            raise SystemExit(
                f'{relative}:{error.lineno}: does not parse ({error.msg}), so '
                f'the exception budget cannot be measured. Fix the syntax '
                f'error; flake8 reports it as E9.'
            ) from error
        count = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                bare.append(f'{relative}:{node.lineno}')
                continue
            if not _is_broad(node):
                continue
            count += 1
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                silent.append(f'{relative}:{node.lineno}')
        if count:
            per_file[relative] = count
    return per_file, bare, silent


def evaluate(per_file, bare, silent, budget, general_limit, total_limit):
    problems: list[str] = []

    for site in bare:
        problems.append(
            f'{site}: bare `except:`. It catches KeyboardInterrupt and '
            f'SystemExit too, so it can swallow a shutdown. There were none '
            f'left in this tree.'
        )

    for site in silent:
        problems.append(
            f'{site}: a broad handler whose body is only `pass`. The exception '
            f'is not handled, it is discarded, and no caller can tell this '
            f'path from one that worked. Log it, re-raise it, or narrow the '
            f'handler to the exception you meant.'
        )

    total = sum(per_file.values())
    if total > total_limit:
        problems.append(
            f'{total} broad exception handlers in the tree, over the pinned '
            f'{total_limit}. This is the number #671 is about, and it has gone '
            f'up. Narrow the new handler to the exception it expects, or say '
            f'here why the count had to move.'
        )
    elif total < total_limit:
        problems.append(
            f'{total} broad exception handlers, below the pinned '
            f'{total_limit}. Lower TOTAL_LIMIT to {total} in the same commit: '
            f'a pin left above what the tree contains stops being a ratchet '
            f'and becomes a comment.'
        )

    for name, pinned in sorted(budget.items()):
        found = per_file.get(name)
        if found is None:
            problems.append(
                f'{name} is in the budget and has no broad handlers, or no '
                f'longer exists. Remove the entry; an entry matching nothing '
                f'drops a ceiling silently.'
            )
        elif found > pinned:
            problems.append(
                f'{name}: {found} broad handlers, over its budgeted {pinned}.'
            )
        elif found < pinned:
            problems.append(
                f'{name}: {found} broad handlers, below its budgeted {pinned}. '
                f'Lower the entry to {found} in the same commit.'
            )

    for name, found in sorted(per_file.items()):
        if name not in budget and found > general_limit:
            problems.append(
                f'{name}: {found} broad handlers, over the general limit of '
                f'{general_limit} and not in the budget. Narrow them, or add '
                f'the file with a reason.'
            )

    return problems


def main() -> int:
    per_file, bare, silent = measure()
    problems = evaluate(per_file, bare, silent, BUDGET, GENERAL_LIMIT, TOTAL_LIMIT)
    if not problems:
        print(
            f'Exception budget OK: {sum(per_file.values())} broad handlers '
            f'(pinned {TOTAL_LIMIT}), 0 bare, 0 silent, nothing over '
            f'{GENERAL_LIMIT} outside the budget.'
        )
        return 0
    print('\nException budget failed:\n')
    for problem in problems:
        print('  ' + problem)
    print(
        f'\n{len(problems)} problem(s). The budget is in '
        f'scripts/check_exception_budget.py; read the docstring before '
        f'raising a number.\n'
    )
    return 1


if __name__ == '__main__':
    sys.exit(main())
