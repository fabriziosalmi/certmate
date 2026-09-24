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
#
# 425 -> 427 on 2026-09-16, for the client CA reset (#578), and written down
# because that is what raising this is supposed to cost. Both are the kind the
# docstring above calls defensible, and both LOG:
#
#   modules/api/client_certificates.py   the new resource's catch-all, the same
#                                        `except Exception -> logger.error ->
#                                        abort(500)` every sibling resource in
#                                        that file already has.
#   modules/core/client_certificates.py  the guard around the audit record, the
#                                        same shape as _audit_scheduled_renew
#                                        directly above it. The reset has
#                                        already happened when it runs: letting
#                                        the failure propagate would make the
#                                        caller retry and regenerate the CA a
#                                        second time.
#
# A third one was removed rather than counted: it wrapped CRLManager.update_crl(),
# which already catches internally and returns None, so it could never fire.
#
# 426 -> 427 on 2026-09-22, for the CAA explanation on a failed issuance:
#
#   modules/core/certificates.py   _caa_explanation. It runs inside the branch
#                                  that is already raising certbot's failure,
#                                  and anything it raises would replace that
#                                  error with its own. It logs and returns ''.
#
# Two more were narrowed instead of counted, both in modules/core/caa.py: the
# resolver factory now catches ImportError only, and the per-name catch-all
# went, because every dnspython failure is already a DNSException that the
# resolver turns into LookupFailed.
#
# 427 -> 428 on 2026-09-22, for the domain registration step of the inventory
# scan:
#
#   modules/api/resources_inventory.py   InventoryScan runs discovery, the CT
#                                        poll and now the registration check,
#                                        each in its own `except Exception ->
#                                        logger.error -> error entry`, so one
#                                        failing step cannot lose the other
#                                        two's results. The same shape as the
#                                        two handlers directly above it.
#
# The sweep itself (DomainRegistrationManager.run_check) has no catch-all: a
# single lookup never raises, and anything else is left to the scheduler
# wrapper, which already logs it and records the run.
#
# 428 -> 430 on 2026-09-22, for the name-level checks (SPF/DMARC/MX/blocklists/
# HSTS). Both LOG:
#
#   modules/api/resources_inventory.py   the scan's domain-health step, the
#                                        same shape as the three steps above
#                                        it, for the same reason.
#   modules/core/domain_health.py        DomainHealthManager.check_one. This is
#                                        where it differs from the registration
#                                        sweep above: that one checks each
#                                        domain through a client that turns
#                                        every failure into a status, so it can
#                                        leave the rest to the wrapper. This one
#                                        runs five checks per name against
#                                        injected lookups, and one name's
#                                        surprise must not cost the other two
#                                        hundred their sweep. It records the
#                                        name as `unknown`, never as passing,
#                                        which is what
#                                        test_a_failed_name_is_recorded_as_
#                                        unknown_not_as_passing pins.
# 430 -> 431 on 2026-09-24, for sealing the audit chain on a clean shutdown
# (#876 item 10). LOGS.
#
#   modules/core/factory.py   stop_background_work's new checkpoint step. It
#                             could have been narrowed: write_checkpoint
#                             catches Exception itself and returns None, so in
#                             practice only a manager without the method can
#                             escape it. It is broad anyway, because the
#                             contract of that function is that NOTHING escapes
#                             it — every other step in it (scheduler, issuance
#                             executor, event bus) is broad for the same
#                             reason, and an audit checkpoint must never be why
#                             a container fails to stop. Narrowing this one to
#                             AttributeError would make it the single step that
#                             can take the process down, which is a worse
#                             answer than a number going up by one.
# 431 -> 429 on 2026-09-24, removing the prometheus Info fallback cascade.
#
#   modules/core/metrics.py   Three handlers around `certmate_info.info()`:
#                             an `except AttributeError` that built a Gauge
#                             instead, an `except Exception` inside it, and a
#                             trailing `except Exception`. The AttributeError
#                             fired on EVERY call, on every prometheus_client
#                             this project has pinned, because an Info with
#                             labelnames is a family and `.info()` on the
#                             parent is not a thing. So the handler was not a
#                             fallback for an older library — it was the only
#                             path that ever ran, and the "try" half had never
#                             worked in any release. Declaring the Gauge
#                             directly leaves one call that cannot raise.
TOTAL_LIMIT = 429

# Broad handlers that neither record the failure nor carry a comment saying why
# silence is correct. This is the tractable half of #671: `except Exception` is
# often the right call, but a handler that discards the exception AND says
# nothing about it leaves no way to tell a path that worked from one that
# failed and decided not to mention it.
#
# Two of these were fixed in the commit that added this pin, and both had
# turned a failure into a confident answer: the storage health check answered
# "ok" when it could not read the backend, and the API_BEARER_TOKEN_FILE reader
# returned "no token supplied" for a file it could not open, so an operator who
# rotated the token there got 401 with nothing in the log.
#
# A comment satisfies this, deliberately. The aim is that the silence be
# chosen, and a reader can judge a stated reason; they cannot judge an absence.
UNACCOUNTED_LIMIT = 30

# Files already over GENERAL_LIMIT, with what they measure today.
BUDGET = {
    'modules/core/storage_backends.py': 64,
    'modules/core/certificates.py': 45,
    'modules/core/file_operations.py': 16,
    'modules/web/misc_routes.py': 16,
    'modules/api/resources_health.py': 15,
    'modules/core/auth.py': 13,
    'modules/core/factory.py': 14,
    'modules/web/settings_routes.py': 13,
    'modules/api/client_certificates.py': 13,
    'modules/core/client_certificates.py': 12,
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


# Calls that leave a trace of the failure. A handler that makes one of these
# has handled the exception; a handler that makes none has discarded it.
_RECORDING_CALLS = frozenset({
    'debug', 'info', 'warning', 'warn', 'error', 'exception', 'critical',
    'log', 'log_operation', 'print', 'capture_exception', 'flash',
})


def _records(handler: ast.ExceptHandler) -> bool:
    """True if the handler logs, re-raises, or otherwise records the failure."""
    module = ast.Module(body=handler.body, type_ignores=[])
    for node in ast.walk(module):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Call):
            name = getattr(node.func, 'attr', None) or getattr(node.func, 'id', None)
            if name in _RECORDING_CALLS:
                return True
    return False


def _explained(handler: ast.ExceptHandler, lines: list[str]) -> bool:
    """True if a comment sits on, above, or immediately inside the handler.

    Three places because all three are how this codebase already writes the
    reason down, and insisting on one of them would be a style rule wearing a
    gate's clothes.
    """
    on = lines[handler.lineno - 1] if handler.lineno <= len(lines) else ''
    above = lines[handler.lineno - 2].strip() if handler.lineno >= 2 else ''
    inside = ''
    if handler.body and handler.body[0].lineno - 2 < len(lines):
        inside = lines[handler.body[0].lineno - 2].strip()
    return '#' in on or above.startswith('#') or inside.startswith('#')


def measure() -> tuple[dict[str, int], list[str], list[str], list[str]]:
    """Broad handlers per file, plus the bare, silent and unaccounted sites."""
    per_file: dict[str, int] = {}
    bare: list[str] = []
    silent: list[str] = []
    unaccounted: list[str] = []
    for path in _sources():
        relative = path.relative_to(REPO).as_posix()
        text = path.read_text(encoding='utf-8')
        lines = text.split('\n')
        try:
            tree = ast.parse(text)
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
            if not _records(node) and not _explained(node, lines):
                unaccounted.append(f'{relative}:{node.lineno}')
        if count:
            per_file[relative] = count
    return per_file, bare, silent, unaccounted


def evaluate(per_file, bare, silent, unaccounted, budget, general_limit,
             total_limit, unaccounted_limit):
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

    if len(unaccounted) > unaccounted_limit:
        problems.append(
            f'{len(unaccounted)} broad handlers neither record the failure nor '
            f'say why not, over the pinned {unaccounted_limit}. A handler that '
            f'logs nothing turns a failure into an answer: the storage health '
            f'check reported "ok" when it could not read the backend at all, '
            f'which is the reverse of what that check exists to say. Log it, '
            f'or write one line saying why silence is right here.\n'
            f'      The gate cannot tell which one is new; here are the first '
            f'few of all {len(unaccounted)}, and `git diff` names yours:\n      '
            + '\n      '.join(sorted(set(unaccounted))[:8])
        )
    elif len(unaccounted) < unaccounted_limit:
        problems.append(
            f'{len(unaccounted)} broad handlers neither record nor explain, '
            f'below the pinned {unaccounted_limit}. Lower UNACCOUNTED_LIMIT to '
            f'{len(unaccounted)} in the same commit, for the same reason the '
            f'total is pinned both ways.'
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
    per_file, bare, silent, unaccounted = measure()
    problems = evaluate(per_file, bare, silent, unaccounted, BUDGET,
                        GENERAL_LIMIT, TOTAL_LIMIT, UNACCOUNTED_LIMIT)
    if not problems:
        print(
            f'Exception budget OK: {sum(per_file.values())} broad handlers '
            f'(pinned {TOTAL_LIMIT}), 0 bare, 0 silent, '
            f'{len(unaccounted)} unaccounted (pinned {UNACCOUNTED_LIMIT}), '
            f'nothing over {GENERAL_LIMIT} outside the budget.'
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
