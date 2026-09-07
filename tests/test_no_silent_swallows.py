"""No handler may catch broadly and then say nothing (#671).

`except Exception: pass` on a certificate manager is how a genuine failure
becomes a wrong value with no error attached. That is not a hypothetical here:

* `auth.py` swallowed the write of `last_used_at`, and the comment above it
  records what that cost — `json.dump` refused a datetime and the column
  stayed empty for every API key, forever, with nothing logged;
* during the #666 decomposition a `NameError` introduced in the propagation
  lookup was swallowed by its surrounding `except Exception` and turned into
  the strategy default: 60 seconds instead of the configured 30, silently.

So this file draws the line at the shape that cannot be defended — a *broad*
catch whose entire body is `pass` — rather than at the 397 broad handlers,
most of which do log or return something. Narrow silent handlers stay
allowed: `except OSError: pass` around an `unlink` in a cleanup path says
exactly what it means.

The bare-except half of the issue is already enforced: `E722` is in the gated
flake8 selection in both `.github/workflows/ci.yml` and `scripts/release.sh`,
and there are none left. `test_bare_excepts_stay_gated` pins that so removing
the flag from the gate fails here instead of quietly reopening the door.
"""
import ast
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

ROOT = pathlib.Path(__file__).resolve().parent.parent
BROAD = {'Exception', 'BaseException'}


def _silent_handlers(tree):
    """Yield (lineno, caught) for handlers whose whole body is `pass`."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if len(node.body) != 1 or not isinstance(node.body[0], ast.Pass):
            continue
        yield node.lineno, (ast.unparse(node.type) if node.type else '<bare>')


def _python_sources():
    return sorted(ROOT.glob('modules/**/*.py')) + [ROOT / 'app.py']


def test_no_broad_handler_swallows_in_silence():
    offenders = []
    for path in _python_sources():
        tree = ast.parse(path.read_text())
        for lineno, caught in _silent_handlers(tree):
            if caught == '<bare>' or caught in BROAD:
                offenders.append(f'{path.relative_to(ROOT)}:{lineno} '
                                 f'except {caught}: pass')

    assert not offenders, (
        'these catch everything and then say nothing, so a real failure '
        'becomes a wrong value with no error attached:\n  '
        + '\n  '.join(offenders)
    )


def test_narrow_silent_handlers_are_still_allowed():
    """CONTROL: the rule above must not be read as "no silent handler ever".

    `except OSError: pass` around an unlink in a cleanup path is precise about
    what it ignores and why. If this ever reaches zero, someone has widened
    the rule into a style edict and the codebase will grow log noise instead
    of clarity.
    """
    narrow = 0
    for path in _python_sources():
        tree = ast.parse(path.read_text())
        for _lineno, caught in _silent_handlers(tree):
            if caught != '<bare>' and caught not in BROAD:
                narrow += 1

    assert narrow > 0, (
        'no narrow silent handlers remain, which suggests this rule was '
        'applied as a blanket ban rather than to broad catches'
    )


def test_bare_excepts_stay_gated():
    """E722 in the gated flake8 selection is what keeps `except:` out.

    The issue reported it as missing; it is present in both gates. Asserted
    here so removing it fails visibly rather than reopening the door quietly.
    """
    for gate in ('.github/workflows/ci.yml', 'scripts/release.sh'):
        text = (ROOT / gate).read_text()
        assert 'E722' in text, f'{gate} no longer gates on E722'


def test_there_are_no_bare_excepts_left():
    """The other half: the gate only helps if the count is already zero."""
    offenders = []
    for path in _python_sources():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                offenders.append(f'{path.relative_to(ROOT)}:{node.lineno}')

    assert not offenders, f'bare `except:` remains at {offenders}'
