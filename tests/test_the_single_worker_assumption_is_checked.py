"""Two things are correct only under one worker, and both fail silently.

`_get_domain_lock` returns a `threading.Lock`. It serialises issuance and
renewal for a domain — *within one process*. With two gunicorn workers it is
two locks, so two requests for the same domain would run certbot concurrently
against the same `--config-dir`, and the four-file publish would interleave
with itself, producing the mixed generation `reconcile_served_copies` exists to
repair — arrived at deliberately rather than by a crash.

APScheduler is worse. It runs in-process, so two workers means two schedulers:
every certificate examined and renewed *once per worker*, against the CA's rate
limits.

Both facts lived in a `CMD` line (`--workers 1`) and in the Helm chart, which
pins one replica and refuses more at template time. Neither was stated in the
code that depends on them, and nothing checked the one route left to violate
them: overriding the command.

A worker cannot ask how many workers there are — each is a separate process —
so it reads its parent's command line. That works on Linux, which the image
runs. Everywhere else, and under `python app.py` or pytest, the answer is
`None` and nothing is said: a guess would be worse than silence, because a
CRITICAL that fires in development teaches people to ignore it.
"""
import logging

import pytest

from modules.core import factory

pytestmark = [pytest.mark.unit]


class _Parent:
    """Stands in for /proc/<ppid>/cmdline with a chosen command line."""

    def __init__(self, monkeypatch, argv):
        self.blob = b'\0'.join(a.encode() for a in argv) + b'\0'
        monkeypatch.setattr(factory.os, 'getppid', lambda: 4242)
        real_open = open

        def fake_open(path, *args, **kwargs):
            if str(path) == '/proc/4242/cmdline':
                import io
                return io.BytesIO(self.blob)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr('builtins.open', fake_open)


# --- reading the worker count -------------------------------------------

@pytest.mark.parametrize('argv, expected', [
    (['/usr/bin/gunicorn', '--bind', '0.0.0.0:8000', '--workers', '1',
      '--threads', '8', 'app:app'], 1),
    (['/usr/bin/gunicorn', '--workers', '4', 'app:app'], 4),
    (['/usr/bin/gunicorn', '-w', '3', 'app:app'], 3),
    (['/usr/bin/gunicorn', '--workers=2', 'app:app'], 2),
    # gunicorn's own default when the flag is absent.
    (['/usr/bin/gunicorn', 'app:app'], 1),
])
def test_the_worker_count_is_read_from_the_parent(monkeypatch, argv, expected):
    _Parent(monkeypatch, argv)
    assert factory.worker_count() == expected


@pytest.mark.parametrize('argv', [
    ['/usr/bin/python', 'app.py'],
    ['/usr/bin/python', '-m', 'pytest'],
    ['/bin/sh', '-c', 'something else'],
])
def test_a_parent_that_is_not_gunicorn_answers_nothing(monkeypatch, argv):
    """CONTROL: `python app.py` and pytest must produce no answer, so the
    caller says nothing. A guess here becomes a CRITICAL in development, and
    a CRITICAL that fires in development teaches people to ignore it."""
    _Parent(monkeypatch, argv)
    assert factory.worker_count() is None


def test_an_unreadable_parent_answers_nothing(monkeypatch):
    """Not Linux, or a hardened /proc. Silence, not a guess."""
    monkeypatch.setattr(factory.os, 'getppid', lambda: 4242)

    def refuse(path, *args, **kwargs):
        raise OSError('no /proc here')

    monkeypatch.setattr('builtins.open', refuse)
    assert factory.worker_count() is None


def test_a_malformed_worker_count_answers_nothing(monkeypatch):
    _Parent(monkeypatch, ['/usr/bin/gunicorn', '--workers', 'lots', 'app:app'])
    assert factory.worker_count() is None


def test_a_trailing_flag_with_no_value_does_not_crash(monkeypatch):
    """CONTROL for the index arithmetic: `--workers` as the last argument."""
    _Parent(monkeypatch, ['/usr/bin/gunicorn', 'app:app', '--workers'])
    assert factory.worker_count() is None


# --- what it says --------------------------------------------------------

def test_more_than_one_worker_is_reported_at_critical(monkeypatch, caplog):
    _Parent(monkeypatch, ['/usr/bin/gunicorn', '--workers', '4', 'app:app'])

    with caplog.at_level(logging.CRITICAL, logger='certmate.factory'):
        assert factory.warn_if_multiple_workers() == 4

    said = ' '.join(r.getMessage() for r in caplog.records)
    assert 'single-worker' in said, f'nothing was said: {said!r}'
    assert 'rate limits' in said, (
        'the message does not say what goes wrong — duplicate renewals are '
        'the consequence an operator can act on'
    )
    assert '--workers 1' in said, 'the message does not say what to do instead'


def test_one_worker_says_nothing(monkeypatch, caplog):
    """CONTROL: a line on every start is a line nobody reads, and the correct
    configuration is by far the common one."""
    _Parent(monkeypatch, ['/usr/bin/gunicorn', '--workers', '1', 'app:app'])
    with caplog.at_level(logging.DEBUG, logger='certmate.factory'):
        assert factory.warn_if_multiple_workers() == 1
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_an_unknown_count_says_nothing(monkeypatch, caplog):
    _Parent(monkeypatch, ['/usr/bin/python', 'app.py'])
    with caplog.at_level(logging.DEBUG, logger='certmate.factory'):
        assert factory.warn_if_multiple_workers() is None
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


# --- the wiring, and the comment that explains it -----------------------

def test_startup_performs_the_check():
    """Reads the file by path rather than via factory.__file__: the suite's
    autouse fixture anchors that attribute at a stub so create_app does not
    write into the checkout, and reading it here would measure the stub."""
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
              / 'core' / 'factory.py').read_text()
    assert 'warn_if_multiple_workers()' in source.split('def create_app')[-1], (
        'create_app no longer checks the worker count, so the one route left '
        'to violate the single-worker assumption is unguarded again'
    )


def test_the_lock_says_it_is_per_process():
    """The comment is the durable half: the next person to add a second
    worker reads the code before they read the CMD line."""
    from modules.core.certificates import CertificateManager
    doc = CertificateManager._get_domain_lock.__doc__ or ''
    assert 'per-PROCESS' in doc or 'per-process' in doc
    assert 'one worker' in doc, (
        'the docstring does not name the assumption the lock rests on'
    )


def test_nothing_calls_a_structured_logger_with_lazy_arguments():
    """A latent TypeError that only fires in the branch nobody exercises.

    `get_certmate_logger` returns a `StructuredLogger`, whose methods are
    `(message, **fields)` — not the stdlib's `(msg, *args)`. Passing lazy
    `%s` arguments raises `TypeError` at the call, and these calls live in
    exactly the places that run rarely: a startup misconfiguration, a failure
    path. The warning about a broken configuration would itself become the
    failure.

    Found while writing `warn_if_multiple_workers`, which had this bug. The
    rest of the codebase is already consistent; this keeps it that way.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in list((root / 'modules').rglob('*.py')) + [root / 'app.py']:
        source = path.read_text(encoding='utf-8')
        if 'get_certmate_logger' not in source:
            continue
        tree = ast.parse(source)

        bound = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if ast.unparse(node.value.func).endswith('get_certmate_logger'):
                    bound.update(t.id for t in node.targets
                                 if isinstance(t, ast.Name))

        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in bound
                    and node.func.attr in ('debug', 'info', 'warning',
                                           'error', 'critical', 'exception')
                    and len(node.args) > 1):
                offenders.append(
                    f'{path.relative_to(root)}:{node.lineno} '
                    f'{node.func.value.id}.{node.func.attr}() with '
                    f'{len(node.args)} positional arguments')

    assert not offenders, (
        'a StructuredLogger takes (message, **fields), so these raise '
        'TypeError when they run — and they run on the rare paths:\n  '
        + '\n  '.join(offenders))
