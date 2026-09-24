"""Three from the #591 re-triage where the right answer existed and was lost.

**A cleared Timeout box was a 500.** `_validate_hook` did
`int(hook.get('timeout', DEFAULT_TIMEOUT))` with nothing around it, and the
shipped UI binds `x-model.number` — Alpine emits `null` for an empty numeric
input. `int(None)` is a TypeError, which the deploy-config route's blanket
handler turned into `500 {"error": "Failed to save deploy config"}`. So
clearing a field and pressing Save produced a server error with no clue.

**A missing certificate was a 422.** `renew_certificate` raised
`FileNotFoundError("No certificate found for domain: ...")` inside its try,
and the catch-all re-wrapped every exception as
`RuntimeError(f"Exception: {msg}")`. The `except FileNotFoundError:` arm in
`resources_lifecycle.py` — which returns 404 — was therefore dead code, and
an operator asking to renew something that is not there was told the CA had
refused. Measured on a real manager before the fix:

    tipo sollevato       : RuntimeError
    e FileNotFoundError? : False
    messaggio            : Exception: No certificate found for domain: ...

**A hook that backgrounded anything was a timeout.** `capture_output=True`
makes subprocess wait for EOF on the pipes, and a backgrounded grandchild
inherits them. So `curl ... &` — where the direct child exits at once — was
reported as "timeout after Ns", and the operator could not work around it
either: `_is_command_safe` refuses `>/dev/null`, so the stdio cannot be
detached by hand. Measured with a 2s timeout:

    'sleep 6 &'                pipe : TIMEOUT dopo 2.00s   file : uscito dopo 0.01s
    'echo avviato; sleep 6 &'  pipe : TIMEOUT dopo 2.00s   file : uscito dopo 0.01s
    'sleep 6'                  pipe : TIMEOUT dopo 2.00s   file : TIMEOUT dopo 2.01s

That last line is the control: the fix must stop the timeout firing on a
process that has already exited, not remove the timeout.
"""
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = [pytest.mark.unit]


@pytest.fixture
def deployer(tmp_path):
    from modules.core.deployer import DeployManager
    from modules.core.shell import ShellExecutor

    # (settings_manager, shell_executor, audit_logger, event_bus, ...) —
    # the executor is the SECOND positional, not a keyword. The first draft
    # passed it by name on top of four positionals and every test errored on
    # the constructor, which says nothing about the behaviour under test.
    return DeployManager(MagicMock(), ShellExecutor(), MagicMock(),
                         MagicMock(),
                         cert_dir=tmp_path / 'certs',
                         data_dir=str(tmp_path / 'data'))


def _hook(**overrides):
    hook = {'id': 'h1', 'name': 'reload', 'command': 'echo hi'}
    hook.update(overrides)
    return hook


# --- a timeout that is not a number --------------------------------------

@pytest.mark.parametrize('value', [None, ''])
def test_a_cleared_field_takes_the_default(deployer, value):
    """THE regression. Alpine sends null for an empty numeric input, and the
    neighbouring fields already treat an absence as an absence: `on_events`
    and `enabled` fall back rather than refusing."""
    from modules.core.deployer import DEFAULT_TIMEOUT

    hook = _hook(timeout=value)
    ok, error = deployer._validate_hook(hook)

    assert ok is True, error
    assert hook['timeout'] == DEFAULT_TIMEOUT


def test_a_missing_field_takes_the_default_too(deployer):
    from modules.core.deployer import DEFAULT_TIMEOUT

    hook = _hook()
    ok, error = deployer._validate_hook(hook)

    assert (ok, error) == (True, None)
    assert hook['timeout'] == DEFAULT_TIMEOUT


@pytest.mark.parametrize('value', ['abc', [30], {'s': 30}, True, False])
def test_a_value_that_is_not_a_number_is_named(deployer, value):
    """Present and wrong is a mistake, and saying so beats silently running
    with a timeout the operator never chose. The same distinction
    `save_config` draws for `enabled`: absent leaves alone, present-and-wrong
    is refused."""
    ok, error = deployer._validate_hook(_hook(timeout=value))

    assert ok is False
    assert 'timeout must be a number' in error
    assert "hook 'reload'" in error, 'the refusal does not name the hook'


@pytest.mark.parametrize('value,expected', [
    (30, 30), ('45', 45), (0, 1), (-5, 1), (99999, 300),
])
def test_a_number_is_still_clamped(deployer, value, expected):
    """CONTROL. Naming the bad values must not stop the good ones being
    bounded — an unbounded hook timeout holds the deploy queue."""
    hook = _hook(timeout=value)
    ok, _ = deployer._validate_hook(hook)

    assert ok is True
    assert hook['timeout'] == expected


# --- a missing certificate is not a CA refusal ---------------------------

@pytest.fixture(scope='module')
def certificates(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('renew')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.core.factory import create_app
        _, container = create_app()
        yield container.managers['certificates']


def test_renewing_what_is_not_there_says_so(certificates):
    """THE regression, on the real manager. The route maps this type to 404;
    re-wrapped as RuntimeError it became a 422 "renewal failed"."""
    with pytest.raises(FileNotFoundError):
        certificates.renew_certificate('nosuch.example.com')


def test_the_route_still_has_somewhere_to_send_it():
    """A pass-through is only a fix if something downstream acts on the
    type. This asserts the arm that was dead code is still there."""
    import inspect

    from modules.api import resources_lifecycle

    source = inspect.getsource(resources_lifecycle)

    assert 'except FileNotFoundError:' in source
    assert "'NOT_FOUND'" in source


def test_an_unexpected_failure_is_still_wrapped():
    """CONTROL. The catch-all exists so an arbitrary fault does not reach the
    caller as itself; letting everything through would be the opposite
    defect."""
    import inspect

    from modules.core.certificates import CertificateManager

    source = inspect.getsource(CertificateManager.renew_certificate)

    assert 'raise RuntimeError(f"Exception: {error_msg}")' in source
    assert 'except (FileNotFoundError, DomainOperationInProgress):' in source


# --- a hook that backgrounds something is not a timeout ------------------

def _run_hook(deployer, command, timeout=2):
    started = time.time()
    result = deployer._run_hook(
        {'id': 'h1', 'name': 'bg', 'command': command, 'timeout': timeout,
         'enabled': True, 'on_events': ['renewed']},
        'example.com', 'renewed')
    return result, time.time() - started


def test_a_hook_that_backgrounds_something_returns_at_once(deployer):
    """THE regression. The direct child exits immediately; only the pipes
    were still open, held by the grandchild."""
    result, elapsed = _run_hook(deployer, 'sleep 6 &')

    assert result['status'] == 'success', result.get('error')
    assert elapsed < 1.5, f'took {elapsed:.2f}s for a command that exits at once'


def test_the_output_of_an_ordinary_hook_is_still_captured(deployer):
    """Files instead of pipes must not cost the output — the delivery log
    and the audit record are built from it.

    Not `echo avviato; sleep 6 &`, which the first draft used: the command
    guard refuses `;` and `>`, so that is not a hook an operator could write
    either. A probe the product would reject measures nothing about the
    product.
    """
    result, _ = _run_hook(deployer, 'echo avviato')

    assert result['status'] == 'success'
    assert 'avviato' in result['stdout']


def test_a_genuinely_slow_hook_still_times_out(deployer):
    """THE control, and the one that matters: this must stop the timeout
    firing on a process that has already exited, not remove the timeout."""
    result, elapsed = _run_hook(deployer, 'sleep 6')

    assert result['status'] == 'failure'
    assert 'timeout' in (result.get('error') or '')
    assert elapsed < 4, f'the timeout did not fire ({elapsed:.2f}s)'


def test_a_failing_hook_still_reports_its_exit_code(deployer):
    """CONTROL on the other half of the change: the return code comes from
    the process, and reading output from a file must not lose it."""
    result, _ = _run_hook(deployer, 'exit 3')

    assert result['status'] == 'failure'
    assert result['exit_code'] == 3
    assert 'exit code 3' in result['error']


def test_the_hooks_stderr_is_still_captured(deployer):
    """The other stream, read from the other file."""
    result, _ = _run_hook(deployer, 'echo problema >&2')

    assert result['status'] == 'success'
    assert 'problema' in result['stderr']


@pytest.mark.parametrize('command,allowed', [
    ('echo x', True),
    ('echo x >&2', True),       # redirect to a stream: fine
    ('echo x | cat', True),     # a pipe: fine
    ('sleep 1 &', True),        # BACKGROUNDING IS ALLOWED — hence this defect
    ('echo x; echo y', False),
    ('echo x && echo y', False),
    ('echo x > /dev/null', False),   # and hence no workaround for it
    ('echo `id`', False),
])
def test_what_the_command_guard_permits(deployer, command, allowed):
    """Measured, because the first draft of two probes above guessed and was
    wrong in both directions: it assumed `>` was refused (it is not — only a
    redirect to a FILE is) and that `;` was fine (it is not).

    The two rows that matter to this change are next to each other:
    backgrounding with `&` is permitted, so operators do it — and
    `> /dev/null` is refused, so the usual way to detach a hook's stdio is
    not available to them. Which is why "it timed out" was the only answer
    they could get.
    """
    ok, reason = deployer._is_command_safe(command)

    assert ok is allowed, reason


def test_the_measurement_behind_this(tmp_path):
    """The difference itself, at the subprocess level, so the reason for
    files survives even if `_run_hook` is rewritten around them."""
    def elapsed(use_files):
        started = time.time()
        try:
            if use_files:
                with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                    subprocess.run(['sh', '-c', 'sleep 6 &'], stdout=out,
                                   stderr=err, timeout=2)
            else:
                subprocess.run(['sh', '-c', 'sleep 6 &'], capture_output=True,
                               timeout=2)
        except subprocess.TimeoutExpired:
            return None
        return time.time() - started

    assert elapsed(use_files=False) is None, 'pipes no longer block — good news'
    took = elapsed(use_files=True)
    assert took is not None and took < 1.0


def test_the_hook_runner_waits_on_the_process():
    """Asserted on the call so a future edit cannot quietly put the pipes
    back: `capture_output=True` is the shape that caused this."""
    import inspect

    from modules.core.deployer import DeployManager

    source = inspect.getsource(DeployManager._run_hook)

    assert 'capture_output=False' in source
    assert 'tempfile.TemporaryFile()' in source
    assert Path  # keeps the import used
