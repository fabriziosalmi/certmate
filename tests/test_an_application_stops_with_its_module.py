"""An application built by a test stops with the module that built it.

`create_app()` starts a scheduler, an issuance pool and a watchdog, and leaves
stopping them to `atexit`. A test process builds hundreds of applications, and
before conftest.py stopped each with its module, all of their schedulers ran
until the last test: 284 of them by the end of the suite, every one firing
`deploy_window_drain` at each minute, in whatever test was running then.

What that did was measured on `tests/test_audit_chain_streaming.py`, which
holds the chain's verifier to a peak of memory. The verifier takes 25 KB. With
22 schedulers left by the modules before it, a window that crossed a minute
saw 666 KB, and the test failed in CI with 551 KB on a pull request that
changed one line of a lock file.

A rule about what one module leaves to the next cannot be seen from inside one
module. So a pytest run of its own is started here, with this repository's
conftest and two modules: the first builds applications, the second looks at
what is still running.
"""
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

BUILDS = """
    import pytest

    from modules.factory import create_app


    @pytest.fixture(scope="session")
    def for_the_session():
        return create_app()


    @pytest.fixture(scope="module")
    def for_the_module():
        return create_app()


    def test_three_applications_run_while_their_module_does(for_the_session, for_the_module):
        in_the_test = create_app()
        for _, container in (for_the_session, for_the_module, in_the_test):
            assert container.scheduler.running
"""

LOOKS = """
    import gc

    from apscheduler.schedulers.base import BaseScheduler


    def test_none_of_them_runs_in_the_module_after():
        schedulers = [o for o in gc.get_objects() if isinstance(o, BaseScheduler)]
        assert len(schedulers) == 3, len(schedulers)      # CONTROL: they are in this process, and found
        assert [s for s in schedulers if s.running] == []
"""


def test_what_one_module_builds_is_stopped_before_the_next(tmp_path):
    (tmp_path / 'test_one_builds.py').write_text(textwrap.dedent(BUILDS))
    (tmp_path / 'test_two_looks.py').write_text(textwrap.dedent(LOOKS))
    root = Path(__file__).resolve().parent.parent
    run = subprocess.run(
        [sys.executable, '-m', 'pytest', str(tmp_path), '-p', 'tests.conftest', '-p', 'no:cacheprovider',
         '-q', '--no-header', '--rootdir', str(tmp_path), '-c', '/dev/null'],
        cwd=root, capture_output=True, text=True, timeout=180)
    assert '2 passed' in run.stdout, run.stdout[-3000:] + run.stderr[-2000:]
