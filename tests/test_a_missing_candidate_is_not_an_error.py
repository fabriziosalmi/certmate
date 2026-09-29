"""A certbot candidate that is not there is not an error (container boot noise).

The probe tries `.venv/bin/certbot` first, the path a source checkout uses,
then `certbot` on PATH, which is where the image installs it. In the image the
first path does not exist, so every probe handed a missing path to
`ShellExecutor.run`, which logged the `FileNotFoundError` at ERROR before the
probe treated it as "next candidate":

    level=error  logger=modules.core.shell
    Command execution failed: [Errno 2] No such file or directory: '.venv/bin/certbot'
    level=info   certbot is available: certbot 2.10.0 (via certbot)

That first line appeared at every container start and again at every re-probe
(the answer's TTL is five minutes), on an instance where nothing was wrong. An
ERROR that means nothing teaches an operator to scroll past ERRORs. Seen on the
public demo on 2026-09-28.
"""
import logging

import pytest

from modules.core import issuance_readiness as readiness
from modules.core.shell import ShellExecutor

pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def clean_probe():
    readiness.reset()
    yield
    readiness.reset()


class _RecordingShell(ShellExecutor):
    """The real executor, so its own logging is what is measured, with the
    arguments recorded. `certbot` on PATH is answered without running it."""

    def __init__(self):
        self.calls = []

    def run(self, cmd, **kwargs):
        self.calls.append(cmd[0])
        if cmd[0] == 'certbot':
            import subprocess
            return subprocess.CompletedProcess(cmd, 0, stdout='certbot 2.10.0\n', stderr='')
        return super().run(cmd, **kwargs)


def test_an_absent_path_candidate_is_skipped_without_an_error(tmp_path, monkeypatch, caplog):
    """THE regression, with the real ShellExecutor and a working directory
    that has no `.venv`, which is what the container is."""
    monkeypatch.chdir(tmp_path)
    shell = _RecordingShell()

    with caplog.at_level(logging.DEBUG):
        status = readiness.probe(shell)

    assert status['state'] == 'ok'
    assert shell.calls == ['certbot'], 'the absent path was executed anyway'
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors == [], [r.getMessage() for r in errors]


def test_a_present_path_candidate_is_still_tried_first(tmp_path, monkeypatch):
    """CONTROL. In a source checkout the venv's certbot must still win over
    whatever `certbot` is on PATH, which may be a different version."""
    venv_bin = tmp_path / '.venv' / 'bin'
    venv_bin.mkdir(parents=True)
    (venv_bin / 'certbot').write_text('#!/bin/sh\necho certbot 9.9.9\n')
    (venv_bin / 'certbot').chmod(0o755)
    monkeypatch.chdir(tmp_path)
    shell = _RecordingShell()

    status = readiness.probe(shell)

    assert shell.calls[0] == '.venv/bin/certbot'
    assert status['version'] == 'certbot 9.9.9'


def test_when_nothing_is_there_the_failure_still_names_every_candidate(tmp_path, monkeypatch):
    """CONTROL. Skipping a missing path must not hide it from the one message
    that matters: the one saying certbot cannot run at all."""
    monkeypatch.chdir(tmp_path)

    class NoCertbot(_RecordingShell):
        def run(self, cmd, **kwargs):
            self.calls.append(cmd[0])
            raise FileNotFoundError(2, 'No such file or directory', cmd[0])

    status = readiness.probe(NoCertbot())

    assert status['state'] == 'failed'
    assert '.venv/bin/certbot' in status['error']
    assert 'certbot' in status['error']
