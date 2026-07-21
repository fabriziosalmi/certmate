"""File logging, when enabled, is rotated by construction.

Regression tests for #431 (the application-log half; rotating the
tamper-evident audit chain is a separate design and a separate issue).

The audit found "no log rotation anywhere". Looking at it, the situation was
one step stranger: `configure_structured_logging` accepted a `log_file` and
nothing ever passed one, so the application never wrote a log file at all —
`logs/certmate.log`, which the web UI's log stream tails, was never created by
anything. So the fix is not "add rotation to the file handler", it is "make
the file handler exist, and make it impossible to have one without rotation".

Console logging remains the default: the container logs to stdout, which is
what `docker logs` and every shipper expect.
"""

import logging
import os

import pytest

from modules.core.structured_logging import (
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_MAX_BYTES,
    configure_structured_logging,
)


pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def _restore_root_logger():
    """configure_structured_logging replaces the root handlers; put them back
    so this module cannot silence the rest of the suite."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    yield
    for h in root.handlers[:]:
        root.removeHandler(h)
    for h in saved_handlers:
        root.addHandler(h)
    root.setLevel(saved_level)


def _file_handlers():
    return [
        h for h in logging.getLogger().handlers
        if isinstance(h, logging.FileHandler)
    ]


def test_no_file_handler_by_default():
    """stdout only, unless an operator asks for a file."""
    configure_structured_logging(json_output=False)
    assert _file_handlers() == []


def test_enabling_a_log_file_always_gives_a_rotating_handler(tmp_path):
    log_file = tmp_path / "certmate.log"

    configure_structured_logging(json_output=False, log_file=str(log_file))

    handlers = _file_handlers()
    assert len(handlers) == 1
    handler = handlers[0]
    # The point of the issue: a plain FileHandler grows without bound.
    assert isinstance(handler, logging.handlers.RotatingFileHandler)
    assert handler.maxBytes == DEFAULT_LOG_MAX_BYTES
    assert handler.backupCount == DEFAULT_LOG_BACKUP_COUNT


def test_the_file_is_actually_written(tmp_path):
    log_file = tmp_path / "certmate.log"
    configure_structured_logging(json_output=False, log_file=str(log_file))

    logging.getLogger("test").warning("hello from the test")

    assert log_file.exists()
    assert "hello from the test" in log_file.read_text()


def test_it_rotates_at_the_configured_size(tmp_path):
    log_file = tmp_path / "certmate.log"
    configure_structured_logging(
        json_output=False, log_file=str(log_file), max_bytes=2048, backup_count=2,
    )
    logger = logging.getLogger("rotation-test")

    for i in range(200):
        logger.warning("x" * 100 + f" line {i}")

    rotated = sorted(p.name for p in tmp_path.glob("certmate.log*"))
    assert "certmate.log" in rotated
    assert "certmate.log.1" in rotated, "the log never rotated"
    # backupCount caps the tail: no .3 survives.
    assert "certmate.log.3" not in rotated
    for name in rotated:
        assert (tmp_path / name).stat().st_size < 20_000


def test_the_parent_directory_is_created(tmp_path):
    log_file = tmp_path / "nested" / "dir" / "certmate.log"

    configure_structured_logging(json_output=False, log_file=str(log_file))
    logging.getLogger("test").warning("creates its own directory")

    assert log_file.exists()


def test_an_unwritable_path_does_not_stop_the_application(tmp_path, caplog):
    """A certificate manager that refuses to boot because it cannot write a
    *log* has failed at the wrong thing."""
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o500)  # no write permission
    try:
        configure_structured_logging(
            json_output=False, log_file=str(blocked / "certmate.log"),
        )
        # Console logging still works, and nothing raised.
        assert _file_handlers() == []
        logging.getLogger("test").warning("still alive")
    finally:
        blocked.chmod(0o700)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_the_unwritable_case_is_reported(tmp_path, capsys):
    """Silence here would leave an operator thinking a log file exists.

    Captured from stderr rather than with caplog: configure_structured_logging
    removes every root handler, including the one caplog installs, so the only
    place the warning can be observed is the console handler it then adds.
    """
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    blocked.chmod(0o500)
    try:
        configure_structured_logging(
            json_output=False, log_file=str(blocked / "certmate.log"),
        )
    finally:
        blocked.chmod(0o700)

    err = capsys.readouterr().err
    assert "Could not open log file" in err
    assert "console logging only" in err
