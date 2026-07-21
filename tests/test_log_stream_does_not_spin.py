"""The log stream must not burn a worker thread at 100% CPU forever.

Regression test for #418. `stream_logs` tailed the log with
``while True: f.readline()`` — no sleep, no exit condition. At EOF readline()
returns '' immediately, so the loop never yielded and never blocked: the
generator spun on the CPU indefinitely, and because nothing was ever written
to the socket a client disconnect was never detected. The Dockerfile runs one
worker with 8 threads, so opening the Logs page eight times wedged the
container.

The fix sleeps between empty reads, emits an SSE keepalive comment (writing it
is what makes a dead client raise and end the generator), and gives up after a
bounded idle period.
"""

import time

import pytest

from modules.web.misc_routes import _stream_log_file


pytestmark = [pytest.mark.unit]


def test_missing_log_file_yields_one_frame_and_stops(tmp_path):
    frames = list(_stream_log_file(tmp_path / "nope.log"))
    assert frames == ["data: Log file not found\n\n"]


def test_idle_stream_sleeps_instead_of_spinning(tmp_path):
    """The core of the bug: an idle tail used to iterate as fast as the CPU
    allowed. Bound the iterations by wall-clock, not by luck."""
    log = tmp_path / "certmate.log"
    log.write_text("existing line\n")

    started = time.monotonic()
    frames = list(_stream_log_file(log, poll_seconds=0.01, max_idle_seconds=0.05))
    elapsed = time.monotonic() - started

    # 0.05s of idle at 0.01s per poll = ~5 keepalives, then the final notice.
    keepalives = [f for f in frames if f.startswith(":")]
    assert 3 <= len(keepalives) <= 8, f"unexpected poll count: {len(keepalives)}"
    # If it were still spinning, this would be thousands of iterations in
    # near-zero time.
    assert elapsed >= 0.04, "the generator did not actually sleep"


def test_idle_stream_terminates_instead_of_holding_the_thread(tmp_path):
    log = tmp_path / "certmate.log"
    log.write_text("")

    frames = list(_stream_log_file(log, poll_seconds=0.01, max_idle_seconds=0.03))

    assert frames[-1].startswith("data: [stream idle"), \
        "an abandoned tab would hold a worker thread forever"


def test_new_lines_are_streamed_and_reset_the_idle_timer(tmp_path):
    log = tmp_path / "certmate.log"
    log.write_text("old\n")

    gen = _stream_log_file(log, poll_seconds=0.01, max_idle_seconds=5)
    # Only content appended AFTER the stream opens is sent: the generator
    # seeks to the end, so a client does not get the whole history.
    first = next(gen)
    assert first.startswith(":"), "pre-existing lines must not be replayed"

    with open(log, "a") as f:
        f.write("fresh line\n")
        f.flush()

    frames = []
    for _ in range(20):
        frame = next(gen)
        frames.append(frame)
        if frame.startswith("data:"):
            break
    gen.close()

    assert any(f == "data: fresh line\n\n" for f in frames)


def test_a_disconnected_client_ends_the_generator(tmp_path):
    """Closing the consumer must stop the tail — that is what the keepalive
    write buys us in production, where the socket raises instead."""
    log = tmp_path / "certmate.log"
    log.write_text("")

    gen = _stream_log_file(log, poll_seconds=0.01, max_idle_seconds=60)
    next(gen)
    gen.close()

    with pytest.raises(StopIteration):
        next(gen)


def test_a_burst_of_lines_drains_without_sleeping_between_them(tmp_path):
    """Backlog must not be paced at one line per poll interval."""
    log = tmp_path / "certmate.log"
    log.write_text("")

    gen = _stream_log_file(log, poll_seconds=0.5, max_idle_seconds=60)
    # The generator is lazy: it opens the file and seeks to the end on the
    # first next(), so prime it before appending or the burst lands before
    # the seek and is never seen.
    next(gen)
    with open(log, "a") as f:
        for i in range(20):
            f.write(f"line {i}\n")
        f.flush()

    started = time.monotonic()
    data_frames = []
    while len(data_frames) < 20:
        frame = next(gen)
        if frame.startswith("data:"):
            data_frames.append(frame)
    elapsed = time.monotonic() - started
    gen.close()

    assert data_frames[0] == "data: line 0\n\n"
    assert data_frames[-1] == "data: line 19\n\n"
    # 20 lines at one 0.5s poll each would be 10s.
    assert elapsed < 1.0, f"the backlog was paced by the poll interval ({elapsed:.1f}s)"
