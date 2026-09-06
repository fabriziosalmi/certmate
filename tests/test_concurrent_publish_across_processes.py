"""Two processes publishing the same domain must not leave a mixed generation.

The per-domain lock is a `threading.Lock` (certificates.py), so it serialises
threads inside one worker and nothing else. The renewal flock covers the
scheduled sweep, and by its own docstring does not cover the synchronous
issuance path. Every existing concurrency test races threads in one
interpreter, so the cross-process case — two containers on a shared data
directory, or an operator who raised `--workers` — was never exercised.

The invariant that has to survive it is not "one of them wins". It is that
whichever wins, the four published PEM files come from the SAME issuance: a
cert.pem from one generation beside a privkey.pem from another cannot complete
a handshake, and it is served straight off disk by the download endpoint and
pushed to every deploy hook.

The promote step is four independent renames, and the staging files are named
after the destination — so both processes stage through the same paths (#663).
"""
import multiprocessing
from pathlib import Path

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES

pytestmark = [pytest.mark.unit]

ROUNDS = 25


def _publish(generation, src_root, dest_dir, barrier, results):
    """Stage a whole generation and promote it, repeatedly, racing a sibling.

    Reports how much work it really did: a worker that dies on import would
    otherwise let the race test pass without a race ever happening.
    """
    manager = CertificateManager.__new__(CertificateManager)
    src = Path(src_root) / generation
    dest = Path(dest_dir)
    completed = 0
    errors = 0
    for _ in range(ROUNDS):
        try:
            barrier.wait(timeout=30)
        except Exception:
            break
        try:
            manager._publish_flat_files(src, dest)
            completed += 1
        except Exception:
            # A losing racer may find its staging file gone; that is a legal
            # outcome. Publishing a MIXED generation is not, and the parent
            # checks for that.
            errors += 1
    results.put((generation, completed, errors))


def _generation_of(dest_dir):
    """Which generation each published file belongs to, or None if absent."""
    seen = {}
    for name in CERTIFICATE_FILES:
        path = Path(dest_dir) / name
        if not path.exists():
            seen[name] = None
            continue
        content = path.read_bytes()
        seen[name] = content.split(b'-')[0].decode(errors='replace')
    return seen


@pytest.mark.slow
def test_two_processes_publishing_never_leave_a_split_generation(tmp_path):
    src_root = tmp_path / 'src'
    dest = tmp_path / 'live-flat'
    dest.mkdir()

    # Two complete, internally consistent generations.
    for generation in ('AAAA', 'BBBB'):
        gen_dir = src_root / generation
        gen_dir.mkdir(parents=True)
        for name in CERTIFICATE_FILES:
            (gen_dir / name).write_bytes(f'{generation}-{name}\n'.encode())

    ctx = multiprocessing.get_context('spawn')
    barrier = ctx.Barrier(2)
    results = ctx.Queue()

    workers = [
        ctx.Process(target=_publish,
                    args=(generation, str(src_root), str(dest), barrier,
                          results))
        for generation in ('AAAA', 'BBBB')
    ]
    for w in workers:
        w.start()

    # Drain BEFORE joining, and by count rather than by `empty()`.
    # multiprocessing.Queue.empty() is advisory: a child can finish put() and
    # exit while the bytes are still in the pipe, so draining after join()
    # loses results intermittently — which made an earlier version of this
    # test fail only under full-suite load. A flaky test is worse than none.
    reported = {}
    for _ in workers:
        generation, completed, errors = results.get(timeout=180)
        reported[generation] = (completed, errors)

    for w in workers:
        w.join(timeout=120)
        assert w.exitcode is not None, 'publisher process hung' 
    assert set(reported) == {'AAAA', 'BBBB'}, (
        f'both publishers must report back; got {reported} — a worker that '
        f'died on import would make this test pass without racing'
    )
    for generation, (completed, errors) in reported.items():
        assert completed + errors == ROUNDS, (
            f'{generation} only attempted {completed + errors}/{ROUNDS} '
            f'publishes, so the processes were not running concurrently'
        )
        assert completed > 0, f'{generation} never published successfully'

    published = _generation_of(dest)
    present = {name: gen for name, gen in published.items() if gen is not None}
    assert present, 'no certificate files were published at all'

    generations = set(present.values())
    assert len(generations) == 1, (
        f'the published files came from more than one issuance: {published}. '
        f'A cert.pem and privkey.pem from different generations cannot '
        f'complete a handshake, and this directory is what the download '
        f'endpoint serves and the deploy hooks receive.'
    )
    assert len(present) == len(CERTIFICATE_FILES), (
        f'only part of the bundle is present: {published}'
    )


def test_the_check_can_detect_a_split_generation(tmp_path):
    """CONTROL: prove the assertion above is capable of failing.

    Hand-build the mixed state the race could produce and confirm the helper
    reports two generations. Without this, a race that never interleaved would
    be indistinguishable from a check that cannot see mixing.
    """
    dest = tmp_path / 'flat'
    dest.mkdir()
    for name in CERTIFICATE_FILES[:-1]:
        (dest / name).write_bytes(f'AAAA-{name}\n'.encode())
    (dest / CERTIFICATE_FILES[-1]).write_bytes(b'BBBB-privkey.pem\n')

    generations = {g for g in _generation_of(dest).values() if g}
    assert generations == {'AAAA', 'BBBB'}, (
        'the helper cannot distinguish generations, so the race test above '
        'would pass regardless of what the race produced'
    )


def test_an_interleaved_promote_can_split_the_bundle(tmp_path):
    """Deterministic companion to the race above.

    Twenty-five rounds without a split is weak evidence — absence of a failure
    is not proof the window is closed. This drives the interleaving by hand
    instead of hoping the scheduler produces it: promote half of one
    generation, then the other half of a second.

    It documents the shape of the hazard the review recorded: the promote step
    is four independent renames, not a transaction. Publishing is atomic per
    FILE; it is not atomic across the bundle, and nothing in this layer makes
    it so across processes.
    """
    manager = CertificateManager.__new__(CertificateManager)
    dest = tmp_path / 'flat'
    dest.mkdir()

    sources = {}
    for generation in ('AAAA', 'BBBB'):
        gen_dir = tmp_path / generation
        gen_dir.mkdir()
        for name in CERTIFICATE_FILES:
            (gen_dir / name).write_bytes(f'{generation}-{name}\n'.encode())
        sources[generation] = gen_dir

    manager._publish_flat_files(sources['AAAA'], dest)
    # Now emulate a second process promoting only part of its bundle — the
    # state a crash, an OOM kill or an unlucky interleave leaves behind.
    for name in CERTIFICATE_FILES[:2]:
        (dest / name).write_bytes(f'BBBB-{name}\n'.encode())

    generations = {g for g in _generation_of(dest).values() if g}
    assert generations == {'AAAA', 'BBBB'}, (
        'the bundle should now hold two generations; if it does not, this '
        'test is not reproducing the hazard it claims to describe'
    )
    # Recorded, not asserted away: a split bundle is reachable at this layer.
    # What prevents it in production is the per-domain lock (one process) and
    # the renewal flock (the sweep) — neither of which covers two processes on
    # the synchronous issuance path. Closing that is architectural work, not a
    # test change; see the non-transactional-publish item in phase 4.
