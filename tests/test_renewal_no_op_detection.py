"""Telling a real renewal from a no-op (#666).

`certbot renew` exits 0 both when it renews and when nothing is due, so the
exit code cannot answer the question. Getting it wrong stamps `renewed_at` and
reports a renewal that did not happen — false telemetry that masks a genuinely
stuck renewal, which is worse than reporting nothing at all.

Two signals, and the ORDER between them is the contract:

* the artifact — fingerprint the live certificate before and after. This one
  cannot lie;
* the output sentinel ("not yet due for renewal") — the fallback for executors
  that stage no real files. It must never be primary, because certbot
  suppresses those messages under `--quiet`, and a suppressed sentinel reads
  as "it renewed".

Before the extraction this decision was six lines in the middle of a 137-line
result handler, reachable only by staging a whole renewal. It is a pure
decision over four inputs, so it is tested as one.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]


class _Result:
    def __init__(self, stdout='', stderr=''):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = 0


def _manager(tmp_path, fingerprint=None):
    manager = CertificateManager(
        cert_dir=tmp_path, settings_manager=MagicMock(),
        dns_manager=MagicMock(), storage_manager=None, ca_manager=None,
        shell_executor=MagicMock())
    manager._cert_fingerprint = lambda path: fingerprint
    return manager


# ---------------------------------------------------------------------------
# The artifact is primary
# ---------------------------------------------------------------------------

def test_a_changed_fingerprint_means_it_renewed(tmp_path):
    manager = _manager(tmp_path, fingerprint='after')
    assert manager._renewal_happened(_Result(), True, tmp_path / 'c.pem', 'before')


def test_an_unchanged_fingerprint_means_it_did_not(tmp_path):
    manager = _manager(tmp_path, fingerprint='same')
    assert not manager._renewal_happened(_Result(), True, tmp_path / 'c.pem', 'same')


def test_a_certificate_that_is_still_absent_did_not_renew(tmp_path):
    """`_cert_fingerprint` returns None when there is no file. Treating that
    as "changed" would report a renewal for a lineage that produced nothing."""
    manager = _manager(tmp_path, fingerprint=None)
    assert not manager._renewal_happened(_Result(), True, tmp_path / 'c.pem', 'before')


def test_a_certificate_that_appeared_where_there_was_none_did_renew(tmp_path):
    manager = _manager(tmp_path, fingerprint='new')
    assert manager._renewal_happened(_Result(), True, tmp_path / 'c.pem', None)


@pytest.mark.parametrize('output', [
    'not yet due for renewal',
    'no renewals were attempted',
    'Cert not yet due for renewal',
])
def test_the_sentinel_does_not_override_the_artifact(tmp_path, output):
    """THE contract. certbot printing "not yet due" while the certificate on
    disk changed means the fingerprint is right and the message is stale — and
    the reverse (silent output, unchanged file) is what --quiet produces.
    The artifact wins in both directions.
    """
    manager = _manager(tmp_path, fingerprint='after')
    assert manager._renewal_happened(
        _Result(stdout=output), True, tmp_path / 'c.pem', 'before'), (
        'the output sentinel overrode a real change on disk'
    )


# ---------------------------------------------------------------------------
# The sentinel is the fallback, and only that
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('field', ['stdout', 'stderr'])
@pytest.mark.parametrize('phrase', [
    'not yet due for renewal',
    'no renewals were attempted',
    'Cert NOT YET DUE FOR RENEWAL',
])
def test_without_artifacts_the_sentinel_reports_a_no_op(tmp_path, field, phrase):
    manager = _manager(tmp_path)
    assert not manager._renewal_happened(
        _Result(**{field: phrase}), False, tmp_path / 'c.pem', None)


def test_without_artifacts_silence_reads_as_a_renewal(tmp_path):
    """Deliberate, and the reason the sentinel must never be primary: under
    `--quiet` certbot prints nothing for a no-op, so this is exactly the case
    that would be wrong if the fingerprint check were skipped in production.
    It is not — `produces_artifacts` is False only for test doubles.
    """
    manager = _manager(tmp_path)
    assert manager._renewal_happened(_Result(), False, tmp_path / 'c.pem', None)


@pytest.mark.parametrize('result', [
    _Result(stdout=None, stderr=None),
    _Result(stdout='', stderr=''),
])
def test_missing_output_does_not_raise(tmp_path, result):
    """capture_output can leave these None, and a TypeError here would surface
    as a failed renewal for a run that succeeded.

    Measured, so the strength of this is not overstated: the current
    `f"{x or ''}"` form survives None either way — dropping the `or ''` from an
    f-string yields the string "None", which matches no sentinel. What this
    catches is the plausible rewrite, `(result.stdout + '\\n' + result.stderr)`,
    which raises. It guards a shape the code could take, not one it has.
    """
    manager = _manager(tmp_path)
    assert manager._renewal_happened(result, False, tmp_path / 'c.pem', None) is True


def test_the_fingerprint_is_read_from_the_live_path_it_is_given(tmp_path):
    """CONTROL: reading the flat copy instead of live/ would compare the file
    the publish step writes AFTER this decision, and always report a renewal.
    """
    seen = []
    manager = _manager(tmp_path)
    manager._cert_fingerprint = lambda path: seen.append(path) or 'x'

    live = tmp_path / 'example.com' / 'live' / 'example.com' / 'cert.pem'
    manager._renewal_happened(_Result(), True, live, 'before')

    assert seen == [live], f'fingerprinted {seen}, not the live path'
