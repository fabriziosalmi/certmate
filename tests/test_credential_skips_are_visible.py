"""A skipped test is not a passing test, and the run has to say so.

Ten test files hang off the `cloudflare_token` fixture. Without the token they
all skip, and `9 skipped` at the end of a green run is indistinguishable from
`9 passed` to anyone reading quickly — which is how a whole class of tests can
rot for years while the board stays green. The audit found the class; nothing
in the repository made it visible.

Three mechanisms, and each one can be wrong on its own:

* the skip reason carries a mark the terminal summary counts, so the run ends
  by naming what it did not measure;
* `CERTMATE_REQUIRE_CREDENTIALED=1` turns those skips into failures, so a job
  that exists to run them cannot silently run none — the same mechanism
  `CERTMATE_UI_REQUIRE_BROWSER` already provides for the Playwright suite;
* the `credentialed` marker is applied by derivation from the fixtures a test
  requests, so `-m credentialed` selects exactly this class and cannot drift
  the way a hand-written marker does.

These tests drive the conftest helpers directly rather than through a nested
pytest run: the logic is small, and a subprocess run would need the container
fixture for reasons that have nothing to do with what is being checked.
"""
import pytest

from tests import conftest

pytestmark = [pytest.mark.unit]


class _Reporter:
    """Enough of a terminal reporter to record what the summary writes."""

    def __init__(self, skipped):
        self.stats = {'skipped': skipped}
        self.lines = []
        self.seps = []

    def write_sep(self, char, title, **kw):
        self.seps.append(title)

    def write_line(self, line, **kw):
        self.lines.append(line)


class _Report:
    def __init__(self, reason):
        self.longrepr = ('some/path.py', 12, reason)


def _summary(skipped):
    reporter = _Reporter(skipped)
    conftest.pytest_terminal_summary(reporter, 0, None)
    return reporter


# --- the skip carries something countable --------------------------------

def test_a_missing_credential_skips_with_a_countable_mark(monkeypatch):
    monkeypatch.setattr(conftest, '_REQUIRE_CREDENTIALED', False)
    with pytest.raises(pytest.skip.Exception) as caught:
        conftest._credential_missing('CLOUDFLARE_API_TOKEN', 'real DNS tests')

    message = str(caught.value)
    assert conftest.CREDENTIAL_SKIP_MARK in message
    assert 'CLOUDFLARE_API_TOKEN' in message
    assert 'real DNS tests' in message


def test_the_skip_is_a_skip_and_not_a_pass(monkeypatch):
    """CONTROL: a helper that returned instead of raising would let every one
    of these tests run against a None token and fail somewhere unrelated.

    `Skipped` and `Failed` derive from BaseException, so `pytest.raises(
    Exception)` does not catch them — it lets the outcome propagate and the
    test itself is reported as skipped. Which is exactly the confusion this
    whole file is about, arrived at from the other direction."""
    monkeypatch.setattr(conftest, '_REQUIRE_CREDENTIALED', False)
    with pytest.raises(pytest.skip.Exception) as caught:
        conftest._credential_missing('X_TOKEN', 'something')
    assert type(caught.value).__name__ == 'Skipped'


def test_requiring_the_credential_turns_the_skip_into_a_failure(monkeypatch):
    monkeypatch.setattr(conftest, '_REQUIRE_CREDENTIALED', True)
    with pytest.raises(pytest.fail.Exception) as caught:
        conftest._credential_missing('CLOUDFLARE_API_TOKEN', 'real DNS tests')

    assert type(caught.value).__name__ == 'Failed'
    assert 'CERTMATE_REQUIRE_CREDENTIALED=1' in str(caught.value)


# --- the run says what it did not measure --------------------------------

def test_the_summary_names_the_count_and_the_variable():
    reporter = _summary([
        _Report(f'{conftest.CREDENTIAL_SKIP_MARK} CLOUDFLARE_API_TOKEN not set'),
        _Report(f'{conftest.CREDENTIAL_SKIP_MARK} CLOUDFLARE_API_TOKEN not set'),
    ])
    text = ' '.join(reporter.lines)
    assert '2 test(s) did not run' in text
    assert 'CLOUDFLARE_API_TOKEN' in text
    assert 'unmeasured' in text, (
        'the summary reports a number without saying what it means; "skipped" '
        'reading as "fine" is the whole defect'
    )
    assert 'CERTMATE_REQUIRE_CREDENTIALED=1' in text, (
        'the summary does not say how to make this fail instead'
    )


def test_a_run_with_no_credential_skips_says_nothing():
    """CONTROL: a banner on every run is a banner nobody reads."""
    assert _summary([]).lines == []
    assert _summary([_Report('needs a browser')]).lines == []


def test_ordinary_skips_are_not_counted_as_missing_credentials():
    """CONTROL: over-counting would make the number meaningless in the other
    direction — every platform skip would look like an unmeasured test."""
    reporter = _summary([
        _Report('not supported on this platform'),
        _Report(f'{conftest.CREDENTIAL_SKIP_MARK} CLOUDFLARE_API_TOKEN not set'),
    ])
    assert '1 test(s) did not run' in ' '.join(reporter.lines)


# --- the marker is derived, not written by hand --------------------------

class _Item:
    def __init__(self, fixtures):
        self.fixturenames = fixtures
        self.markers = []

    def add_marker(self, marker):
        self.markers.append(marker)


def test_a_test_that_asks_for_the_token_is_marked():
    item = _Item(['cloudflare_token', 'api'])
    conftest.pytest_collection_modifyitems(None, [item])
    assert [m.name for m in item.markers] == ['credentialed']


def test_a_test_that_does_not_is_left_alone():
    item = _Item(['tmp_path'])
    conftest.pytest_collection_modifyitems(None, [item])
    assert item.markers == []


def test_the_marker_is_declared_so_strict_markers_accepts_it():
    """pytest.ini runs with --strict-markers, so an undeclared marker is a
    collection error rather than a typo nobody notices."""
    import pathlib
    ini = (pathlib.Path(__file__).resolve().parent.parent
           / 'pytest.ini').read_text()
    assert 'credentialed:' in ini


def test_the_real_fixture_is_the_one_that_is_derived_from():
    """CONTROL: renaming the fixture without updating the derivation would
    silently stop marking anything, and -m credentialed would select zero
    tests while still exiting 0."""
    assert hasattr(conftest, 'cloudflare_token')
    assert 'cloudflare_token' in conftest.CREDENTIALED_FIXTURES
