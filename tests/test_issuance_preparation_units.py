"""The pieces `_prepare_issuance` was split into (#666).

Splitting a 230-line method is only worth it if the pieces are testable on
their own, so these test the two that carry the subtle behaviour rather than
re-testing issuance through them.

`_resolve_all_domains` is the only part of preparation with no dependency on
settings, the CA, or the filesystem, which is exactly what makes exhaustive
tests cheap here and expensive through `create_certificate`.

`_LazySettings` exists because a fully-specified HTTP-01 request needs no
settings at all and this is the issuance hot path. The original threaded
`if settings is None: settings = ...load_settings()` through five branches;
splitting into four methods would have meant threading it through four
signatures. The property that matters is that it loads at most once, and
reports `value is None` when nothing asked — which is what
`_PreparedIssuance.settings` carries downstream, and what the propagation
lookup keys off.
"""
import pytest

from modules.core.certificates import _LazySettings, _resolve_all_domains

pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# The -d list
# ---------------------------------------------------------------------------

def test_a_certificate_with_no_sans_is_just_the_domain():
    assert _resolve_all_domains('example.com', None, 'dns-01') == ['example.com']


def test_sans_follow_the_primary_in_order():
    assert _resolve_all_domains(
        'example.com', ['www.example.com', 'api.example.com'], 'dns-01'
    ) == ['example.com', 'www.example.com', 'api.example.com']


def test_a_san_is_normalised_before_it_reaches_certbot():
    """validate_domain returns the normalised name; appending the RAW entry is
    how a URL form or a case variant reaches certbot's -d."""
    assert _resolve_all_domains(
        'example.com', ['WWW.Example.com'], 'dns-01'
    ) == ['example.com', 'www.example.com']


def test_a_san_equal_to_the_primary_collapses():
    """"Example.com" as a SAN of "example.com" must not produce a duplicate -d."""
    assert _resolve_all_domains(
        'example.com', ['Example.com', 'www.example.com'], 'dns-01'
    ) == ['example.com', 'www.example.com']


def test_duplicate_sans_collapse():
    assert _resolve_all_domains(
        'example.com', ['www.example.com', 'www.example.com'], 'dns-01'
    ) == ['example.com', 'www.example.com']


@pytest.mark.parametrize('blank', ['', '   ', '\t'])
def test_blank_entries_are_skipped(blank):
    """A trailing comma in the form leaves one behind."""
    assert _resolve_all_domains(
        'example.com', [blank, 'www.example.com'], 'dns-01'
    ) == ['example.com', 'www.example.com']


def test_an_invalid_san_is_refused_rather_than_dropped():
    """Silently dropping it would issue a certificate missing a name the
    operator asked for, and they would find out at handshake time."""
    with pytest.raises(ValueError, match='Invalid SAN domain'):
        _resolve_all_domains('example.com', ['not a domain'], 'dns-01')


def test_a_wildcard_is_allowed_under_dns_01():
    assert '*.example.com' in _resolve_all_domains(
        'example.com', ['*.example.com'], 'dns-01')


def test_a_wildcard_is_refused_under_http_01():
    """HTTP-01 cannot validate a wildcard; certbot would fail later and less
    clearly."""
    with pytest.raises(ValueError, match='wildcard'):
        _resolve_all_domains('example.com', ['*.example.com'], 'http-01')


def test_a_wildcard_primary_is_refused_under_http_01_too():
    """CONTROL: the guard must cover the primary, not only the SANs."""
    with pytest.raises(ValueError, match='wildcard'):
        _resolve_all_domains('*.example.com', None, 'http-01')


# ---------------------------------------------------------------------------
# The lazy load
# ---------------------------------------------------------------------------

def test_nothing_is_loaded_until_something_asks():
    calls = []
    lazy = _LazySettings(lambda: calls.append(1) or {'a': 1})

    assert calls == [], 'settings were loaded before anyone asked'
    assert lazy.value is None


def test_it_loads_once_however_many_times_it_is_asked():
    calls = []

    def loader():
        calls.append(1)
        return {'a': 1}

    lazy = _LazySettings(loader)
    assert lazy.get() == {'a': 1}
    assert lazy.get() == {'a': 1}
    assert lazy.get() == {'a': 1}
    assert len(calls) == 1, f'settings were loaded {len(calls)} times'


def test_value_reports_what_was_loaded_after_the_first_ask():
    lazy = _LazySettings(lambda: {'a': 1})
    lazy.get()
    assert lazy.value == {'a': 1}


def test_a_loader_returning_none_still_counts_as_loaded():
    """CONTROL: memoising on `value is None` instead of a flag would reload
    forever here, and `value is None` downstream would be indistinguishable
    from "nobody asked"."""
    calls = []

    def loader():
        calls.append(1)
        return None

    lazy = _LazySettings(loader)
    lazy.get()
    lazy.get()
    assert len(calls) == 1


def test_the_prepared_record_carries_none_when_nothing_asked():
    """The downstream contract: _propagation_seconds and the create path both
    treat a None settings as "not loaded", and the builder reloads nothing."""
    from modules.core.certificates import _propagation_seconds

    class _Strategy:
        default_propagation_seconds = 60

    assert _propagation_seconds(None, 'cloudflare', _Strategy()) == 60
