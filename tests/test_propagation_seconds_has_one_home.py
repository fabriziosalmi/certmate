"""Create and renew must agree on the DNS propagation wait (#666).

The formula existed **four** times — once in `create_certificate`, three times
in `renew_certificate` (the alias branch, the acme-dns alias branch, and
`custom-script`). One of them carried a comment reading "Mirror the create
path": a copy that announces it is a copy is exactly the drift this issue is
about.

All four clamped to 1..3600, but not in the same place: three clamped where
the value was computed, the acme-dns alias branch clamped at the call site. I
first read that as one copy having drifted into not clamping at all, and said
so in #736 — wrongly. The clamp was there, four lines further down. Unifying
them changes no behaviour; what it removes is four chances for the next edit
to move one of those clamps and not the others.

There is one `_propagation_seconds` now. These pin what it must do, because the
bounds are the interesting part: too small and certbot asks the CA to validate
before the TXT record is visible, too large and a wedged issuance holds a
per-domain lock for hours.

A note on what did NOT change. `certbot renew` replays the flags stored in
`renewal/<domain>.conf`, so the renew path deliberately does not re-emit
`--{plugin}-propagation-seconds` the way create does; it only exports the value
to the hooks for `custom-script`. That asymmetry is real — an operator who
raises the setting after issuance keeps the old value until the next create or
reissue — but it is behaviour, not duplication, and changing it is not a
refactor. Recorded here so the next reader does not "fix" it by accident.
"""
import pytest

from modules.core.certificates import _propagation_seconds

pytestmark = [pytest.mark.unit]


class _Strategy:
    def __init__(self, default=60):
        self.default_propagation_seconds = default


def test_a_configured_value_is_used():
    settings = {'dns_propagation_seconds': {'cloudflare': 30}}
    assert _propagation_seconds(settings, 'cloudflare', _Strategy()) == 30


def test_an_unconfigured_provider_falls_back_to_the_strategy_default():
    settings = {'dns_propagation_seconds': {'cloudflare': 30}}
    assert _propagation_seconds(settings, 'route53', _Strategy(45)) == 45


@pytest.mark.parametrize('settings', [
    {},
    {'dns_propagation_seconds': None},
    {'dns_propagation_seconds': {}},
    None,
])
def test_a_missing_map_falls_back_rather_than_raising(settings):
    """`None` covers the create path's lazy load returning nothing."""
    assert _propagation_seconds(settings, 'cloudflare', _Strategy(60)) == 60


@pytest.mark.parametrize('value', ['abc', None, [], {'a': 1}])
def test_an_unparseable_value_falls_back(value):
    """A typo in settings.json must not take issuance down."""
    settings = {'dns_propagation_seconds': {'cloudflare': value}}
    assert _propagation_seconds(settings, 'cloudflare', _Strategy(60)) == 60


@pytest.mark.parametrize('configured,expected', [
    (0, 1),          # zero would ask the CA to validate immediately
    (-5, 1),
    (3600, 3600),
    (86400, 3600),   # a day would hold the per-domain lock all day
    (1, 1),
])
def test_the_value_is_clamped_to_one_second_and_one_hour(configured, expected):
    settings = {'dns_propagation_seconds': {'cloudflare': configured}}
    assert _propagation_seconds(settings, 'cloudflare', _Strategy()) == expected


def test_a_string_that_is_a_number_is_accepted():
    """settings.json is hand-edited often enough that "30" happens."""
    settings = {'dns_propagation_seconds': {'cloudflare': '30'}}
    assert _propagation_seconds(settings, 'cloudflare', _Strategy()) == 30


def test_neither_path_computes_it_inline_any_more():
    """The point of the extraction, asserted on the source.

    Both call sites reading the same settings key with their own arithmetic is
    exactly how they drifted; if a third appears, or one reverts, this says so.
    """
    import inspect
    import re

    from modules.core.certificates import CertificateManager

    # Matches the READ, not the word: the first version of this asserted the
    # bare name was absent and tripped on a comment that merely mentions it.
    pattern = re.compile(r"""\.get\(\s*['"]dns_propagation_seconds['"]""")

    for method in (CertificateManager.create_certificate,
                   CertificateManager.renew_certificate,
                   CertificateManager._build_issuance_command):
        src = inspect.getsource(method)
        assert not pattern.search(src), (
            f'{method.__qualname__} reads the propagation setting directly '
            f'again; it belongs to _propagation_seconds'
        )
