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


# --- the second home, found by the certmate-website session ---------------
#
# The file above was written about the GLOBAL setting, and it was right about
# it. The per-account `propagation_seconds` field had its own export, in
# dns_strategies, with no bound at all:
#
#     env['CERTMATE_DNS_PROPAGATION_SECONDS'] = str(propagation)
#
# Two strategies did it, and that variable is exactly what this project's own
# custom-script example sleeps on. So the clamp "so a typo cannot make an
# issuance hang" (#666) covered one of the two ways to set the number.

@pytest.mark.parametrize('value,expected', [
    (99999, 3600),          # 27 hours, holding the domain lock
    (-5, 1),                # `sleep -5` fails the hook under `set -eu`
    ('300', 300),           # a string of digits is still a number
    (300, 300),
    ('99999; rm -rf /', 120),   # not a number: the default, not the shell
    ('abc', 120),
    (None, 120),
])
def test_an_account_level_value_is_bounded(value, expected):
    from modules.core.dns_strategies import clamp_propagation_seconds

    assert clamp_propagation_seconds(value, 120) == expected


def test_the_account_path_exports_the_bounded_value():
    """THE regression, at the call site: the env var the hook reads."""
    from modules.core.dns_strategies import DNSStrategyFactory

    strategy = DNSStrategyFactory.get_strategy('custom-script')
    env = {}
    strategy.prepare_environment(env, {'propagation_seconds': 99999,
                                       'script': '/bin/true'})

    assert env['CERTMATE_DNS_PROPAGATION_SECONDS'] == '3600'


def test_no_strategy_exports_it_unbounded():
    """The two that did were found by reading; this is what finds a third.

    AST, not a regex: the first version of this matched to end-of-line and
    the fixed expression wraps, so it read `str(` and failed on correct code.
    """
    import ast
    import inspect

    from modules.core import dns_strategies

    tree = ast.parse(inspect.getsource(dns_strategies))
    exports = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == 'CERTMATE_DNS_PROPAGATION_SECONDS'):
                exports.append(ast.unparse(node.value))

    assert exports, 'nothing exports the variable — this test is reading nothing'
    for expression in exports:
        assert 'clamp_propagation_seconds' in expression, (
            f'exported without the clamp: {expression}'
        )


def test_the_global_path_shares_the_same_bound():
    """One home means one home: the global clamp is the shared helper now,
    not a second `max(1, min(3600, ...))` that happens to agree today."""
    import inspect

    from modules.core import certificates

    source = inspect.getsource(certificates._propagation_seconds)

    assert 'clamp_propagation_seconds' in source
    assert 'min(3600' not in source
