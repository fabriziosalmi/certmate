"""An ACME directory is fetched over https, wherever its URL came from.

`test_ca_endpoints_are_live.py::test_every_ca_url_is_https` holds every
built-in CA to this. It reads the *registry* — `ca_providers[key]['production_url']`
and `['staging_url']` — and a provider whose URL is the string `"custom"` is
skipped, because there is nothing to check yet.

That is the whole gap. `private_ca` carries `"custom"`, so its real directory
URL arrives later, per account, through `validate_ca_configuration` — which
accepted `http://` as readily as `https://`. The rule the gate exists to
enforce applied to the URLs CertMate ships and not to the ones an operator
supplies, which are the only ones `private_ca` ever uses.

A directory fetched over plain HTTP is not merely eavesdropped. It is the
document that says where to register, where to place orders and where to
finalise them; anything on the path can rewrite it. Binding an account key to
a directory obtained that way is not a weaker version of ACME, it is a
different protocol with the same shape.

So the check moved to where the URL is, rather than where it happens to be
declared.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.ca_manager import CAManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager():
    return CAManager(settings_manager=MagicMock())


def _validate(manager, url, provider='private_ca'):
    return manager.validate_ca_configuration(
        provider, {'acme_url': url, 'email': 'ops@example.com',
                   'eab_kid': 'k', 'eab_hmac_key': 'h'})


def test_an_account_configured_directory_must_be_https(manager):
    ok, error = _validate(manager, 'http://acme.internal/directory')
    assert ok is False
    assert 'https' in error.lower()


def test_https_is_accepted(manager):
    ok, _ = _validate(manager, 'https://acme.internal/directory')
    assert ok is True


@pytest.mark.parametrize('url', [
    'HTTP://acme.internal/directory',
    'HtTp://acme.internal/directory',
    'http://acme.internal:8080/directory',
    'http://127.0.0.1/directory',
])
def test_the_refusal_does_not_depend_on_how_it_is_written(manager, url):
    """Case, port and loopback are all still plain HTTP. RFC 3986 makes the
    scheme case-insensitive, so `HTTP://` is not a different thing; loopback
    especially looks safe and is the shape a proxy in front of it would take.

    The url is passed exactly as written — an earlier version of this test
    lower-cased it first, which is how a test comes to assert the name it was
    given rather than the thing it was named for."""
    ok, error = _validate(manager, url)
    assert ok is False
    assert 'https' in error.lower(), (
        f'{url!r} was refused as malformed rather than as plain HTTP, which '
        f'tells the operator the wrong thing to fix'
    )


@pytest.mark.parametrize('url', ['ftp://acme.internal/d', 'acme.internal/d',
                                 'ws://acme.internal/d', '//acme.internal/d'])
def test_anything_that_is_not_a_url_is_still_refused(manager, url):
    ok, error = _validate(manager, url)
    assert ok is False
    assert error


def test_a_missing_url_is_reported_as_missing_not_as_malformed(manager):
    """An operator who left the field empty should be told that, rather than
    being told their empty string is not https."""
    ok, error = _validate(manager, '')
    assert ok is False
    assert 'requires' in error.lower()


def test_the_error_says_what_to_do_rather_than_only_what_is_wrong(manager):
    _, error = _validate(manager, 'http://acme.internal/directory')
    assert 'must use https' in error.lower()


# --------------------------------------------------------------------------- #
# The same rule for every provider that configures its own directory
# --------------------------------------------------------------------------- #

def _providers_with_their_own_directory(manager):
    """Every CA whose directory comes from the account, not the registry."""
    return [key for key, info in manager.ca_providers.items()
            if key == 'private_ca' or info.get('requires_acme_url')]


def test_more_than_one_provider_configures_its_own_directory(manager):
    """Guard the guard: with only `private_ca` in this set the two tests
    below would say nothing about the rule being shared."""
    assert len(_providers_with_their_own_directory(manager)) >= 2


def test_an_uppercase_scheme_is_accepted_wherever_a_directory_is_configured(manager):
    """`HTTPS://` is https. RFC 3986 makes the scheme case-insensitive, and
    refusing it tells an operator to use HTTPS while they are using it.

    This was true for `private_ca` and false for every other provider with
    its own directory: those compared with `startswith('https://')`. The
    divergence appeared when the private-CA branch was improved and the
    others were left behind, so it is checked here across the whole set
    rather than on the one provider that happened to be right.
    """
    for provider in _providers_with_their_own_directory(manager):
        ok, error = _validate(manager, 'HTTPS://acme.internal/directory',
                              provider=provider)
        assert ok is True, f'{provider} refused an uppercase https scheme: {error}'


def test_plain_http_is_refused_wherever_a_directory_is_configured(manager):
    """The other direction of the same rule, across the same set."""
    for provider in _providers_with_their_own_directory(manager):
        ok, error = _validate(manager, 'HTTP://acme.internal/directory',
                              provider=provider)
        assert ok is False, f'{provider} accepted plain HTTP'
        assert 'must use https' in error.lower(), (
            f'{provider} refused it without saying what to fix: {error}')


# --------------------------------------------------------------------------- #
# The registry gate and this one cover the whole surface between them
# --------------------------------------------------------------------------- #

def test_every_registry_url_is_either_https_or_deferred(manager):
    """Restates the neighbouring gate's rule here so the two are read
    together: a built-in CA either ships an https directory or declares
    `custom`, and `custom` is exactly the case this file covers."""
    for key, config in manager.ca_providers.items():
        for field in ('production_url', 'staging_url'):
            url = config.get(field)
            if not url:
                continue
            assert url == 'custom' or url.startswith('https://'), (
                f'{key}.{field} is {url!r}: a built-in CA directory must be '
                f'https, or "custom" when the operator supplies it'
            )


def test_a_provider_that_defers_its_url_really_does_ask_for_one(manager):
    """A provider declaring `custom` and then never validating what arrives
    would have the gap this file closes, in a new place."""
    deferred = [k for k, c in manager.ca_providers.items()
                if c.get('production_url') == 'custom']
    assert deferred, 'no provider defers its directory URL; this file is vacuous'
    for key in deferred:
        ok, error = manager.validate_ca_configuration(
            key, {'email': 'ops@example.com'})
        assert ok is False, f'{key} accepted a configuration with no acme_url'
        assert error
