"""A request for a CA this instance cannot use is refused, not substituted.

Item 2 of #876. When the requested CA's configuration or account could not be
loaded, issuance reset the provider to Let's Encrypt, logged a warning, and
answered 201. A request for DigiCert came back as a Let's Encrypt certificate.

Measured before the fix, asking each provider with nothing configured:

    digicert   -> issued with 'letsencrypt'
    zerossl    -> issued with 'letsencrypt'
    google     -> issued with 'letsencrypt'
    sslcom     -> issued with 'letsencrypt'
    actalis    -> issued with 'letsencrypt'
    private_ca -> issued with 'letsencrypt'
    sectigo    -> refused

Six of seven. Sectigo refused only because it arrived after the fallback and
carved itself out (#884); that carve-out is gone, subsumed by the rule.

**`private_ca` is the case that settles it.** An operator asking their internal
CA for an internal name and receiving a publicly-trusted certificate has had
that name published — a public certificate exists for it, in the CT logs, for
its lifetime. A log warning does not undo that.

The one CA that may still proceed without saved configuration is Let's
Encrypt, because certbot's defaults *are* its configuration. Both entries:
production and staging. Keeping the staging entry distinct matters as much as
refusing the rest — silently promoting a staging request to production is the
same class of defect pointing the other way, and it is what
`tests/test_staging_as_ca.py` has guarded since #279.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.ca_manager import CAManager
from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def resolver():
    """A CertificateManager reduced to the one decision under test: nothing
    else in issuance is reached, and nothing else needs to exist for it."""
    manager = CertificateManager.__new__(CertificateManager)
    manager.ca_manager = CAManager(settings_manager=MagicMock())
    return manager


@pytest.fixture
def settings():
    unconfigured = MagicMock()
    unconfigured.get.return_value = {'default_ca': 'letsencrypt'}
    return unconfigured


def _needs_configuration(resolver):
    """Every CA in the registry except the two Let's Encrypt entries.

    Derived rather than listed: a CA added later is covered by these tests on
    the day it is added, which is the day the fallback would otherwise have
    quietly applied to it.
    """
    return [key for key in resolver.ca_manager.ca_providers
            if key not in ('letsencrypt', 'letsencrypt_staging')]


def test_there_are_providers_to_test(resolver):
    """Guard the guard: an empty list would make the refusal tests vacuous."""
    assert len(_needs_configuration(resolver)) >= 5


def test_every_unconfigured_ca_is_refused(resolver, settings):
    for provider in _needs_configuration(resolver):
        with pytest.raises(ValueError) as refusal:
            resolver._resolve_ca(settings, provider, None, False)
        assert provider in str(refusal.value), (
            f'the refusal for {provider} does not name it, so an operator '
            f'cannot tell which CA they need to configure'
        )


def test_the_refusal_says_what_to_do(resolver, settings):
    with pytest.raises(ValueError) as refusal:
        resolver._resolve_ca(settings, 'digicert', None, False)
    message = str(refusal.value).lower()
    assert 'not configured' in message
    assert 'settings' in message


def test_a_private_ca_request_never_becomes_a_public_certificate(resolver, settings):
    """Named on its own because it is the harm that is not recoverable. The
    others issue from the wrong CA; this one publishes a name."""
    with pytest.raises(ValueError):
        resolver._resolve_ca(settings, 'private_ca', None, False)


@pytest.mark.parametrize('requested', ['letsencrypt', 'letsencrypt_staging'])
def test_lets_encrypt_still_proceeds_without_saved_configuration(
        resolver, settings, requested):
    """The exception, and it is not an oversight: certbot's defaults are the
    configuration. A fix that refused here would break the common case — a
    fresh instance issuing its first certificate."""
    provider, _, config, account = resolver._resolve_ca(
        settings, requested, None, False)
    assert provider == requested
    assert config is None and account is None


def test_a_staging_request_is_not_promoted_to_production(resolver, settings):
    """The staging entry stays the staging entry. The old fallback took care
    over this for the providers it substituted; the rule that replaced it has
    to keep it for the one provider it still lets through."""
    provider, staging, _, _ = resolver._resolve_ca(
        settings, 'letsencrypt_staging', None, False)
    assert provider == 'letsencrypt_staging'
    assert staging is True


def test_a_legacy_staging_flag_still_maps_onto_the_staging_entry(resolver, settings):
    """`staging=True` with the plain letsencrypt provider is the pre-#279
    spelling and must land on the staging CA, not on production."""
    provider, staging, _, _ = resolver._resolve_ca(
        settings, 'letsencrypt', None, True)
    assert provider == 'letsencrypt_staging'
    assert staging is True


def test_nothing_is_left_that_silently_substitutes_a_ca():
    """The fallback assigned to `ca_provider` inside the failure handler. Read
    from the source because a future edit could reintroduce it in a form the
    behaviour tests above would not reach — they cover the registry as it is
    today, and the harm is about a provider nobody remembered to check."""
    import inspect

    source = inspect.getsource(CertificateManager._resolve_ca)
    handler = source[source.index('except Exception'):]
    assert "ca_provider = 'letsencrypt" not in handler, (
        'the CA is reassigned while handling a failure to load its config; '
        'that is the substitution #876 item 2 is about'
    )
