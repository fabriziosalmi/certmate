"""If the settings form asks for an ACME directory, issuance uses it.

Item 1 of #876. `ca_manager.py` contained both halves of the contradiction,
about a hundred lines apart. The DigiCert registry entry:

    It is REGIONAL: an account outside the default region has its own
    directory URL, shown in CertCentral. Operators override it per
    certificate via `acme_url`; this is the default, not the only value.

and `get_acme_server_url`:

    Other public CAs retain their pinned directory, even if an account
    contains an acme_url (as with the existing DigiCert settings form).

The code implemented the second. The settings form collected the field and the
connection test required it, so a DigiCert customer outside the default region
filled it in, saw the test pass, and had every certificate issued against the
default region's endpoint.

The rule this pins is the one the UI already states: **a CA whose settings form
collects an ACME Directory URL honours it.** Measured against the template
rather than a list here, so a field added to a new provider's form is covered
on the day it is added — and a provider that pins its directory is not
required to grow a field it does not want.

Three kinds of provider now, declared in the registry:

* *requires* — the directory only exists in the account (`private_ca`,
  `requires_acme_url`). No pinned URL, so a missing one is an error.
* *accepts* — a pinned default the account may override
  (`accepts_account_directory`). DigiCert, because its mPKI directory is
  regional.
* *pinned* — one public directory. ZeroSSL, Google, SSL.com, Actalis, whose
  forms collect no URL.
"""
import pathlib
import re
from unittest.mock import MagicMock

import pytest

from modules.core.ca_manager import CAManager

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
CA_FORM = REPO / 'templates' / 'partials' / 'settings_ca.html'
REGIONAL = 'https://eu.one.digicert.com/mpki/api/v1/acme/v2/directory'


@pytest.fixture
def manager():
    return CAManager(settings_manager=MagicMock())


def _providers_whose_form_asks_for_a_directory():
    """Every CA with an `<id>-acme-url` input in the settings form.

    Read from the template because that is the promise an operator sees: a
    field they are asked to fill in, next to a Test button that checks it.
    """
    html = CA_FORM.read_text(encoding='utf-8')
    found = set(re.findall(r'id="([a-z0-9_-]+)-acme-url"', html))
    # The form spells provider ids with hyphens; the registry uses
    # underscores.
    return {name.replace('-', '_') for name in found}


def test_the_form_still_asks_somebody_for_a_directory():
    """Guard the guard: an empty set would make the rule below vacuous, and
    the selector is matched against markup that could be restructured."""
    asked = _providers_whose_form_asks_for_a_directory()
    assert len(asked) >= 3, asked


def test_every_provider_in_the_form_is_a_provider(manager):
    """A field for a CA the registry does not have would mean the template
    and the registry had drifted, and the rule below would pass over it."""
    unknown = _providers_whose_form_asks_for_a_directory() - set(manager.ca_providers)
    assert not unknown, unknown


def test_a_directory_the_form_collects_is_the_one_used(manager):
    """The rule. DigiCert failed it; the other two already passed."""
    for provider in sorted(_providers_whose_form_asks_for_a_directory()):
        used = manager.get_acme_server_url(
            provider, account_config={'acme_url': REGIONAL})
        assert used == REGIONAL, (
            f"the settings form asks for {provider}'s ACME Directory URL and "
            f"issuance used {used!r} instead"
        )


def test_a_provider_that_pins_its_directory_ignores_a_stray_one(manager):
    """The other direction, and it is not symmetry for its own sake. These
    CAs have one public directory; honouring whatever turned up in an account
    would let a settings file point a "ZeroSSL" request anywhere while the
    certificate's metadata still said zerossl."""
    asked = _providers_whose_form_asks_for_a_directory()
    pinned = [key for key, info in manager.ca_providers.items()
              if key not in asked and info.get('production_url') != 'custom']
    assert pinned, 'no provider pins its directory; this test is vacuous'
    for provider in pinned:
        used = manager.get_acme_server_url(
            provider, account_config={'acme_url': REGIONAL})
        assert used == manager.ca_providers[provider]['production_url'], provider


def test_the_pinned_url_is_still_the_default(manager):
    """An account that configures nothing keeps working. The override is an
    override, not a requirement — that distinction is the whole of DigiCert's
    entry being *accepts* rather than *requires*."""
    used = manager.get_acme_server_url('digicert', account_config={})
    assert used == manager.ca_providers['digicert']['production_url']


def test_an_overridden_directory_is_still_held_to_https(manager):
    """The override must not be a way around the rule that an ACME directory
    is fetched over https."""
    with pytest.raises(ValueError, match='(?i)must use https'):
        manager.get_acme_server_url(
            'digicert', account_config={'acme_url': 'http://one.digicert.com/d'})


def test_a_provider_with_no_directory_anywhere_still_says_so(manager):
    """`private_ca` has no pinned URL to fall back to, so silence is an error
    rather than a default. The rewrite that made DigiCert's override work had
    to keep that distinction."""
    with pytest.raises(ValueError, match='(?i)not configured'):
        manager.get_acme_server_url('private_ca', account_config={})


def test_the_registry_declares_the_override_rather_than_the_code_guessing():
    """A provider is *accepts* because its entry says so. Special-casing
    DigiCert by name in `get_acme_server_url` would put the fact in the one
    place nobody reads when adding the next regional CA."""
    import inspect

    source = inspect.getsource(CAManager.get_acme_server_url)
    assert 'accepts_account_directory' in source
    assert "'digicert'" not in source, (
        'the provider is named in the resolution code; declare it in the '
        'registry instead'
    )
