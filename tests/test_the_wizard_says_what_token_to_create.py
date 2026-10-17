"""The first-run wizard says what credential to create, and from what source.

Step 2 of the wizard asked for a provider's credentials and said nothing about
them: not which permissions a token needs, not where the guide is. A token with
the wrong permissions passed the wizard and failed at the first issuance, after
the propagation wait. It also offered Namecheap, which has no working plugin,
like any other provider, and told Scaleway users to `pip install` into an image
that has no pip.

Each provider now has a line on what to create, taken from the plugin's own
documentation or from docs/dns-providers.md, and a link to its section; a
provider with no such source gets the link only. The providers the default
image cannot use carry a notice that follows the Availability column of
docs/dns-providers.md. These tests hold the wizard to the backend's provider
list, to headings that exist, to a named source, to the plugins' own words,
and to that column.
"""
import re
from pathlib import Path

import pytest

from modules.core.dns_providers import DNSManager
from tests.test_provider_availability_is_truthful import TABLE_ROWS

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
WIZARD = (REPO / 'static' / 'js' / 'setup-wizard.js').read_text(encoding='utf-8')
DOCS = (REPO / 'docs' / 'dns-providers.md').read_text(encoding='utf-8')


def _block(name):
    start = WIZARD.index(f'var {name} = {{')
    return WIZARD[start:WIZARD.index('\n    };', start)]


def _entries(name):
    return dict(re.findall(r"^\s+'?([a-z0-9-]+)'?:\s+(\{.*\}|'.*')\s*,?\s*$", _block(name), re.M))


PROVIDERS = set(re.findall(r"^\s+'?([a-z0-9-]+)'?:\s+\{ label:", _block('PROVIDERS'), re.M))
GUIDES = {key: dict(re.findall(r"(\w+): '((?:[^'\\]|\\.)*)'", body)) for key, body in _entries('GUIDES').items()}
AVAILABILITY = {key: body.strip("'") for key, body in _entries('AVAILABILITY').items()}


def _slug(heading):
    text = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', heading).replace('`', '').strip().lower()
    return re.sub(r'\s', '-', re.sub(r'[^\w\s-]', '', text))


ANCHORS = {_slug(line.lstrip('#')) for line in DOCS.splitlines() if re.match(r'^#{1,6} ', line)}

# The plugins' own words, which the wizard's line must repeat: if a plugin
# changes what it asks for, this is where it shows.
PLUGIN_TERMS = {
    'cloudflare': ('certbot_dns_cloudflare', 'Zone:DNS:Edit'),
    'route53': ('certbot_dns_route53', 'route53:ChangeResourceRecordSets'),
    'digitalocean': ('certbot_dns_digitalocean', 'domain'),
    'ovh': ('certbot_dns_ovh', '/domain/zone/'),
    'google': ('certbot_dns_google', 'managed zone'),
}

# Availability column name -> wizard key, for the providers that are not Stable.
NAMES = {'Namecheap': 'namecheap', 'Hurricane Electric': 'he-ddns', 'Dynu': 'dynudns',
         'Scaleway': 'scaleway', 'PowerDNS': 'powerdns'}
NOTICE = {'Unavailable': 'No working certbot plugin',
          'Extended image': 'EXTRA_REQUIREMENTS=requirements-extended.txt',
          'Separate install': 'derived image'}


def test_the_blocks_are_being_read():
    """CONTROL: if the parsing breaks, every case below passes over nothing."""
    assert len(PROVIDERS) >= 25 and len(GUIDES) == len(PROVIDERS)
    assert sum(1 for g in GUIDES.values() if g.get('text')) >= 10
    assert len(AVAILABILITY) >= 4


def test_the_wizard_offers_every_provider_but_the_custom_script():
    supported = set(DNSManager.SUPPORTED_PROVIDERS) - {'custom-script'}
    assert PROVIDERS == supported, (sorted(supported - PROVIDERS), sorted(PROVIDERS - supported))


def test_every_provider_has_a_guide_entry():
    assert set(GUIDES) == PROVIDERS


@pytest.mark.parametrize('provider', sorted(PROVIDERS))
def test_every_link_lands_on_a_heading(provider):
    anchor = GUIDES[provider].get('docs', '')
    assert anchor.startswith('#') and anchor[1:] in ANCHORS, (provider, anchor)


@pytest.mark.parametrize('provider', sorted(PROVIDERS))
def test_a_line_names_its_source(provider):
    guide = GUIDES[provider]
    if not guide.get('text'):
        assert 'source' not in guide, f'{provider} names a source for no line'
        return
    source = guide.get('source', '')
    pinned = {re.split(r'[=<>!~\[;\s]', line.strip(), maxsplit=1)[0].lower()
              for path in REPO.glob('requirements*.txt')
              for line in path.read_text().splitlines()
              if line.strip() and not line.lstrip().startswith(('#', '-'))}
    assert source == 'docs' or source in pinned, (
        f'{provider}: the line must come from docs/dns-providers.md or from a plugin '
        f'this repository pins, and {source!r} is neither')


@pytest.mark.parametrize('provider', sorted(PLUGIN_TERMS))
def test_a_plugin_sourced_line_says_what_the_plugin_says(provider):
    module, term = PLUGIN_TERMS[provider]
    plugin = pytest.importorskip(module)
    assert term in (plugin.__doc__ or ''), f'{module} no longer says {term!r}: re-read it'
    assert term in GUIDES[provider]['text'], f'the wizard line for {provider} lost {term!r}'


def test_the_notices_follow_the_availability_column():
    not_stable = {name: status for name, status in TABLE_ROWS if status != 'Stable'}
    unknown = sorted(set(not_stable) - set(NAMES))
    assert not unknown, f'docs/dns-providers.md marks {unknown} as not Stable; add them to NAMES'
    assert {NAMES[n] for n in not_stable} == set(AVAILABILITY)
    for name, status in not_stable.items():
        assert NOTICE[status] in AVAILABILITY[NAMES[name]], (name, status)


def test_nothing_tells_the_reader_to_pip_install():
    """The image has no pip (#1267)."""
    assert 'pip install' not in WIZARD
