"""A domain entry has one shape, and normalising it changes nothing else.

`settings['domains']` accepted a bare string or an object, both spellings were
live, and nine modules decoded that union independently. Three separate
defects came out of it, and only the first is a tidiness problem.

**The union never ended.** The load-time migration converted only when EVERY
entry was a string, so the moment one object entry existed the list was frozen
mixed — which is the state of any instance that added a domain after the object
format arrived. And `save_settings` wrote a validated string entry straight
back as a string, so even a fully converted list could be un-converted by the
next save. Normalisation was not a fixed point.

**The normaliser that did run was not lossless.** `migrate_domains_format`
filled in `dns_provider` and `account_id` from the global defaults. Two of its
callers invoke it inside a settings mutator — `set_auto_renew` and the sweep's
re-registration — so those invented values were PERSISTED. An entry naming no
provider means "follow the global setting"; an entry naming one is pinned to
it. So an unrelated operation silently converted the first into the second, and
from then on changing the global DNS provider had no effect on any existing
domain. Measured before the fix, on a mixed list, after one unrelated write:

    global dns_provider set to route53
      a.example.com resolves to cloudflare
      b.example.com resolves to cloudflare

Nothing ever read the injected fields: the provider comes from
`get_domain_dns_provider`, the account from the certificate's own metadata.

**The flag one spelling cannot carry.** A string entry has nowhere to put
`auto_renew`, so it reads as True. That stays true after normalisation only
because `{'domain': x}` is read as True as well — which is the property the
losslessness tests below pin.
"""
import json

import pytest

from modules.core.domain_entries import (
    entry_auto_renew, entry_domain, iter_domains, normalize_domains,
    normalize_entry,
)
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager(tmp_path):
    """A real SettingsManager over a real file — the boundary under test."""
    for name in ('certificates', 'data', 'backups', 'logs'):
        (tmp_path / name).mkdir()
    file_ops = FileOperations(cert_dir=tmp_path / 'certificates',
                              data_dir=tmp_path / 'data',
                              backup_dir=tmp_path / 'backups',
                              logs_dir=tmp_path / 'logs')
    settings_file = tmp_path / 'data' / 'settings.json'
    return SettingsManager(file_ops, settings_file), settings_file


def _write(settings_file, domains, provider='cloudflare'):
    settings_file.write_text(json.dumps({
        'domains': domains, 'dns_provider': provider, 'auto_renew': True,
    }), encoding='utf-8')


# --- THE regression: normalising must not pin a provider -----------------

def test_an_unrelated_write_does_not_pin_the_global_provider(manager):
    """The defect, end to end. Before the fix both domains resolved to
    cloudflare after this sequence, because the normaliser had written the
    global provider of that moment into every entry."""
    sm, settings_file = manager
    _write(settings_file, ['a.example.com', {'domain': 'b.example.com'}])

    # Any operation that normalises inside a settings mutator.
    sm.update(lambda s: sm.migrate_domains_format(s), reason='unrelated')
    # The operator then changes the global provider, as the settings UI does.
    sm.update(lambda s: s.__setitem__('dns_provider', 'route53'),
              reason='global change')

    settings = sm.load_settings()
    assert sm.get_domain_dns_provider('a.example.com', settings) == 'route53'
    assert sm.get_domain_dns_provider('b.example.com', settings) == 'route53'


def test_normalising_does_not_invent_fields(manager):
    """The same property at the unit level: what is written back is the entry,
    not the entry plus the defaults of the moment."""
    sm, settings_file = manager
    _write(settings_file, ['a.example.com'])

    sm.update(lambda s: sm.migrate_domains_format(s), reason='unrelated')

    stored = json.loads(settings_file.read_text(encoding='utf-8'))['domains']
    assert stored == [{'domain': 'a.example.com'}]


def test_a_pinned_provider_survives_normalising(manager):
    """CONTROL for the finding above: an entry that DOES name a provider is
    stating a per-domain override, and normalising must not drop it."""
    sm, settings_file = manager
    _write(settings_file, [{'domain': 'pinned.example.com',
                            'dns_provider': 'route53'}])

    sm.update(lambda s: s.__setitem__('dns_provider', 'digitalocean'),
              reason='global change')

    settings = sm.load_settings()
    assert sm.get_domain_dns_provider('pinned.example.com', settings) == 'route53'


# --- normalisation is a fixed point --------------------------------------

def test_a_mixed_list_is_normalised(manager):
    """The old migration converted only when every entry was a string, so a
    mixed list -- which is what any instance that added a domain after the
    object format has -- stayed mixed forever."""
    sm, settings_file = manager
    _write(settings_file, ['a.example.com', {'domain': 'b.example.com'},
                           'c.example.com'])

    settings = sm.load_settings()

    assert settings['domains'] == [{'domain': 'a.example.com'},
                                   {'domain': 'b.example.com'},
                                   {'domain': 'c.example.com'}]


def test_saving_does_not_undo_the_normalisation(manager):
    """The other half of the fixed point. save_settings used to write a
    validated string entry back as a string, so the union could reappear on
    any save after a clean load."""
    sm, settings_file = manager
    _write(settings_file, ['a.example.com'])

    sm.save_settings({'domains': ['a.example.com'], 'dns_provider': 'cloudflare'})

    stored = json.loads(settings_file.read_text(encoding='utf-8'))['domains']
    assert stored == [{'domain': 'a.example.com'}]


def test_load_save_load_is_stable(manager):
    """A round trip through the boundary must reach a fixed point, not
    oscillate: this is what makes the object form retirable."""
    sm, settings_file = manager
    _write(settings_file, ['a.example.com', {'domain': 'b.example.com',
                                             'auto_renew': False}])

    first = sm.load_settings()
    sm.save_settings(first)
    second = sm.load_settings()
    sm.save_settings(second)
    third = sm.load_settings()

    assert first['domains'] == second['domains'] == third['domains']
    # And the fixed point is the OBJECT form. Without this the assertion above
    # is satisfied by the old behaviour too, which was stable at the mixed
    # shape: stability alone was never the problem.
    assert third['domains'] == [{'domain': 'a.example.com'},
                                {'domain': 'b.example.com', 'auto_renew': False}]


@pytest.mark.parametrize('raw', [
    'a.example.com',
    {'domain': 'a.example.com'},
    {'domain': 'a.example.com', 'auto_renew': False},
    {'domain': 'a.example.com', 'dns_provider': 'route53', 'account_id': 'x'},
])
def test_normalising_is_idempotent(raw):
    once = normalize_entry(raw)
    assert normalize_entry(once) == once


# --- what the two spellings mean, before and after -----------------------

@pytest.mark.parametrize('raw,expected', [
    ('a.example.com', True),
    ({'domain': 'a.example.com'}, True),
    ({'domain': 'a.example.com', 'auto_renew': True}, True),
    ({'domain': 'a.example.com', 'auto_renew': False}, False),
])
def test_auto_renew_survives_normalisation(raw, expected):
    """The property that makes the conversion safe: a string and
    {'domain': x} are read identically, so turning one into the other cannot
    change whether a certificate renews."""
    assert entry_auto_renew(raw) is expected
    assert entry_auto_renew(normalize_entry(raw)) is expected


@pytest.mark.parametrize('raw,expected', [
    ('a.example.com', 'a.example.com'),
    ({'domain': 'a.example.com'}, 'a.example.com'),
    ('', None),
    ({}, None),
    ({'domain': ''}, None),
    ({'domain': None}, None),
    ({'nope': 'a.example.com'}, None),
    (42, None),
    (None, None),
    ([], None),
])
def test_what_counts_as_naming_a_domain(raw, expected):
    assert entry_domain(raw) == expected


def test_a_malformed_entry_is_dropped_and_counted_and_the_rest_survive():
    """One bad element must not make the certificate list unreachable, and the
    caller needs a number it can report rather than an exception."""
    entries, dropped = normalize_domains(
        ['a.example.com', 42, {'domain': 'b.example.com'}, {'nope': 1}, None])

    assert entries == [{'domain': 'a.example.com'}, {'domain': 'b.example.com'}]
    assert dropped == 3


def test_a_malformed_entry_does_not_hide_the_others_at_the_boundary(manager):
    """The same property through the real load path."""
    sm, settings_file = manager
    _write(settings_file, ['a.example.com', 42, {'domain': 'b.example.com'}])

    settings = sm.load_settings()

    assert [e['domain'] for e in settings['domains']] == ['a.example.com',
                                                          'b.example.com']


# --- one decoder ---------------------------------------------------------

def test_nothing_else_decodes_the_union():
    """The guard that keeps this fixed. Nine modules each had their own
    version of 'a string or an object', with three different answers for a
    third shape; the value of consolidating is lost the moment a tenth is
    written."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent / 'modules'
    pattern = re.compile(
        r"get\('domain'\)\s+if\s+isinstance|isinstance\(entry,\s*str\)"
        r"|isinstance\(domain_entry,\s*(?:str|dict)\)")

    offenders = []
    for path in sorted(root.rglob('*.py')):
        if path.name == 'domain_entries.py':
            continue
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if pattern.search(line):
                offenders.append(f'{path.relative_to(root.parent)}:{number}: {line.strip()}')

    # auth.py validates API-key allowed_domains, which is a list of patterns
    # rather than domain entries -- a different structure with a different rule.
    offenders = [o for o in offenders if 'core/auth.py' not in o]

    assert not offenders, (
        'these decode the domain-entry union outside modules/core/'
        'domain_entries.py:\n  ' + '\n  '.join(offenders))


def test_the_canonical_reader_is_what_inventory_uses():
    """collect_domain_sources is the one answer to 'which certificates exist',
    so it must read entries the same way everything else does."""
    import inspect

    from modules.core import inventory_sources

    assert 'iter_domains' in inspect.getsource(inventory_sources._settings_domains)


# --- the shape older builds already read ---------------------------------

def test_the_normalised_shape_is_the_one_older_builds_expect(manager):
    """Downgrade safety. The object form is not new -- it is the format every
    build since the multi-account change has written -- so normalising cannot
    strand a rollback. What would have been unsafe is inventing a field, which
    is exactly what the previous normaliser did."""
    sm, settings_file = manager
    _write(settings_file, ['a.example.com'])

    settings = sm.load_settings()

    assert all(isinstance(entry, dict) and 'domain' in entry
               for entry in settings['domains'])
    assert all(set(entry) <= {'domain'} for entry in settings['domains']), (
        'normalisation added a field an older build would have to understand')


def test_iter_domains_reads_an_un_normalised_dict_too():
    """Settings assembled in a test, or handed over by a restore, have not
    been through the boundary. The readers must still cope."""
    assert list(iter_domains({'domains': ['a.example.com',
                                          {'domain': 'b.example.com',
                                           'auto_renew': False}]})) == [
        ('a.example.com', True), ('b.example.com', False)]
