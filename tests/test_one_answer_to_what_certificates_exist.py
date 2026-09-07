"""One implementation of "what certificates exist" (#670).

Three things describe the inventory and none is authoritative: `settings.json`'s
`domains` list, the directories under the certificate root, and certbot's
`live/` lineage. Choosing an authority is a larger change; this is the
prerequisite — the question has one implementation, and a domain's provenance
survives the answer instead of being unioned away.

Two endpoints rebuilt that union inline: the certificate list and the discovery
scan. Same loop, same tolerance for a domain entry being a string or a dict,
and only one of them collected `auto_renew`. Both iterated a *set*, so two
callers listing the same certificates could disagree about the order.

The tests that matter are the provenance ones. A domain in settings with no
directory and a domain on disk with no settings entry are different situations
with different remedies, and the old code made them indistinguishable.
"""

import pytest

from modules.core.inventory_sources import (
    auto_renew_for,
    collect_domain_sources,
)

pytestmark = [pytest.mark.unit]


def _cert_dir(tmp_path, *domains):
    for domain in domains:
        d = tmp_path / domain
        d.mkdir(parents=True)
        (d / 'cert.pem').write_text('x')
    return tmp_path


def test_a_domain_in_both_sources_reports_both(tmp_path):
    sources = collect_domain_sources(
        {'domains': [{'domain': 'example.com'}]},
        _cert_dir(tmp_path, 'example.com'))

    s = sources['example.com']
    assert s.in_settings and s.on_disk
    assert not s.only_in_settings and not s.only_on_disk


def test_registered_but_never_issued_is_distinguishable(tmp_path):
    """A certificate that was never issued, or a data volume that is not
    mounted. Reporting it identically to a healthy one is what the union did."""
    sources = collect_domain_sources(
        {'domains': ['example.com']}, _cert_dir(tmp_path))

    assert sources['example.com'].only_in_settings


def test_issued_but_not_registered_is_distinguishable(tmp_path):
    """The restore that brought certificates without settings.json — the shape
    the boot-time warning in settings.py already reports."""
    sources = collect_domain_sources({}, _cert_dir(tmp_path, 'example.com'))

    assert sources['example.com'].only_on_disk


def test_both_entry_spellings_are_accepted(tmp_path):
    """Strings and dicts are both in the wild, and this is not the place to
    migrate them."""
    sources = collect_domain_sources(
        {'domains': ['a.example.com', {'domain': 'b.example.com'}]},
        _cert_dir(tmp_path))

    assert set(sources) == {'a.example.com', 'b.example.com'}


@pytest.mark.parametrize('entry', [None, 42, [], {}, {'domain': ''}, ''])
def test_a_malformed_entry_is_skipped_not_fatal(tmp_path, entry):
    """One bad entry must not make the certificate list unreachable."""
    sources = collect_domain_sources(
        {'domains': [entry, 'good.example.com']}, _cert_dir(tmp_path))

    assert set(sources) == {'good.example.com'}


def test_auto_renew_defaults_to_true_and_is_read_when_present(tmp_path):
    sources = collect_domain_sources({'domains': [
        {'domain': 'on.example.com'},
        {'domain': 'off.example.com', 'auto_renew': False},
        'plain.example.com',
    ]}, _cert_dir(tmp_path))

    assert sources['on.example.com'].auto_renew is True
    assert sources['off.example.com'].auto_renew is False
    assert sources['plain.example.com'].auto_renew is True


def test_a_disk_only_domain_defaults_to_auto_renew(tmp_path):
    """Matching what the certificate list did before the move — a domain found
    only on disk was listed with auto_renew True."""
    sources = collect_domain_sources({}, _cert_dir(tmp_path, 'example.com'))
    assert sources['example.com'].auto_renew is True


def test_settings_auto_renew_survives_the_domain_also_being_on_disk(tmp_path):
    """CONTROL: the disk pass runs second, and must not overwrite the flag the
    settings pass read. Getting this wrong silently re-enables renewal for a
    certificate an operator deliberately turned off."""
    sources = collect_domain_sources(
        {'domains': [{'domain': 'example.com', 'auto_renew': False}]},
        _cert_dir(tmp_path, 'example.com'))

    assert sources['example.com'].auto_renew is False


def test_the_order_is_stable(tmp_path):
    """Both call sites iterated a set, so two listings of the same certificates
    could come back in different orders."""
    settings = {'domains': ['c.example.com', 'a.example.com']}
    cert_dir = _cert_dir(tmp_path, 'b.example.com')

    first = list(collect_domain_sources(settings, cert_dir))
    second = list(collect_domain_sources(settings, cert_dir))

    assert first == second == ['a.example.com', 'b.example.com', 'c.example.com']


def test_filesystem_artifacts_are_not_certificates(tmp_path):
    """`lost+found` on an ext volume, hidden directories, and any subdirectory
    without a cert.pem. They surfaced as ghost "Not Found" rows (#99)."""
    (tmp_path / 'lost+found').mkdir()
    (tmp_path / '.cache').mkdir()
    (tmp_path / 'config').mkdir()
    _cert_dir(tmp_path, 'example.com')

    assert set(collect_domain_sources({}, tmp_path)) == {'example.com'}


def test_neither_endpoint_rebuilds_the_union_itself():
    """The guard. Two inline copies is how they came to disagree about
    auto_renew and about ordering."""
    import inspect
    import re

    from modules.api import resources_certificates, resources_discovery

    for module in (resources_certificates, resources_discovery):
        src = inspect.getsource(module)
        assert not re.search(r"for\s+\w+\s+in\s+settings\.get\(\s*['\"]domains", src), (
            f'{module.__name__} walks settings["domains"] itself again'
        )


# ---------------------------------------------------------------------------
# The single-certificate answer
# ---------------------------------------------------------------------------

def test_auto_renew_for_reads_the_dict_spelling():
    settings = {'domains': [{'domain': 'example.com', 'auto_renew': False}]}
    assert auto_renew_for(settings, 'example.com') is False


def test_auto_renew_for_reads_the_string_spelling():
    """The site this replaced handled only dicts, so a domain stored as a plain
    string reached the default by a different route. Same answer, but by
    accident rather than by design."""
    assert auto_renew_for({'domains': ['example.com']}, 'example.com') is True


def test_auto_renew_for_defaults_true_for_an_unknown_domain():
    assert auto_renew_for({'domains': []}, 'example.com') is True
    assert auto_renew_for({}, 'example.com') is True


def test_auto_renew_for_agrees_with_the_list(tmp_path):
    """The property that was not enforced: the single-certificate endpoint and
    the list endpoint must say the same thing about the same certificate."""
    settings = {'domains': [
        {'domain': 'off.example.com', 'auto_renew': False},
        {'domain': 'on.example.com'},
        'plain.example.com',
    ]}
    cert_dir = _cert_dir(tmp_path, 'off.example.com', 'on.example.com',
                         'plain.example.com', 'disk-only.example.com')
    listed = collect_domain_sources(settings, cert_dir)

    for domain, source in listed.items():
        assert auto_renew_for(settings, domain) == source.auto_renew, (
            f'the list and the detail disagree about {domain}'
        )
