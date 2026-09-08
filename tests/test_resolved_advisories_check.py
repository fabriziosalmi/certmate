"""The advisory check must read the versions that ship, not the manifests.

An audit reported that `pyjwt 2.9.0` ships in the default image carrying seven
unassessed advisories. It does not ship. The published v2.29.0 image contains
`PyJWT 2.13.0`, which carries none. The auditor had scanned the repository's
requirements files, and a manifest scan resolves each transitive constraint to
the *lowest* version it admits — not to what `pip install` produces. Measured
on 2026-09-08, every package the manifest scan flagged was a false positive:

    package     manifest scan says   image actually has
    pyjwt       2.9.0 (7 advisories) 2.13.0 (none)
    requests    2.9.2 (5)            2.34.2 (none)
    pygments    2.9.0 (2)            not installed at all
    idna        3.9.0 (1)            3.19   (none)
    filelock    3.9.1 (2)            3.32.5 (none)
    protobuf    4.25.9 (1)           7.36.1 (none)

The finding was wrong and the gap behind it was real: nothing scanned the set
that ships, so the correct answer — four advisories, all `cryptography`, all
already documented — was nobody's measurement either.

`scripts/check_resolved_advisories.py` takes a `pip freeze` from inside the
built image and reconciles it with SECURITY.md. These tests cover the parts
that can be wrong without the network: the freeze parser, the alias grouping
that turns seven records into four advisories, and the reconciliation. The
network layer is injected, so nothing here reaches OSV.
"""
import importlib.util
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, REPO / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load('check_resolved_advisories')

# The four advisories the published v2.29.0 image actually carries, measured
# with `pip freeze` inside it. All four are `cryptography==46.0.7`.
SHIPPED = [
    'GHSA-537c-gmf6-5ccf',
    'GHSA-g6cj-pr64-35w5',
    'GHSA-jwv3-5hgf-82ww',
    'GHSA-m2h6-j472-rp4c',
]


# --- the freeze parser ---------------------------------------------------

def test_a_freeze_is_read_as_exact_pins():
    pinned, skipped = check.parse_freeze(
        'Flask==3.1.3\ncryptography==46.0.7\nPyJWT==2.13.0\n')
    assert pinned == [('Flask', '3.1.3'), ('cryptography', '46.0.7'),
                      ('PyJWT', '2.13.0')]
    assert skipped == []


def test_anything_that_is_not_an_exact_pin_is_reported_not_dropped():
    """A freeze that stops pinning is a broken measurement, and silence about
    it would read as a clean scan."""
    pinned, skipped = check.parse_freeze(
        'Flask==3.1.3\n'
        'certmate\n'                                  # bare name
        'requests>=2.34.2\n'                          # a range
        '-e git+https://example.invalid/x#egg=x\n'     # editable
        '# a comment\n'
        '\n')
    assert pinned == [('Flask', '3.1.3')]
    assert skipped == ['certmate', 'requests>=2.34.2']


def test_an_empty_freeze_is_a_failure_not_a_clean_scan(tmp_path):
    """The failure mode that would matter most: `pip freeze` ran against the
    wrong path, produced nothing, and the check congratulated the image."""
    empty = tmp_path / 'resolved.txt'
    empty.write_text('# nothing here\n')
    with pytest.raises(SystemExit, match='pins no packages'):
        check.main(['check', str(empty)])


def test_a_missing_freeze_file_is_a_failure(tmp_path):
    with pytest.raises(SystemExit, match='lost its subject'):
        check.main(['check', str(tmp_path / 'absent.txt')])


# --- alias grouping ------------------------------------------------------

def test_the_same_flaw_under_three_names_counts_once():
    """This is the whole reason the count is four and not seven: OSV publishes
    a GHSA, a CVE and a PYSEC record for one advisory."""
    rows = [
        ('cryptography', '46.0.7', 'GHSA-g6cj-pr64-35w5',
         frozenset({'GHSA-g6cj-pr64-35w5', 'CVE-2026-69247',
                    'PYSEC-2026-3552'})),
        ('cryptography', '46.0.7', 'PYSEC-2026-3552',
         frozenset({'PYSEC-2026-3552', 'CVE-2026-69247',
                    'GHSA-g6cj-pr64-35w5'})),
    ]
    groups = check.group_by_alias(rows)
    assert len(groups) == 1
    assert check.canonical(groups[0][0]) == 'GHSA-g6cj-pr64-35w5'


def test_aliases_are_merged_transitively():
    """A links to B, B links to C, and A never mentions C. Treating these as
    two advisories would double-count, and reporting either as undocumented
    would fail a build over an advisory that is written down."""
    rows = [
        ('p', '1', 'A', frozenset({'A', 'B'})),
        ('p', '1', 'C', frozenset({'C', 'B'})),
    ]
    groups = check.group_by_alias(rows)
    assert len(groups) == 1
    assert groups[0][0] == {'A', 'B', 'C'}


def test_distinct_flaws_stay_distinct():
    """CONTROL: over-merging would hide a real advisory behind a documented
    one, which fails in the direction that matters."""
    rows = [
        ('p', '1', 'GHSA-aaaa-aaaa-aaaa', frozenset({'GHSA-aaaa-aaaa-aaaa'})),
        ('p', '1', 'GHSA-bbbb-bbbb-bbbb', frozenset({'GHSA-bbbb-bbbb-bbbb'})),
    ]
    assert len(check.group_by_alias(rows)) == 2


def test_a_group_remembers_every_package_it_hits():
    rows = [
        ('alpha', '1', 'GHSA-aaaa-aaaa-aaaa', frozenset({'GHSA-aaaa-aaaa-aaaa'})),
        ('beta', '2', 'GHSA-aaaa-aaaa-aaaa', frozenset({'GHSA-aaaa-aaaa-aaaa'})),
    ]
    groups = check.group_by_alias(rows)
    assert len(groups) == 1
    assert groups[0][1] == {('alpha', '1'), ('beta', '2')}


def test_a_group_with_no_ghsa_is_still_reportable():
    """PYSEC-2025-183 has a CVE alias and no GHSA. Reporting it as `None`
    would make the failure message useless."""
    ids = {'PYSEC-2025-183', 'CVE-2025-45768'}
    assert check.canonical(ids) == 'CVE-2025-45768'


# --- reconciliation with SECURITY.md ------------------------------------

def test_an_advisory_named_in_security_md_is_accepted():
    groups = [({'GHSA-537c-gmf6-5ccf'}, {('cryptography', '46.0.7')})]
    assert check.undocumented(groups, set(SHIPPED)) == []


def test_an_advisory_not_named_in_security_md_is_reported():
    groups = [({'GHSA-zzzz-zzzz-zzzz', 'CVE-2026-1'}, {('newpkg', '1.0')})]
    missing = check.undocumented(groups, set(SHIPPED))
    assert len(missing) == 1
    ghsa, ids, packages = missing[0]
    assert ghsa == 'GHSA-zzzz-zzzz-zzzz'
    assert packages == [('newpkg', '1.0')]
    assert 'CVE-2026-1' in ids


def test_documentation_by_any_alias_counts():
    """SECURITY.md names GHSA ids, but a group is one flaw: matching on the
    group rather than on the canonical id means renaming which alias the file
    happens to quote does not turn a documented advisory into a build break."""
    groups = [({'PYSEC-2026-3552', 'GHSA-g6cj-pr64-35w5'}, {('c', '1')})]
    assert check.undocumented(groups, {'GHSA-g6cj-pr64-35w5'}) == []


def test_the_four_advisories_the_image_carries_are_all_in_security_md():
    """The regression guard with teeth. If SECURITY.md loses one of these,
    the scheduled scan would start failing against the published image — this
    catches it offline, at the commit that removed it."""
    documented = _load('check_advisories').documented_advisories()
    missing = [g for g in SHIPPED if g not in documented]
    assert not missing, (
        'SECURITY.md no longer documents %s, which the published image '
        'carries' % ', '.join(missing)
    )


# --- the network layer, with the network replaced -----------------------

def _fake_osv(hits, aliases):
    """A stand-in for OSV: `hits` maps (name, version) to advisory ids."""
    calls = {'batch': 0, 'vulns': []}

    def post(url, payload):
        calls['batch'] += 1
        return {'results': [
            {'vulns': [{'id': i}
                       for i in hits.get((q['package']['name'], q['version']),
                                         [])]}
            for q in payload['queries']]}

    def get(url):
        vuln_id = url.rsplit('/', 1)[1]
        calls['vulns'].append(vuln_id)
        return {'id': vuln_id, 'aliases': aliases.get(vuln_id, [])}

    return post, get, calls


def test_only_the_packages_that_hit_are_looked_up_in_detail():
    post, get, calls = _fake_osv(
        hits={('cryptography', '46.0.7'): ['GHSA-a', 'PYSEC-a']},
        aliases={'GHSA-a': ['PYSEC-a'], 'PYSEC-a': ['GHSA-a']})
    rows = check.query_osv(
        [('Flask', '3.1.3'), ('cryptography', '46.0.7')], post=post, get=get)

    assert calls['batch'] == 1, 'one batch request should cover every package'
    assert sorted(calls['vulns']) == ['GHSA-a', 'PYSEC-a']
    assert len(check.group_by_alias(rows)) == 1


def test_each_advisory_is_fetched_once_however_many_packages_it_hits():
    post, get, calls = _fake_osv(
        hits={('alpha', '1'): ['GHSA-a'], ('beta', '2'): ['GHSA-a']},
        aliases={})
    check.query_osv([('alpha', '1'), ('beta', '2')], post=post, get=get)
    assert calls['vulns'] == ['GHSA-a']


def test_a_short_answer_from_osv_is_refused_not_realigned():
    """CONTROL: `zip` would silently pair each result with the wrong package
    and report advisories against packages that do not have them — or, worse,
    drop the tail of the list and pass."""
    def post(url, payload):
        return {'results': [{'vulns': []}]}      # one answer, two questions

    with pytest.raises(SystemExit, match='refusing to guess'):
        check.query_osv([('alpha', '1'), ('beta', '2')],
                        post=post, get=lambda url: {})


def test_a_package_with_no_advisories_produces_no_rows():
    post, get, _ = _fake_osv(hits={}, aliases={})
    assert check.query_osv([('PyJWT', '2.13.0')], post=post, get=get) == []


@pytest.mark.parametrize('bad_id', [
    '../../etc/passwd',
    'GHSA-a/../../x',
    'GHSA a',
    '',
    'x' * 65,
])
def test_an_advisory_id_is_not_put_into_a_url_unchecked(bad_id):
    """The id is remote data and the next thing done with it is string
    concatenation into a request URL."""
    post, get, _ = _fake_osv(hits={('p', '1'): [bad_id]}, aliases={})
    with pytest.raises(SystemExit, match='will not put in a URL'):
        check.query_osv([('p', '1')], post=post, get=get)


def test_the_real_advisory_ids_still_pass_the_shape_check():
    """CONTROL: a guard that rejects the ids OSV actually returns would turn
    every scan into a failure, which reads as a broken build, not a finding."""
    post, get, _ = _fake_osv(
        hits={('cryptography', '46.0.7'):
              ['GHSA-537c-gmf6-5ccf', 'PYSEC-2026-3552', 'CVE-2026-69247']},
        aliases={})
    assert len(check.query_osv([('cryptography', '46.0.7')],
                               post=post, get=get)) == 3


# --- the wiring ----------------------------------------------------------

def test_ci_captures_the_freeze_from_inside_the_image_and_runs_this_check():
    """The script is worth nothing if nothing calls it, and worth less than
    nothing if what calls it feeds it a manifest."""
    import yaml
    workflow = yaml.safe_load(
        (REPO / '.github' / 'workflows'
         / 'docker-multiplatform.yml').read_text())
    steps = workflow['jobs']['security-scan']['steps']
    scripts = [s for s in steps
               if 'scripts/check_resolved_advisories.py' in (s.get('run') or '')]
    assert len(scripts) == 1, 'the check is not wired into security-scan'

    capture = [s for s in steps
               if 'freeze' in (s.get('run') or '')
               and 'certmate:scan' in (s.get('run') or '')]
    assert capture, (
        'the freeze must be captured from the image under test; pointing this '
        'at a requirements file would reintroduce exactly the false positives '
        'it replaces'
    )
    assert steps.index(capture[0]) < steps.index(scripts[0]), (
        'the check runs before the freeze it reads is written'
    )


def test_the_check_gates_a_merge():
    """security-scan is the job that hosts it, and it is a required context."""
    import yaml
    registry = yaml.safe_load(
        (REPO / '.github' / 'required-checks.yml').read_text())
    gating = {e['context'] for e in registry['gating']}
    assert 'security-scan' in gating
