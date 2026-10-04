"""The 76 packages nobody chose are now recorded, and cannot drift silently.

`requirements.txt` pins 42 packages. Installing it resolves **118**. The other
76 — the transitive closure — were whatever the index served on the day the
image was built. Two images built from the same commit a month apart were not
the same image, and nothing in the repository would have shown the difference.

`requirements.lock` and `requirements-minimal.lock` record the resolution in
full, resolved by uv for the two published architectures
(`scripts/regenerate_lockfiles.sh`), and the builder installs from them with pip.

The failure this file exists to prevent is not drift, though. It is the
opposite: **installing from a lock means a bump to `requirements.txt` does
nothing until the lock is regenerated.** Dependabot raises a security patch, it
merges, every check is green, and the image keeps installing the old version.
Nothing would say so. `test_every_direct_pin_is_the_one_the_image_installs`
says so, and its negative controls below prove it actually would.

Freezing the transitives has a second cost, which is that a locked package can
age into a known-vulnerable one. That is left to the gate that already covers
it: `scripts/check_resolved_advisories.py` asks OSV about the set actually
installed in the built image, on every build, as a required check. This file
does not duplicate that; it asserts the two mechanisms are both wired up, so
removing one is a failing test rather than a quiet loss of cover.
"""
import importlib.util
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent


def _load(name):
    """The idiom the other script tests use. A plain `from scripts.lockfile
    import ...` happens to work through pytest's rootdir handling, but
    `scripts/` is not a package and that is not a property to depend on."""
    spec = importlib.util.spec_from_file_location(
        name, REPO / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_lockfile = _load('lockfile')
PIN = _lockfile.PIN
check = _lockfile.check
normalize = _lockfile.normalize
read_pins = _lockfile.read_pins
render = _lockfile.render
read_entries = _lockfile.read_entries
check_hashes = _lockfile.check_hashes
check_constraints = _lockfile.check_constraints
HASH = _lockfile.HASH
PAIRS = [('requirements.txt', 'requirements.lock'),
         ('requirements-minimal.txt', 'requirements-minimal.lock')]


# --- the locks themselves ------------------------------------------------

@pytest.mark.parametrize('source,lock', PAIRS)
def test_the_lock_exists(source, lock):
    assert (REPO / lock).is_file(), (
        f'{source} has no lockfile, so the image resolves it fresh at build '
        f'time and the transitive versions are build-day luck')


@pytest.mark.parametrize('source,lock', [*PAIRS, ('requirements-build.txt', 'requirements-build.lock')])
def test_every_direct_pin_is_the_one_the_image_installs(source, lock):
    """The guard. A pin bumped without regenerating the lock is a patch that
    merges, goes green, and never ships."""
    problems = check(REPO / source, REPO / lock)
    assert not problems, '\n'.join(problems)


@pytest.mark.parametrize('source,lock', PAIRS)
def test_the_lock_records_more_than_it_was_given(source, lock):
    """A lock the size of its requirements file has recorded nothing — it would
    pass every other test here while leaving the transitive set unpinned."""
    text = (REPO / source).read_text(encoding='utf-8')
    direct = read_pins(text)
    locked = read_pins((REPO / lock).read_text(encoding='utf-8'))
    assert len(locked) > len(direct), (
        f'{lock} holds {len(locked)} pins for {len(direct)} direct '
        f'requirements, so the transitive packages are not in it')


@pytest.mark.parametrize('source,lock', [*PAIRS, ('requirements-build.txt', 'requirements-build.lock')])
def test_every_line_in_the_lock_is_an_exact_pin_or_its_hash(source, lock):
    """A range or a bare name in a lockfile re-opens exactly the hole the file
    was written to close, for that one package, invisibly. The only other kind
    of line is a `--hash=` line belonging to the pin above it."""
    loose = []
    lines = (REPO / lock).read_text('utf-8').splitlines()
    for number, raw in enumerate(lines, 1):
        line = raw.split('#')[0].strip()
        if line.endswith('\\'):
            line = line[:-1].strip()
        if line and not PIN.match(line) and not HASH.match(line):
            loose.append(f'{lock}:{number}: {line}')
    assert not loose, 'not an exact pin: ' + ', '.join(loose)


@pytest.mark.parametrize('lock', ['requirements.lock', 'requirements-minimal.lock', 'requirements-build.lock'])
def test_every_pin_in_the_lock_is_hashed(lock):
    """The image installs these with --require-hashes, which refuses the whole
    file for one unhashed line. Said here, with the package's name, rather
    than as a build failure."""
    problems = check_hashes(REPO / lock)
    assert not problems, '\n'.join(problems)
    entries = read_entries((REPO / lock).read_text('utf-8'))
    assert entries and all(found for _, found in entries.values())


@pytest.mark.parametrize('lock', ['requirements.lock', 'requirements-minimal.lock'])
def test_the_constraints_file_holds_the_locks_pins(lock):
    """The extras and test layers are constrained by the .constraints file. If
    it disagreed with the lock, a layer could move a pin the lock holds."""
    path = REPO / lock
    problems = check_constraints(path, path.with_suffix('.constraints'))
    assert not problems, '\n'.join(problems)
    assert '--hash' not in path.with_suffix('.constraints').read_text('utf-8'), (
        'a hash in the constraints file turns hash checking on for the extras install')


@pytest.mark.parametrize('source,lock', PAIRS)
def test_the_lock_says_how_to_regenerate_it(source, lock):
    """A generated file that does not name its generator gets hand-edited."""
    header = (REPO / lock).read_text(encoding='utf-8')[:1200]
    assert 'scripts/regenerate_lockfiles.sh' in header
    assert 'GENERATED' in header


# --- the build actually uses them ----------------------------------------

def test_the_builder_installs_from_the_lock_with_its_hashes():
    dockerfile = (REPO / 'Dockerfile').read_text(encoding='utf-8')
    assert 'LOCKFILE="${REQUIREMENTS_FILE%.txt}.lock"' in dockerfile, (
        'the builder no longer derives a lockfile from the chosen variant, so '
        'it resolves at build time again')
    assert 'pip install --no-cache-dir --require-hashes -r "${LOCKFILE}"' in dockerfile, (
        'the lock is installed without --require-hashes, so its hashes verify nothing')
    assert 'pip install --no-cache-dir --require-hashes -r requirements-build.lock' in dockerfile, (
        "the builder's own tools are installed without their hashes")


def test_the_extras_are_constrained_by_the_locks_pins_without_hashes():
    """The .txt constrains 42 packages; the lock constrains 118. Constraining
    with the .txt would let an extras layer move a transitive out from under
    the locked base. Constraining with the hashed lock itself turns hash
    checking on for the extras install and refuses every package outside the
    lock (measured: requirements-infisical-storage.txt, "Hashes are
    required"). So: the .constraints file."""
    dockerfile = (REPO / 'Dockerfile').read_text(encoding='utf-8')
    assert 'CONSTRAINTS="${REQUIREMENTS_FILE%.txt}.constraints"' in dockerfile
    assert '-c "${CONSTRAINTS}"' in dockerfile
    assert '-c "${LOCKFILE}"' not in dockerfile
    assert '-c "${REQUIREMENTS_FILE}"' not in dockerfile


def test_the_locks_and_their_constraints_reach_the_build_context():
    dockerfile = (REPO / 'Dockerfile').read_text(encoding='utf-8')
    copies = dockerfile.count('COPY requirements*.txt requirements*.lock requirements*.constraints ./')
    assert copies == 2, (
        'a stage copies the requirements files without the locks or their constraints')



def test_the_advisory_gate_that_covers_a_stale_lock_still_runs():
    """Pinning transitives trades build-day roulette for the risk of freezing a
    package that later turns out to be vulnerable. That trade is only
    acceptable while something asks OSV about what actually got installed."""
    workflow = (REPO / '.github' / 'workflows'
                / 'docker-multiplatform.yml').read_text(encoding='utf-8')
    assert 'scripts/check_resolved_advisories.py' in workflow

    registry = (REPO / '.github' / 'required-checks.yml').read_text('utf-8')
    gating = registry.split('gating:')[1].split('\nadvisory:')[0]
    assert 'context: build' in gating, (
        'the image build is no longer a required check, so the advisory scan '
        'that covers a frozen transitive can go red without blocking anything')


# --- the pure functions, including what they must NOT accept -------------

def test_a_pin_that_moved_without_the_lock_is_caught(tmp_path):
    """NEGATIVE CONTROL for the guard above. Without this, that test passes
    equally well against a check() that always returns []."""
    source = tmp_path / 'requirements.txt'
    lock = tmp_path / 'requirements.lock'
    source.write_text('flask==3.1.2\n')
    lock.write_text('flask==3.1.1\nwerkzeug==3.1.3\n')

    problems = check(source, lock)

    assert len(problems) == 1
    assert 'flask' in problems[0]
    assert '3.1.1' in problems[0] and '3.1.2' in problems[0], (
        'the message names neither version, so it does not say what to do')


def test_a_pin_missing_from_the_lock_is_caught(tmp_path):
    source = tmp_path / 'requirements.txt'
    lock = tmp_path / 'requirements.lock'
    source.write_text('flask==3.1.2\ncertbot==2.10.0\n')
    lock.write_text('flask==3.1.2\n')

    problems = check(source, lock)

    assert len(problems) == 1
    assert 'certbot' in problems[0]


def test_a_lock_that_agrees_reports_nothing(tmp_path):
    source = tmp_path / 'requirements.txt'
    lock = tmp_path / 'requirements.lock'
    source.write_text('flask==3.1.2  # a comment\n\n# a whole-line comment\n')
    lock.write_text('flask==3.1.2\nwerkzeug==3.1.3\n')

    assert check(source, lock) == []


def test_names_are_compared_the_way_the_index_compares_them():
    """`zope.interface` and `zope-interface` are one package. Comparing the raw
    strings would report a mismatch that does not exist and send someone
    regenerating a lock that was already correct."""
    assert normalize('zope.interface') == normalize('zope_interface')
    assert normalize('PyOpenSSL') == 'pyopenssl'


def test_a_normalised_name_still_matches_across_the_two_files(tmp_path):
    source = tmp_path / 'requirements.txt'
    lock = tmp_path / 'requirements.lock'
    source.write_text('zope.interface==8.1\n')
    lock.write_text('zope-interface==8.1\n')

    assert check(source, lock) == []


@pytest.mark.parametrize('line', [
    'flask>=3.1',                 # a range is not a pin
    'flask',                      # a bare name
    'flask==3.1.2 ; python_version < "3.13"',   # environment marker
    '-r requirements-base.txt',   # an include
    'flask[async]==3.1.2',        # an extra
])
def test_read_pins_ignores_what_is_not_a_plain_pin(line):
    """These are read as *absent* rather than as a pin, so a requirements file
    that grows one is reported by the guard instead of being silently skipped
    with the wrong version assumed."""
    assert read_pins(line) == {}


def test_render_writes_the_whole_resolution_sorted():
    resolved = {'Werkzeug': '3.1.3', 'flask': '3.1.2'}
    text = render(resolved, 'requirements.txt', {'flask': '3.1.2'})

    body = [line for line in text.splitlines()
            if line and not line.startswith('#')]
    assert body == ['flask==3.1.2', 'werkzeug==3.1.3'], (
        'the lock is not sorted, so an unrelated regeneration produces a diff '
        'nobody can review')
    assert '1 of these are' in text and 'other 1 are' in text


def test_render_counts_transitives_rather_than_asserting_them():
    """The header states the split, and it is generated from the resolution — a
    hand-written number would be wrong one bump later."""
    resolved = dict.fromkeys(('a', 'b', 'c', 'd'), '1')
    text = render(resolved, 'requirements.txt', {'a': '1'})
    assert re.search(r'\b1 of these are', text)
    assert re.search(r'other 3 are', text)


def test_the_real_lock_matches_the_measurement_in_its_own_header():
    """The header claims a split; if regeneration ever wrote the counts from
    somewhere other than the file itself, this is where it shows."""
    text = (REPO / 'requirements.lock').read_text(encoding='utf-8')
    direct = len(read_pins((REPO / 'requirements.txt').read_text('utf-8')))
    total = len(read_pins(text))

    assert f'{direct} of these are' in text
    assert f'other {total - direct} are' in text


# --- writing a lock from what uv resolved ----------------------------------

def _hashed(pins):
    """What `uv pip compile --generate-hashes` writes: each pin followed by its
    hash lines. The hash here is a stand-in; write() checks presence, and the
    real check that a hash matches a file is pip's, at build time."""
    out = []
    for line in pins.splitlines():
        match = PIN.match(line.split('#')[0].strip())
        out.append(f'{line} \\\n    --hash=sha256:{"0" * 64}' if match else line)
    return '\n'.join(out) + '\n'


def _write(tmp_path, requirements, pins, *extra, hashed=True):
    (tmp_path / 'requirements.txt').write_text(requirements)
    (tmp_path / 'pins.txt').write_text(_hashed(pins) if hashed else pins)
    code = _lockfile.main(['write', str(tmp_path / 'requirements.txt'), str(tmp_path / 'pins.txt'),
                           str(tmp_path / 'requirements.lock'), *extra])
    return code, tmp_path / 'requirements.lock'


def test_write_turns_the_resolved_pins_into_a_lock(tmp_path):
    code, lock = _write(tmp_path, 'flask==3.1.2\n', 'flask==3.1.2\nwerkzeug==3.1.3\nmarkupsafe==3.0.2\n')
    assert code == 0
    assert read_pins(lock.read_text()) == {'flask': '3.1.2', 'werkzeug': '3.1.3', 'markupsafe': '3.0.2'}
    assert check(tmp_path / 'requirements.txt', lock) == []


def test_write_reads_what_uv_writes_comments_and_all(tmp_path):
    """`uv pip compile` without `--no-annotate` explains each pin in a comment; it is not part of the pin."""
    pins = 'flask==3.1.2\n    # via -r requirements.txt\nwerkzeug==3.1.3\n    # via flask\n'
    code, lock = _write(tmp_path, 'flask==3.1.2\n', pins)
    assert code == 0 and read_pins(lock.read_text()) == {'flask': '3.1.2', 'werkzeug': '3.1.3'}


def test_write_refuses_a_resolution_that_lacks_a_pinned_package(tmp_path):
    """A resolution that dropped a direct pin would produce a lock the image installs without it."""
    code, lock = _write(tmp_path, 'flask==3.1.2\nrequests==2.32.0\n', 'flask==3.1.2\nwerkzeug==3.1.3\n')
    assert code == 1 and not lock.exists()


# --- hashes and constraints: what they must catch -------------------------

def test_an_unhashed_pin_is_caught(tmp_path):
    """NEGATIVE CONTROL for test_every_pin_in_the_lock_is_hashed."""
    lock = tmp_path / 'requirements.lock'
    lock.write_text('flask==3.1.2 \\\n    --hash=sha256:' + 'a' * 64 + '\nwerkzeug==3.1.3\n')
    problems = check_hashes(lock)
    assert len(problems) == 1 and 'werkzeug' in problems[0]


def test_constraints_that_drifted_from_the_lock_are_caught(tmp_path):
    lock = tmp_path / 'requirements.lock'
    lock.write_text('flask==3.1.2 \\\n    --hash=sha256:' + 'a' * 64 + '\n')
    constraints = tmp_path / 'requirements.constraints'
    constraints.write_text('flask==3.1.1\n')
    assert check_constraints(lock, constraints)
    constraints.write_text('flask==3.1.2\n')
    assert check_constraints(lock, constraints) == []
    constraints.unlink()
    assert check_constraints(lock, constraints), 'a missing constraints file passed'


def test_read_entries_keeps_each_hash_with_its_pin():
    text = ('a==1 \\\n    --hash=sha256:' + '1' * 64 + ' \\\n    --hash=sha256:' + '2' * 64 +
            '\n    # via x\nb==2 \\\n    --hash=sha256:' + '3' * 64 + '\n')
    entries = read_entries(text)
    assert entries == {'a': ('1', ['sha256:' + '1' * 64, 'sha256:' + '2' * 64]),
                       'b': ('2', ['sha256:' + '3' * 64])}


def test_write_refuses_a_resolution_without_hashes(tmp_path):
    """A lock written without hashes would be installed with --require-hashes
    and refused at build time; refuse it here, where the fix is one flag."""
    code, lock = _write(tmp_path, 'flask==3.1.2\n', 'flask==3.1.2\nwerkzeug==3.1.3\n', hashed=False)
    assert code == 1 and not lock.exists()


def test_write_with_constraints_writes_the_pins_without_hashes(tmp_path):
    code, lock = _write(tmp_path, 'flask==3.1.2\n', 'flask==3.1.2\nwerkzeug==3.1.3\n', '--constraints')
    assert code == 0
    constraints = lock.with_suffix('.constraints')
    assert read_pins(constraints.read_text()) == {'flask': '3.1.2', 'werkzeug': '3.1.3'}
    assert '--hash' not in constraints.read_text()
    assert check_hashes(lock) == [] and check_constraints(lock, constraints) == []
