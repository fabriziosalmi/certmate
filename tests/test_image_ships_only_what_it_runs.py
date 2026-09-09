"""The published image carries what the process runs, and nothing else.

The runtime stage used to be `COPY . .` with a `.dockerignore` denylist. That
worked the way denylists work. Measured against the published v2.29.0 image on
2026-09-08, `/app` contained:

    licensing.pdf         188K   a licensing document
    demo/                 856K   a demo directory
    charts/                64K   the Helm chart, published on its own channel
    clients/               96K   the SDK and CLI sources, published to PyPI
    mcp/                   80K   the MCP server, published separately
    monitoring/            36K   Grafana and Prometheus assets
    conftest.py, pytest.ini, codecov.yml, .flake8, Makefile, .airgap.yml
    build-docker.sh, build-multiplatform.sh, debug-docker.sh, quick_test.sh,
    run-docker.sh, run-tests.sh, test-multiplatform.sh, start-certmate.sh
    certmate.service, nginx.conf.example

None of it is read by the running process. All of it is either build-time —
already consumed by the builder stage, which is the whole point of a
multi-stage build — or a separate deliverable that ships on its own channel.

The problem with a denylist is not the size. It is that it ships whatever
nobody remembered to add to it, and the thing nobody remembers is always the
thing that arrived last: every one of those directories was added by a feature
that had no reason to think about the Dockerfile.

The Dockerfile now names what it copies. These tests check the image rather
than the Dockerfile, because a `COPY` line that is right and a `.dockerignore`
that quietly re-adds a path look identical in review.

Marked `e2e`: they need the built image, which the session fixture provides.

Verified against the published v2.29.0 image by listing `/app` in it directly:
all sixteen names below are present there, and the "only what it needs" check
finds twenty-three entries too many. Note that `CERTMATE_IMAGE` is NOT a way to
run these against a published image — `docker_container` *builds* the working
tree and tags it with that name, so pointing it at a published tag rebuilds
locally under that tag and the tests pass on a fresh build while appearing to
test the release. Set `CERTMATE_SKIP_BUILD=1` as well, or list the image by
hand.
"""
import subprocess

import pytest

pytestmark = [pytest.mark.e2e]

# What the running process actually touches.
EXPECTED = {
    'app.py',            # the entry point gunicorn loads
    'modules',           # the application
    'templates',         # rendered by it
    'static',            # served by it
    'scripts',           # two files; see EXPECTED_SCRIPTS
    # Runtime-writable trees the Dockerfile creates, not copies.
    'backups', 'certificates', 'data', 'logs',
}

# The allowlist above names directories, and that is one level too coarse for
# this one: `COPY scripts/` put all fourteen files in the image, of which the
# runtime reads two. The other twelve are build- and release-time — release.sh
# carries the entire release procedure, regenerate_lockfiles.sh, five check_*
# gates, the theme codemod, the walkthrough recorder — which is the same defect
# the allowlist was written to fix, surviving one directory further down.
EXPECTED_SCRIPTS = {
    # Executed by the SolidServer DNS strategy as a certbot manual hook.
    'solidserver_hook.py',
    # The documented in-container recovery: the README gives the docker exec
    # line and the login page names the file.
    'reset_admin_password.py',
}

# Two error paths tell the operator to install one of these into a running
# container to add a DNS or storage backend, so they are part of the runtime
# surface even though the builder stage is what consumes them at build time.
REQUIREMENTS_PREFIX = 'requirements'

# Things whose presence in the image was the finding. Named individually so a
# failure says which one came back, rather than "the set changed".
MUST_NOT_SHIP = [
    ('licensing.pdf', 'a licensing document the process never opens'),
    ('demo', 'the demo directory'),
    ('charts', 'the Helm chart, published on its own channel'),
    ('clients', 'the SDK and CLI sources, published to PyPI'),
    ('mcp', 'the MCP server, published separately'),
    ('monitoring', 'Grafana and Prometheus assets'),
    ('conftest.py', "pytest's own configuration"),
    ('pytest.ini', "pytest's own configuration"),
    ('codecov.yml', 'coverage reporting configuration'),
    ('Makefile', 'developer targets'),
    ('build-docker.sh', 'a build script, already consumed by the builder'),
    ('build-multiplatform.sh', 'a build script'),
    ('run-tests.sh', 'a test runner'),
    ('quick_test.sh', 'a test runner'),
    ('test-multiplatform.sh', 'a test runner'),
    ('debug-docker.sh', 'a debugging script'),
]


@pytest.fixture(scope='module')
def app_dir(docker_container):
    """What `/app` holds in the image under test."""
    from tests.conftest import IMAGE_NAME
    result = subprocess.run(
        ['docker', 'run', '--rm', '--entrypoint', 'sh', IMAGE_NAME,
         '-c', 'ls -A /app'],
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    entries = set(result.stdout.split())
    assert entries, 'listing /app in the image produced nothing'
    return entries


@pytest.mark.parametrize('name, what', MUST_NOT_SHIP)
def test_a_build_time_or_separate_deliverable_does_not_ship(app_dir, name, what):
    assert name not in app_dir, (
        f'{name} is in the published image ({what}). It is either build-time '
        f'or published on its own channel; add it to nothing, and remove the '
        f'COPY that brought it back.'
    )


def test_everything_that_ships_is_something_the_process_uses(app_dir):
    """The other direction. Without this the tests above are a denylist too —
    the exact structure the change replaced."""
    unexpected = sorted(
        name for name in app_dir
        if name not in EXPECTED and not name.startswith(REQUIREMENTS_PREFIX))
    assert not unexpected, (
        'these are in the image and nothing in the runtime reads them:\n  '
        + '\n  '.join(unexpected)
        + '\n\nIf one of them is genuinely needed, add it to EXPECTED with '
          'the reason. If not, it should not be copied.'
    )


def test_what_the_runtime_needs_is_actually_there(app_dir):
    """CONTROL: an allowlist that copies too little produces an image that
    boots and then fails on a path nobody exercised in CI."""
    missing = sorted(EXPECTED - app_dir)
    assert not missing, f'the image is missing {", ".join(missing)}'

    assert any(n.startswith(REQUIREMENTS_PREFIX) for n in app_dir), (
        'no requirements file shipped, but two error messages tell the '
        'operator to install one into a running container'
    )


def test_the_solidserver_hook_is_where_the_code_looks_for_it(docker_container):
    """The one runtime dependency outside app/modules/templates/static, and
    the reason `scripts/` is copied at all. `dns_strategies.py` resolves
    `scripts/solidserver_hook.py` relative to the working directory."""
    from tests.conftest import IMAGE_NAME
    result = subprocess.run(
        ['docker', 'run', '--rm', '--entrypoint', 'sh', IMAGE_NAME,
         '-c', 'test -f /app/scripts/solidserver_hook.py && echo present'],
        capture_output=True, text=True, timeout=120)
    assert 'present' in result.stdout, (
        'scripts/solidserver_hook.py is not in the image; the SolidServer DNS '
        'provider would fail at issuance time with a missing-file error'
    )


def test_the_dockerfile_does_not_copy_the_whole_tree():
    """Checked as well as the image, because a `COPY . .` that reappears is
    the specific regression, and it would take a rebuild to see it otherwise.
    """
    import pathlib
    dockerfile = (pathlib.Path(__file__).resolve().parent.parent
                  / 'Dockerfile').read_text()
    runtime = dockerfile.split('FROM')[-1]
    for line in runtime.splitlines():
        stripped = line.strip()
        if stripped.startswith('COPY') and '--from=' not in stripped:
            assert stripped.split()[1] != '.', (
                'the runtime stage copies the whole tree again: ' + stripped)


@pytest.fixture(scope='module')
def scripts_dir(docker_container):
    """What `/app/scripts` holds in the image under test."""
    from tests.conftest import IMAGE_NAME
    result = subprocess.run(
        ['docker', 'run', '--rm', '--entrypoint', 'sh', IMAGE_NAME,
         '-c', 'ls -A /app/scripts'],
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    return set(result.stdout.split())


def test_the_runtime_scripts_are_present(scripts_dir):
    """CONTROL first: an empty directory would satisfy the check below while
    breaking SolidServer issuance and the password reset."""
    assert EXPECTED_SCRIPTS <= scripts_dir, (
        f'missing from the image: {sorted(EXPECTED_SCRIPTS - scripts_dir)}')


def test_no_build_time_script_ships(scripts_dir):
    """The other direction, one level deeper than the /app check above."""
    unexpected = sorted(scripts_dir - EXPECTED_SCRIPTS)
    assert not unexpected, (
        'these are in /app/scripts and nothing in the runtime reads them:\n  '
        + '\n  '.join(unexpected)
        + '\n\nThey are build- or release-time. Copy the runtime ones by name '
          'rather than copying the directory.')
