"""The production compose bundle runs the published image, as released (#1015).

`deploy/docker-compose.yml` is the file the docs tell an operator to download
with one `curl`. Everything it promises is checked here, because each promise
is a way it could quietly stop being true:

* it pins the image of the CURRENT release, which `release.sh` moves, so the
  copy on `main` never installs an older version than the one just shipped;
* it builds nothing: a `build:` key would need the repository it was
  downloaded without;
* it publishes on loopback unless told otherwise;
* the four directories the app writes are named volumes, which Docker seeds
  from the image with the right ownership, so there is nothing to prepare;
* it refuses to start without the two secrets, rather than letting the app
  invent values that change on every recreate.

Verified by running it: a fresh directory with only this file and a
generated .env comes up healthy, the first page creates the admin, the admin
survives `down`/`up`, and CERTMATE_VERSION moves the instance between releases.
"""
import re
from pathlib import Path

import pytest
import yaml

from modules import __version__

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
BUNDLE = REPO / 'deploy' / 'docker-compose.yml'
WRITABLE = ('/app/certificates', '/app/data', '/app/logs', '/app/backups')


@pytest.fixture(scope='module')
def service():
    return yaml.safe_load(BUNDLE.read_text())['services']['certmate']


def test_it_pins_the_image_of_the_current_release(service):
    match = re.fullmatch(r'fabriziosalmi/certmate:\$\{CERTMATE_VERSION:-(.+)\}',
                         service['image'])
    assert match, service['image']
    assert match.group(1) == __version__


def test_it_builds_nothing(service):
    assert 'build' not in service


def test_it_publishes_on_loopback_by_default(service):
    assert service['ports'] == ['${CERTMATE_BIND:-127.0.0.1}:${CERTMATE_PORT:-8000}:8000']


def test_every_directory_the_app_writes_is_a_named_volume(service):
    declared = set(yaml.safe_load(BUNDLE.read_text())['volumes'])
    mounts = dict(v.split(':', 1)[::-1] for v in service['volumes'])
    for path in WRITABLE:
        assert path in mounts, f'{path} is not mounted'
        assert mounts[path] in declared, f'{path} is a bind mount, not a named volume'


@pytest.mark.parametrize('name', ['API_BEARER_TOKEN', 'SECRET_KEY'])
def test_it_refuses_to_start_without_its_secrets(service, name):
    entry = next(e for e in service['environment'] if e.startswith(f'{name}='))
    assert f'${{{name}:?' in entry, entry


def test_the_release_moves_the_pin_and_commits_it():
    script = (REPO / 'scripts' / 'release.sh').read_text()
    assert 'pathlib.Path("deploy/docker-compose.yml")' in script
    git_add = next(l for l in script.splitlines() if l.strip().startswith('git add modules/__init__.py'))
    assert 'deploy/docker-compose.yml' in git_add


def test_the_docs_point_at_this_file():
    docs = (REPO / 'docs' / 'docker.md').read_text()
    assert 'raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml' in docs
