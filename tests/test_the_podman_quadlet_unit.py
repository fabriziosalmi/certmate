"""The Podman Quadlet unit (#1026).

Verified on Fedora 44 with Podman 5.8, rootful and rootless (with lingering):
healthy, the Podman secret reaches the container as the API token, the API
answers 200 with it and 401 without, and the service is back after a reboot.

What those runs depended on, pinned:

* every volume carries `:U`. Rootless, Podman seeded the `backups` volume
  (whose image directory is not empty) with its root still owned by root, and
  CertMate refused to start: "Required directories are not writable";
* the three secrets come from Podman secrets, never from the file;
* the port is published on loopback only;
* the image name is fully qualified: Podman refuses short names without a
  registries.conf alias.
"""
import configparser
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

UNIT = Path(__file__).resolve().parent.parent / 'deploy' / 'podman' / 'certmate.container'


@pytest.fixture(scope='module')
def unit():
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    # Quadlet repeats keys (Volume=, Secret=); read them all.
    values = {}
    section = None
    for raw in UNIT.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            section = line.strip('[]')
            continue
        key, _, value = line.partition('=')
        values.setdefault((section, key), []).append(value)
    return values


def test_every_volume_is_named_and_given_to_the_container_user(unit):
    volumes = unit[('Container', 'Volume')]
    targets = {v.split(':')[1] for v in volumes}
    assert targets == {'/app/certificates', '/app/data', '/app/backups', '/app/logs'}
    for v in volumes:
        name, _, rest = v.partition(':')
        assert not name.startswith('/') and not name.startswith('.'), v
        assert rest.endswith(':U'), v


def test_the_secrets_come_from_podman_secrets(unit):
    targets = {s.split('target=')[1] for s in unit[('Container', 'Secret')]}
    assert targets == {'API_BEARER_TOKEN', 'SECRET_KEY', 'CERTMATE_BACKUP_PASSPHRASE'}
    assert ('Container', 'Environment') not in unit or not any(
        e.startswith(('API_BEARER_TOKEN=', 'SECRET_KEY=')) for e in unit[('Container', 'Environment')])


def test_it_publishes_on_loopback_only(unit):
    assert unit[('Container', 'PublishPort')] == ['127.0.0.1:8000:8000']


def test_the_image_name_is_fully_qualified(unit):
    assert unit[('Container', 'Image')] == ['docker.io/fabriziosalmi/certmate:latest']


def test_it_restarts_and_starts_at_boot(unit):
    assert unit[('Service', 'Restart')] == ['always']
    wanted = unit[('Install', 'WantedBy')][0].split()
    assert 'default.target' in wanted and 'multi-user.target' in wanted
