"""The cloud-init user data (#1028).

Verified by booting the Ubuntu 24.04 cloud image with it (NoCloud seed): cloud-
init reached `done`, CertMate came up healthy on 127.0.0.1:8000, the token in
/srv/certmate/.env authorised the API (200, anonymous 401), .env was mode 600,
and the instance came back after a reboot. What that depended on:
"""
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
FILE = REPO / 'deploy' / 'cloud-init' / 'certmate.yaml'
TEXT = FILE.read_text()
DATA = yaml.safe_load(TEXT)
RUN = '\n'.join(c if isinstance(c, str) else ' '.join(c) for c in DATA['runcmd'])


def test_cloud_init_recognises_it():
    # cloud-init ignores user data that does not start with this exact line.
    assert TEXT.startswith('#cloud-config\n')


def test_it_runs_the_bundle_this_repository_ships():
    url = 'https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml'
    assert url in RUN
    assert (REPO / 'deploy' / 'docker-compose.yml').exists()
    assert 'docker compose up -d' in RUN


def test_no_secret_is_in_the_user_data():
    # User data is readable from the provider's metadata service: secrets
    # are generated on the VM instead.
    for name in ('API_BEARER_TOKEN', 'SECRET_KEY', 'CERTMATE_BACKUP_PASSPHRASE'):
        assert f'{name}=%s' in RUN
    assert 'openssl rand -hex 32' in RUN


def test_a_rerun_does_not_replace_the_keys_of_a_running_instance():
    assert 'if [ ! -f /srv/certmate/.env ]' in RUN
    assert 'umask 077' in RUN
