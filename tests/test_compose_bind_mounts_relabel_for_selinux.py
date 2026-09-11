"""Bind mounts of the gitignored state dirs need SELinux relabeling.

On Fedora/RHEL the four compose bind mounts `stat` as directories inside the
container but creating a file in them fails with ENOENT unless the mount is
relabeled. `:z` (shared) is the option that does that; `:Z` would lock
./certificates to one container and break the nginx profile, which mounts the
same host directory.
"""
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

COMPOSE = Path(__file__).resolve().parent.parent / 'docker-compose.yml'


def _volume_lines():
    return [
        line.strip().lstrip('- ').strip()
        for line in COMPOSE.read_text(encoding='utf-8').splitlines()
        if ':/app/' in line or ':/etc/nginx/' in line
    ]


def test_the_four_state_bind_mounts_are_selinux_shared():
    mounts = {
        'certificates': './certificates:/app/certificates:rw,z',
        'logs': './logs:/app/logs:rw,z',
        'data': './data:/app/data:rw,z',
        'backups': './backups:/app/backups:rw,z',
    }
    volume_lines = _volume_lines()
    missing = [spec for spec in mounts.values() if spec not in volume_lines]
    assert not missing, (
        f"compose bind mounts must carry ':z' (shared SELinux relabel); "
        f"missing or private ':Z' would reproduce ENOENT on Fedora: {missing}"
    )


def test_nginx_shares_certificates_with_z_not_Z():
    """`:Z` (private) on either side would deny the other container."""
    volume_lines = _volume_lines()
    assert './certificates:/etc/nginx/ssl:ro,z' in volume_lines
    assert not any(':Z' in line for line in volume_lines)
