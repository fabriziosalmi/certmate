"""Regression tests for scripts/reset_admin_password.py (issue #383).

The emergency reset script must actually create the admin user in the
settings file it claims to have updated — including on a fresh install
whose settings.json has no "users" key at all, which is precisely the
state in which an operator reaches for this script.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "reset_admin_password.py"

PASSWORD = "SuperSecretPassw0rd!"


def _run_script(settings_path: Path):
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=f"{PASSWORD}\n{PASSWORD}\n",
        capture_output=True,
        text=True,
        env={**os.environ, "CERTMATE_SETTINGS_PATH": str(settings_path)},
        timeout=60,
    )


def _assert_admin_written(settings_path: Path):
    data = json.loads(settings_path.read_text())
    assert "users" in data, "script reported success but wrote no users key"
    admin = data["users"].get("admin")
    assert admin, "script reported success but the admin user is missing"
    assert admin["role"] == "admin"
    assert admin["enabled"] is True

    import bcrypt

    assert bcrypt.checkpw(PASSWORD.encode(), admin["password_hash"].encode())


def test_creates_admin_when_users_key_is_absent(tmp_path):
    """Fresh-install shape: no 'users' key at all (the #383 scenario)."""
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps({"domains": [], "email": "a@b.c"}))

    result = _run_script(settings_path)

    assert result.returncode == 0, result.stderr
    _assert_admin_written(settings_path)
    # Other keys must be preserved.
    data = json.loads(settings_path.read_text())
    assert data["email"] == "a@b.c"


def test_creates_admin_when_users_dict_is_empty(tmp_path):
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps({"users": {}}))

    result = _run_script(settings_path)

    assert result.returncode == 0, result.stderr
    _assert_admin_written(settings_path)


def test_resets_existing_admin_password(tmp_path):
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "users": {
                    "admin": {
                        "password_hash": "$2b$12$invalidoldhashvalue",
                        "role": "admin",
                        "enabled": True,
                        "created_at": "2026-01-01T00:00:00+00:00",
                    }
                }
            }
        )
    )

    result = _run_script(settings_path)

    assert result.returncode == 0, result.stderr
    _assert_admin_written(settings_path)
    # created_at must be preserved, not regenerated.
    data = json.loads(settings_path.read_text())
    assert data["users"]["admin"]["created_at"] == "2026-01-01T00:00:00+00:00"
