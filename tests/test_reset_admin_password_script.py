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

    # The reset must also enable local auth, otherwise login still returns
    # 403 "Local auth disabled" even though the admin now exists (issue #397).
    assert data.get("local_auth_enabled") is True, (
        "reset must enable local auth so the restored admin can actually log in"
    )


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


def test_reset_keeps_settings_file_0600(tmp_path):
    """The reset must NOT widen settings.json permissions — it holds password,
    token and API-key hashes plus DNS creds. The atomic temp+replace chmods the
    temp to 0600 before the swap so os.replace can't transfer a 0644 umask mode."""
    import stat
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps({"users": {}}))
    settings_path.chmod(0o600)

    result = _run_script(settings_path)

    assert result.returncode == 0, result.stderr
    mode = stat.S_IMODE(settings_path.stat().st_mode)
    assert mode == 0o600, f"settings.json mode is {oct(mode)}, expected 0o600"
    # No temp file left behind after a successful write.
    assert not (tmp_path / "settings.json.reset_tmp").exists()


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
