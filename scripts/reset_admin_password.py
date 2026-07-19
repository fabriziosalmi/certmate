#!/usr/bin/env python3
"""
Emergency admin password reset for CertMate.

Usage (inside the container):
    python scripts/reset_admin_password.py

You will be prompted for the new password. The script reads
/app/data/settings.json and overwrites the "admin" user's
password_hash in-place. It preserves every other key in the
file, including domains, DNS providers, and API keys.

If you have lost access to CertMate after a downgrade or wizard
reset, restore the latest backup first, then run this script.
"""
import json
import os
from getpass import getpass
from pathlib import Path

# bcrypt may not be installed in the host venv; try to provide a
# minimal shim if it's missing, but in the container it is present.
try:
    import bcrypt
except ModuleNotFoundError:  # pragma: no cover
    raise SystemExit(
        "bcrypt is required. Install it or run this script inside the "
        "CertMate container where it is already available."
    )

DEFAULT_SETTINGS_PATH = Path("/app/data/settings.json")


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def main() -> int:
    settings_path = Path(os.getenv("CERTMATE_SETTINGS_PATH", DEFAULT_SETTINGS_PATH))
    if not settings_path.exists():
        print(f"ERROR: settings file not found at {settings_path}")
        return 1

    try:
        with settings_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"ERROR: {settings_path} is not valid JSON: {exc}")
        return 1

    if not isinstance(data, dict):
        print(f"ERROR: {settings_path} top-level value is not an object.")
        return 1

    # setdefault, NOT get: on a fresh install settings.json has no "users"
    # key at all, and a plain get() hands back an orphan dict that never
    # lands in the file — the script then reports success while writing no
    # user at all (issue #383).
    users = data.setdefault("users", {})
    if not isinstance(users, dict):
        print("WARNING: 'users' key is not a dict; replacing with empty dict.")
        users = {}
        data["users"] = users

    if "admin" not in users:
        print("WARNING: no 'admin' user exists; creating one.")

    print("=" * 60)
    print("CertMate Emergency Admin Password Reset")
    print("=" * 60)
    print(f"Settings file: {settings_path}")
    print(f"Users present: {list(users.keys()) or '(none)'}")
    print()

    password = getpass("New admin password: ")
    if not password:
        print("ERROR: password cannot be empty.")
        return 1
    if len(password) < 12:
        print("WARNING: password is shorter than 12 characters.")
        confirm = input("Continue anyway? [y/N] ").strip().lower()
        if confirm != "y":
            return 1

    confirm_pw = getpass("Confirm password: ")
    if password != confirm_pw:
        print("ERROR: passwords do not match.")
        return 1

    # Ensure user record has required shape
    admin_user = users.setdefault("admin", {})
    admin_user["password_hash"] = _hash_password(password)
    admin_user.setdefault("role", "admin")
    admin_user.setdefault("enabled", True)
    if "created_at" not in admin_user:
        import datetime
        admin_user["created_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Without this, login still returns 403 "Local auth disabled" even though
    # the admin user now exists (issue #397): local_auth_enabled defaults to
    # False. Enabling it reproduces the exact end-state the setup wizard
    # reaches. The change is monotonic — writing a user AND local_auth=True
    # only ever drives is_setup_mode() False, never into the world-open bypass.
    data["local_auth_enabled"] = True

    # Preserve a pre-write backup of the original file
    backup_path = settings_path.with_suffix(".json.reset_backup")
    try:
        backup_path.write_bytes(settings_path.read_bytes())
        os.chmod(backup_path, 0o600)  # the backup mirrors settings.json's secrets
        print(f"Original settings backed up to: {backup_path}")
    except OSError as exc:
        print(f"WARNING: could not create backup: {exc}")

    # Atomic write: dump to a temp file in the same directory, then os.replace
    # onto settings.json so an interruption can't leave a truncated/corrupt
    # file. This path is the recovery escape hatch, so its robustness matters.
    tmp_path = settings_path.with_suffix(".json.reset_tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        # settings.json holds password/token/API-key hashes and DNS creds and
        # is kept 0600 by the app. os.replace transfers the temp file's mode
        # onto the target, so tighten the temp to 0600 BEFORE the swap —
        # otherwise the umask default (typically 0644) would make the reset
        # file, and every secret in it, world-readable to other local users.
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, settings_path)
    except OSError as exc:
        print(f"ERROR: failed to write settings: {exc}")
        try:
            tmp_path.unlink(missing_ok=True)  # don't leave a 0600 partial behind
        except OSError:
            pass
        return 1

    print(f"Admin password reset successfully in {settings_path}")
    print("Restart CertMate (or the container) if the process is running.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
