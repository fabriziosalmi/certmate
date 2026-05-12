#!/usr/bin/env python3
"""
CertMate password reset tool — uses CertMate's own auth module directly.

Must be run from the CertMate root directory (where 'modules/' lives), or
pass --certmate-root to point at it.

Usage:
    cd /app/data
    python3 reset_password.py --settings settings.json --username admin

    # Dry-run (print hash, don't write):
    python3 reset_password.py --settings settings.json --username admin --dry-run
"""

import sys
import json
import getpass
import argparse
import shutil
from pathlib import Path
from datetime import datetime, timezone


def load_auth_manager(certmate_root: Path):
    """
    Import CertMate's AuthManager exactly as the app does, using a minimal
    stub SettingsManager so we don't need Flask or the full app stack.
    """
    root_str = str(certmate_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

    try:
        from modules.core.auth import AuthManager
    except ImportError as e:
        print(f"ERROR: Could not import modules.core.auth: {e}")
        print(f"       Make sure --certmate-root points to the CertMate project root")
        print(f"       (the directory that contains the 'modules/' folder).")
        sys.exit(1)

    # Minimal stub — AuthManager only needs load_settings() and update()
    # for password hashing/verification; we handle the file write ourselves.
    class StubSettingsManager:
        def load_settings(self):
            return {}
        def update(self, fn, label=None):
            return True

    auth = AuthManager(StubSettingsManager())
    print(f"✅  Loaded AuthManager from: {certmate_root / 'modules' / 'core' / 'auth.py'}")
    return auth


def main():
    parser = argparse.ArgumentParser(
        description="Reset a CertMate user password using CertMate's own auth module"
    )
    parser.add_argument("--settings", required=True, help="Path to settings.json")
    parser.add_argument("--username", required=True,
                        help="Username to reset (e.g. admin or ben@voice1.me)")
    parser.add_argument("--certmate-root", default=".",
                        help="CertMate project root directory (default: current directory)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the new hash but do NOT write to settings.json")
    args = parser.parse_args()

    certmate_root = Path(args.certmate_root).resolve()
    settings_path = Path(args.settings).resolve()

    if not settings_path.exists():
        print(f"ERROR: settings file not found: {settings_path}")
        sys.exit(1)

    # ── Load CertMate's own AuthManager ──────────────────────────────────────
    auth = load_auth_manager(certmate_root)

    # ── Load settings ─────────────────────────────────────────────────────────
    with open(settings_path) as f:
        settings = json.load(f)

    users = settings.get('users', {})
    if args.username not in users:
        print(f"ERROR: user {args.username!r} not found in settings.json.")
        print(f"Known users: {list(users.keys())}")
        sys.exit(1)

    print(f"Found user: [{args.username}]  role={users[args.username].get('role')}  "
          f"enabled={users[args.username].get('enabled')}")

    # ── Get new password (confirmed) ──────────────────────────────────────────
    while True:
        pw1 = getpass.getpass(f"\nNew password for [{args.username}]: ")
        if not pw1:
            print("Password cannot be empty. Try again.")
            continue
        pw2 = getpass.getpass("Confirm new password: ")
        if pw1 != pw2:
            print("Passwords do not match. Try again.")
            continue
        break

    # ── Hash via CertMate's own method ────────────────────────────────────────
    new_hash = auth._hash_password(pw1)
    hash_type = "bcrypt" if new_hash.startswith('$2') else "sha256"
    print(f"\nGenerated {hash_type} hash: {new_hash}")

    # ── Self-verify before touching the file ──────────────────────────────────
    if not auth._verify_password(pw1, new_hash):
        print("\nERROR: Self-verification of the new hash failed. Not writing anything.")
        sys.exit(1)
    print("Self-verification: ✅  hash round-trips correctly.")

    if args.dry_run:
        print("\n--dry-run: settings.json was NOT modified.")
        print("To apply, re-run without --dry-run.")
        sys.exit(0)

    # ── Back up settings.json ─────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = settings_path.with_suffix(f".backup_{ts}.json")
    shutil.copy2(settings_path, backup_path)
    print(f"Backup written to: {backup_path}")

    # ── Write updated settings ────────────────────────────────────────────────
    old_hash = users[args.username].get('password_hash', '(none)')
    settings['users'][args.username]['password_hash'] = new_hash

    with open(settings_path, 'w') as f:
        json.dump(settings, f, indent=2)

    print(f"\n✅  Password reset complete for [{args.username}].")
    print(f"    Old hash: {old_hash[:20]}…")
    print(f"    New hash: {new_hash[:20]}…")
    print(f"\nRestart CertMate in case it caches settings in memory.")


if __name__ == "__main__":
    main()
