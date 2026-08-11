"""A password longer than 72 bytes must keep working across the bcrypt 5 upgrade.

bcrypt has always ignored everything past the 72nd byte. Up to 4.x it truncated
silently; **5.0.0 raises `ValueError` instead**, and that turns a working login
into a permanent, silent lockout:

  * the stored hash was derived from the truncated form and is still valid;
  * `_verify_password` catches `ValueError` and returns `False`, so the operator
    is told their password is wrong — for ever, with nothing in the logs;
  * `_hash_password` has no such catch, so *setting* a long password would have
    raised out of the request instead.

Neither is hypothetical. Measured before the bump was taken:

    >>> h = bcrypt.hashpw(("a"*100).encode()[:72], bcrypt.gensalt())   # 4.x
    >>> bcrypt.checkpw(("a"*100).encode(), h)                          # 5.0.0
    ValueError: password cannot be longer than 72 bytes

So the truncation is explicit on both sides now, which preserves 4.x behaviour
exactly rather than changing it during a dependency upgrade. These tests are
what keep it that way.
"""
import pathlib
import re

import pytest

from modules.core.auth import _BCRYPT_MAX_BYTES, _bcrypt_input

pytestmark = [pytest.mark.unit]

try:
    import bcrypt
    BCRYPT = True
except ImportError:                                  # pragma: no cover
    BCRYPT = False


def test_the_limit_is_the_one_bcrypt_uses():
    assert _BCRYPT_MAX_BYTES == 72


@pytest.mark.parametrize("password,expected", [
    ("short", 5),
    ("a" * 72, 72),
    ("a" * 73, 72),
    ("a" * 1000, 72),
    # Multi-byte characters: the limit is bytes, not characters, and slicing
    # bytes can land mid-character. What matters is that both sides slice
    # identically — an exception here would be the same lockout by a different
    # route.
    ("é" * 40, 72),
])
def test_the_input_is_capped_at_the_byte_limit(password, expected):
    assert len(_bcrypt_input(password)) == expected


@pytest.mark.skipif(not BCRYPT, reason="bcrypt not installed; scrypt fallback in use")
def test_a_long_password_round_trips():
    """Set and verify, the path a new operator takes."""
    from modules.core.auth import AuthManager
    manager = AuthManager.__new__(AuthManager)
    password = "correct horse battery staple " * 10          # 290 bytes
    stored = AuthManager._hash_password(manager, password)
    assert AuthManager._verify_password(manager, password, stored) is True
    assert AuthManager._verify_password(manager, "something else", stored) is False


@pytest.mark.skipif(not BCRYPT, reason="bcrypt not installed; scrypt fallback in use")
def test_a_hash_written_by_bcrypt_4_still_accepts_its_password():
    """The upgrade case: the hash already on disk, checked by the new library.

    Reproduces what 4.x wrote — `hashpw` on the caller's full password, which
    the library itself truncated — and checks it the way the running code does.
    Without the explicit truncation this raises, and `_verify_password` turns
    the exception into 'wrong password'.
    """
    from modules.core.auth import AuthManager
    manager = AuthManager.__new__(AuthManager)
    password = "x" * 100
    legacy = bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(rounds=4)).decode()

    assert AuthManager._verify_password(manager, password, legacy) is True


def test_neither_side_passes_bcrypt_an_untruncated_password():
    """Read the source, not the library.

    The round-trip above can pass while broken if both sides break together,
    so this checks the thing that must not come back: a bare
    `password.encode()` handed to bcrypt.

    An earlier version of this test asserted that bcrypt *raises* on a long
    password — which tests bcrypt, not CertMate, and duly failed under 4.x
    where it truncates instead. What matters is that our code decides, in the
    same way, on both sides.
    """
    source = (pathlib.Path(__file__).resolve().parent.parent
              / "modules" / "core" / "auth.py").read_text(encoding="utf-8")
    offenders = [
        f"{number}: {line.strip()}"
        for number, line in enumerate(source.splitlines(), 1)
        if re.search(r"bcrypt\.(hashpw|checkpw)\(\s*password\.encode\(\)", line)
    ]
    assert not offenders, (
        "these hand bcrypt the full password instead of _bcrypt_input():\n  "
        + "\n  ".join(offenders)
        + "\nUnder bcrypt 5 that raises, and _verify_password turns the "
          "exception into 'wrong password' — a silent, permanent lockout for "
          "anyone whose password is longer than 72 bytes."
    )
