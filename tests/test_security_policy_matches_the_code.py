"""SECURITY.md names a specific control. The control must actually do that.

The policy's deploy-hook section is unusually concrete, and that is what makes
it checkable:

    Hook commands are validated to reject shell metacharacters and references
    to CertMate's own infrastructure secrets (`settings.json`,
    `api_bearer_token`, `client_secret`, `vault_token`, `.env`). ... The issued
    certificate's own private key (`privkey.pem`) is deliberately **not**
    blocked, because installing it is the normal job of a deploy hook.

Five strings a researcher is told are rejected, and one they are told is
allowed on purpose. Nothing tied any of it to `DeployManager._is_command_safe`,
so dropping `vault_token` from the regex — or adding `privkey.pem` to it, which
would break every working deploy hook — would leave the security policy stating
something false, silently, in the document people read before deciding whether
to report a vulnerability.

The list below is parsed out of SECURITY.md rather than copied here, so the
document stays the source and the two cannot drift apart while both look right.
"""
import pathlib
import re

import pytest

from modules.core.deployer import DeployManager

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SECURITY = REPO_ROOT / "SECURITY.md"

pytestmark = [pytest.mark.unit]


def _blocked_names():
    """The secrets SECURITY.md says hook commands may not reference."""
    text = SECURITY.read_text(encoding="utf-8")
    # Whitespace-flexible: the sentence wraps, and "infrastructure secrets" is
    # split across two lines. A regex with a literal space there matched
    # nothing and made this file abort at collection — a check that cannot
    # read its own subject.
    match = re.search(
        r"references\s+to\s+CertMate's\s+own\s+infrastructure\s+secrets"
        r"\s*\(([^)]+)\)",
        text, re.S)
    assert match, (
        "SECURITY.md no longer states which files a deploy hook may not "
        "reference. Either the wording changed and this test needs to follow "
        "it, or the claim is gone — in which case so should the control."
    )
    return re.findall(r"`([^`]+)`", match.group(1))


def _allowed_name():
    """The one SECURITY.md says is deliberately not blocked."""
    text = SECURITY.read_text(encoding="utf-8")
    match = re.search(
        r"private\s+key\s*\(`([^`]+)`\)\s*is\s+deliberately\s+"
        r"\*\*not\*\*\s+blocked",
        text, re.S)
    assert match, (
        "SECURITY.md no longer states that the certificate's own private key "
        "is allowed in a hook. That sentence exists because blocking it would "
        "break every working deploy hook."
    )
    return match.group(1)


# Parsed once, at import. If SECURITY.md's wording changes the assertion inside
# _blocked_names() would fire during collection, which pytest reports as a
# collection error rather than as a failing test — the message says exactly
# what happened, but it aborts the whole file instead of failing one check
# (Copilot, #556). Held as a value so the parametrisation below sees a list
# either way, and the dedicated test reports the parse failure on its own.
try:
    BLOCKED_NAMES = _blocked_names()
    PARSE_ERROR = None
except AssertionError as error:            # pragma: no cover - the failure path
    BLOCKED_NAMES, PARSE_ERROR = [], str(error)


def test_the_policy_still_names_a_list():
    assert PARSE_ERROR is None, PARSE_ERROR
    names = BLOCKED_NAMES
    assert len(names) >= 5, (
        f"parsed {names} out of SECURITY.md — fewer than the five it has "
        f"always named, so this test would be checking less than it claims."
    )


@pytest.mark.parametrize("name", BLOCKED_NAMES)
def test_every_secret_the_policy_names_is_actually_rejected(name):
    safe, reason = DeployManager._is_command_safe(f"cat /app/data/{name}")
    assert safe is False, (
        f"SECURITY.md tells researchers that a deploy hook referencing "
        f"`{name}` is rejected. It is not: the validator accepted it. Either "
        f"restore the rule or stop claiming it."
    )
    assert "sensitive" in (reason or ""), (
        f"`{name}` was rejected, but for {reason!r} rather than as a sensitive "
        f"file — the claim in SECURITY.md is about that specific control."
    )


def test_the_private_key_stays_allowed():
    """Blocking it would break every working deploy hook, quietly."""
    name = _allowed_name()
    safe, reason = DeployManager._is_command_safe(
        f"cp /app/certificates/example.com/{name} /etc/ssl/private/")
    assert safe is True, (
        f"SECURITY.md says `{name}` is deliberately not blocked, because "
        f"installing it is the normal job of a deploy hook. The validator "
        f"rejected it: {reason!r}. Every operator's certificate deployment "
        f"stops working, and the policy says it should not."
    )


def test_the_metacharacter_claim_holds():
    """The other half of the same sentence.

    Named separately from the file list because it is a different rule in the
    validator, and a change to one has no reason to touch the other.
    """
    for command in ("echo hi && rm -rf /", "echo `whoami`", "echo $(id)",
                    "echo hi; rm -rf /", "eval rm -rf /"):
        safe, reason = DeployManager._is_command_safe(command)
        assert safe is False, (
            f"SECURITY.md says hook commands are validated to reject shell "
            f"metacharacters. {command!r} was accepted."
        )
        assert "metacharacter" in (reason or ""), (
            f"{command!r} was rejected for {reason!r}, not as a metacharacter."
        )


def test_the_supported_line_is_the_one_we_ship():
    """A researcher decides whether to report based on this table."""
    version = re.search(
        r"__version__ = '([\d.]+)'",
        (REPO_ROOT / "modules" / "__init__.py").read_text(encoding="utf-8"))
    assert version, "cannot read the current version"
    minor = ".".join(version.group(1).split(".")[:2])
    text = SECURITY.read_text(encoding="utf-8")
    assert re.search(rf"`{re.escape(minor)}\.x`\s*\|\s*Yes", text), (
        f"SECURITY.md does not list `{minor}.x` as supported, but that is the "
        f"line currently shipping."
    )
