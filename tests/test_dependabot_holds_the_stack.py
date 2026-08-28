"""A pin the code holds on purpose must be one Dependabot will not reopen.

The ignore list named `certbot`, `josepy` and `acme` — the three obvious ones —
and blocked `certbot-dns-*` at MAJOR only, on the reasoning that minor and
patch fixes are compatible. They are not. Every plugin from certbot's own
release train carries `certbot>=` its own version, so a minor bump drags certbot
off the pin exactly as a major would:

    certbot-dns-route53  2.10.0 -> 2.11.0   requires certbot>=2.11.0
    certbot-dns-azure    2.5.0  -> 2.6.1    requires certbot>=3.0,<4.0

Both minor. The second is the bump `requirements-azure.txt` already documents
as breaking the install — and an open Dependabot PR proposed it. The first is
how `requirements-aws.txt` came to hold 2.11.0 against a 2.10.0 base, which
moved certbot to 3.3.0 in a build that reported success.

Worse, the list left out the pins that actually hold the stack together:
`pyopenssl` (26.2.0+ removes `OpenSSL.crypto.X509Extension`, which `acme`
evaluates at import), `cryptography` (48.0.1 requires that pyopenssl, i.e. the
same crash by another route) and `dns-lexicon`. Nothing stopped a bump to any
of them.

So this checks both directions: every package the requirements files document
as held is ignored by Dependabot, and every ignore entry still corresponds to a
real, documented pin. A list nobody can verify is how this one drifted.
"""
import pathlib
import re

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"

pytestmark = [pytest.mark.unit]

# Packages held deliberately. The value is a phrase that must appear in a
# requirements file near that pin — so an entry here cannot be a guess, and if
# the reason is ever deleted from the requirements this test says so.
HELD = {
    "certbot": "Certificate management",
    "josepy": "josepy",
    "pyopenssl": "Do not bump to 26.2.0+",
    # Not a GHSA id any more. This entry used to be "GHSA-537c-gmf6-5ccf",
    # and the requirements comment named that one advisory — which is how the
    # record drifted: three more were published on 2026-08-03 against the same
    # pin and the comment still named the first. The list of advisories now
    # lives in exactly one place (SECURITY.md, checked weekly against the live
    # alerts by scripts/check_advisories.py), and what has to sit next to the
    # pin is the pointer to it. A pointer does not go stale when an advisory
    # arrives; an enumeration does.
    "cryptography": 'SECURITY.md "Known dependency constraint"',
    "dns-lexicon": "dns-lexicon",
    "cloudflare": "#568",
}

# Ignored defensively rather than held: `acme` is not pinned anywhere — it
# arrives as certbot's own dependency — but an entry costs nothing and stops a
# future direct pin from being bumped past the stack the moment it is added.
# Kept separate from HELD so the "still pinned" check does not fail on it, and
# so nobody reads it as a pin that exists.
DEFENSIVE = {"acme"}

# Wildcards cover a family; each needs at least one pinned member to be real.
HELD_FAMILIES = {
    "certbot-dns-*": "certbot-dns-",
    "certbot-plugin-*": "certbot-plugin-",
}


def _pip_configs():
    config = yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))
    pip = [u for u in config["updates"] if u["package-ecosystem"] == "pip"]
    assert pip, "dependabot.yml no longer configures the pip ecosystem"
    return pip


def _pip_ignore(config):
    return {
        entry["dependency-name"]: entry.get("update-types")
        for entry in config.get("ignore", [])
    }


def _directory(config):
    """A pip block can target one directory or several."""
    return config.get("directory") or ", ".join(config.get("directories", ["?"]))


def _requirements_text():
    return "".join(
        path.read_text(encoding="utf-8")
        for path in sorted(REPO_ROOT.glob("requirements*.txt"))
    )


def _reason_near_pin(package, evidence, window=4):
    """Is `evidence` written within `window` lines of `package`'s pin?

    The first version of this asked whether the phrase appeared anywhere in the
    concatenated requirements files, which is false confidence of the exact
    kind this suite exists to remove: the reason for pyopenssl could have been
    sitting next to cryptography, in another file, and the check would have
    been satisfied (Copilot, #541). Proximity in the same file is what makes it
    a reason *for that pin*.
    """
    for path in sorted(REPO_ROOT.glob("requirements*.txt")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if not re.match(rf"^{re.escape(package)}==", line, re.I):
                continue
            near = lines[max(0, number - window):number + window + 1]
            if any(evidence in candidate for candidate in near):
                return True
    return False


def test_the_config_is_being_read():
    for config in _pip_configs():
        ignore = _pip_ignore(config)
        assert len(ignore) >= 5, (
            f"the pip block for {_directory(config)} has {len(ignore)} ignore "
            f"entries — the config shape changed and every check below would "
            f"pass over nothing."
        )


@pytest.mark.parametrize("package", sorted(HELD))
def test_every_held_package_is_ignored_entirely(package):
    # Every pip block, not just the first. A second one — for another
    # directory, say — would otherwise be completely unconstrained while this
    # test went on passing against the first (Copilot, #541).
    for config in _pip_configs():
        _assert_held(package, config)


def _assert_held(package, config):
    ignore = _pip_ignore(config)
    assert package in ignore, (
        f"{package} is pinned deliberately but Dependabot is free to propose "
        f"bumps for it in the {_directory(config)} block. Add it to the "
        f"ignore list in .github/dependabot.yml."
    )
    assert ignore[package] is None, (
        f"{package} is ignored only for {ignore[package]}. A narrower rule is "
        f"how `certbot-dns-*` stayed open to minor bumps that carry "
        f"`certbot>=` their own version — the exact drift this file exists to "
        f"prevent. Ignore all updates."
    )


@pytest.mark.parametrize("pattern", sorted(HELD_FAMILIES))
def test_every_held_family_is_ignored_entirely(pattern):
    for config in _pip_configs():
        _assert_family_held(pattern, config)


def _assert_family_held(pattern, config):
    ignore = _pip_ignore(config)
    assert pattern in ignore, (
        f"{pattern} is not ignored in the {_directory(config)} block")
    assert ignore[pattern] is None, (
        f"{pattern} is ignored only for {ignore[pattern]}. Minor and patch "
        f"bumps of these plugins require a newer certbot — measured: "
        f"certbot-dns-route53 2.11.0 needs certbot>=2.11.0, certbot-dns-azure "
        f"2.6.1 needs certbot>=3.0."
    )


@pytest.mark.parametrize("package,evidence", sorted(HELD.items()))
def test_every_held_package_is_still_pinned_and_explained(package, evidence):
    """An ignore entry for something we no longer pin is a stale exception."""
    text = _requirements_text()
    assert re.search(rf"^{re.escape(package)}==", text, re.M | re.I), (
        f"{package} is on the hold list but is no longer pinned in any "
        f"requirements file. Remove the hold or restore the pin."
    )
    assert _reason_near_pin(package, evidence), (
        f"{package} is held, but the reason ({evidence!r}) is not written "
        f"within a few lines of its pin in any requirements file. A hold whose "
        f"reason has been deleted — or which borrowed another package's — is a "
        f"hold nobody can review."
    )


@pytest.mark.parametrize("pattern,prefix", sorted(HELD_FAMILIES.items()))
def test_every_held_family_has_at_least_one_member(pattern, prefix):
    text = _requirements_text()
    members = set(re.findall(rf"^({re.escape(prefix)}[\w.-]+)==", text, re.M))
    assert members, (
        f"{pattern} is ignored by Dependabot but no package matching it is "
        f"pinned anywhere. The rule protects nothing."
    )


@pytest.mark.parametrize("package", sorted(DEFENSIVE))
def test_a_defensive_entry_really_is_unpinned(package):
    """If it acquires a direct pin, it stops being defensive and becomes held.

    Which means it needs a documented reason like everything else in HELD —
    this check is what forces that move rather than letting the entry quietly
    change meaning.
    """
    assert not re.search(rf"^{re.escape(package)}==", _requirements_text(), re.M | re.I), (
        f"{package} is now pinned directly. Move it from DEFENSIVE to HELD "
        f"with the reason written next to the pin."
    )


def test_no_ignore_entry_is_unexplained():
    """The other direction: everything ignored must be something we hold."""
    known = set(HELD) | set(HELD_FAMILIES) | DEFENSIVE
    seen = set()
    for config in _pip_configs():
        seen |= set(_pip_ignore(config))
    unexplained = sorted(seen - known)
    assert not unexplained, (
        f"these are ignored by Dependabot but are not on the hold list: "
        f"{unexplained}. Either record why they are held — with the reason in "
        f"the requirements file — or let Dependabot update them. Silently "
        f"frozen dependencies are how a CVE goes unnoticed."
    )
