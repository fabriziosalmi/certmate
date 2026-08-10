"""The requirements files must agree with each other.

Two defects sat here at once, and both were invisible because nothing installs
these files except the two the image is built from.

**Seven packages were pinned to two different versions.** `requirements.txt`
held `certbot-dns-route53==2.10.0`; `requirements-aws.txt` held `2.11.0`. The
Dockerfile installs extras in a *separate* `pip install`, and advertises the
recipe itself:

    --build-arg EXTRA_REQUIREMENTS="requirements-aws.txt requirements-gcp.txt"

certbot-dns-route53 2.11.0 requires `certbot>=2.11.0`, so pip did the only
thing it could: it upgraded certbot off the pin the whole stack is held at
while #103 is still a plan. Measured, not reasoned about — on Python 3.12,
certbot went 2.10.0 -> 3.3.0, silently, in a build that reported success.

**`requirements-extended.txt` could not be installed at all.** Not layered, not
alone in an empty virtualenv: `certbot-dns-powerdns==0.2.1` requires
`dns-lexicon<=3.5.6` and `certbot-dns-linode` requires `>=3.14.1`.
ResolutionImpossible, every path. `requirements.txt` had already excluded
powerdns for exactly this reason, in a comment; this file reintroduced the
conflict that comment describes avoiding.

The check below is the cheap half — one version per package, offline. The
other half is in CI, which resolves each file for real, because a pin can be
self-consistent and still not exist.
"""
import collections
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _pins():
    """package -> {filename: version}, for every `name==version` line."""
    found = collections.defaultdict(dict)
    for path in sorted(REPO_ROOT.glob("requirements*.txt")):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^([A-Za-z0-9_.-]+)==([\w.]+)", line.strip())
            if match:
                # PEP 503: `certbot_dns_x` and `certbot-dns-x` are one package.
                name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
                found[name][path.name] = match.group(2)
    return found


def test_the_requirements_files_are_being_read():
    """A vacuous pass here would hide every check below it."""
    files = list(REPO_ROOT.glob("requirements*.txt"))
    assert len(files) >= 4, f"only found {[f.name for f in files]}"
    assert len(_pins()) >= 20, (
        f"parsed {len(_pins())} pinned packages out of {len(files)} files — "
        f"the line format has changed and nothing below is checking anything."
    )


def test_no_package_is_pinned_to_two_versions():
    conflicts = {
        pkg: where for pkg, where in _pins().items()
        if len(set(where.values())) > 1
    }
    assert not conflicts, (
        "these packages are pinned to different versions in different "
        "requirements files:\n"
        + "\n".join(
            f"  {pkg}: " + ", ".join(f"{v} in {f}" for f, v in sorted(w.items()))
            for pkg, w in sorted(conflicts.items())
        )
        + "\nThe Dockerfile layers extras in a separate `pip install`, so the "
          "higher pin wins and drags its dependencies with it. That is how "
          "certbot moved from 2.10.0 to 3.3.0 in a build that said it "
          "succeeded."
    )


def test_certbot_stays_on_its_pin_everywhere():
    """Nothing may require a certbot newer than the one that is pinned."""
    pins = _pins()
    certbot = pins.get("certbot")
    assert certbot, "certbot is no longer pinned in any requirements file"
    versions = set(certbot.values())
    assert len(versions) == 1, f"certbot pinned to {versions}"
    pinned = versions.pop()

    # Every certbot-dns-* plugin from the same upstream release train carries
    # `certbot>={its own version}`. So a plugin pinned above the certbot pin
    # forces an upgrade, without saying so anywhere.
    def _key(version):
        return tuple(int(part) for part in re.findall(r"\d+", version)[:3])

    # Anything above the pin, regardless of major. The first version of this
    # check required the majors to match — so `certbot-dns-route53==4.1.1`
    # against `certbot==2.10.0` was skipped entirely, which is the exact number
    # the install docs had drifted to and the exact case this test exists for
    # (Copilot, #533). A guard that steps aside for the biggest version of the
    # problem is not a guard.
    #
    # A handful of plugins version independently (vultr 1.1.0, gandi 1.6.1,
    # powerdns 0.2.1, hetzner 2.0.1) — all of them below the certbot pin, so
    # none needs an exception. If one legitimately goes above it, add it here
    # with the evidence, rather than widening the rule until it stops catching
    # anything.
    checked = 0
    offenders = []
    for pkg, where in pins.items():
        if not pkg.startswith("certbot-dns-"):
            continue
        for filename, version in where.items():
            checked += 1
            if _key(version) > _key(pinned):
                offenders.append(f"{filename}: {pkg}=={version} > certbot=={pinned}")
    assert checked >= 10, (
        f"only {checked} plugin pins examined — the parser is not seeing the "
        f"requirements files, so this test would pass over nothing."
    )
    assert not offenders, (
        "these plugins are pinned above the certbot pin and require "
        "`certbot>=` their own version, so installing them upgrades certbot:\n  "
        + "\n  ".join(sorted(offenders))
    )


@pytest.mark.parametrize("filename", sorted(
    p.name for p in REPO_ROOT.glob("requirements*.txt")))
def test_powerdns_is_not_bundled_with_lexicon_hungry_plugins(filename):
    """The pair that made `requirements-extended.txt` unusable.

    Named explicitly rather than left to the CI resolve step, because this one
    has now been reintroduced once after being fixed and documented.
    """
    text = (REPO_ROOT / filename).read_text(encoding="utf-8")
    declared = {
        re.sub(r"[-_.]+", "-", m.group(1)).lower()
        for m in re.finditer(r"^([A-Za-z0-9_.-]+)==", text, re.M)
    }
    if "certbot-dns-powerdns" not in declared:
        return
    # dns-lexicon<=3.5.6 (powerdns) against dns-lexicon>=3.14.1 (these).
    incompatible = sorted(declared & {
        "certbot-dns-linode", "certbot-dns-ovh", "certbot-dns-rfc2136",
        "certbot-dns-dnsmadeeasy", "certbot-dns-nsone",
    })
    assert not incompatible, (
        f"{filename} pins certbot-dns-powerdns (dns-lexicon<=3.5.6) alongside "
        f"{incompatible} (dns-lexicon>=3.14.1). pip cannot satisfy both: the "
        f"file will not install at all, in any environment. Install powerdns "
        f"separately, as requirements.txt already says."
    )
