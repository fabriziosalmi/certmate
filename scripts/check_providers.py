#!/usr/bin/env python3
"""Ask the built image whether every provider it offers can actually issue.

The test suite validates the issuance path against mocks. Every test that
touches `check_certbot_plugin_installed` replaces it with a stub returning
True — nine files do — so the one guard standing between a configured provider
and certbot's "unrecognized arguments" is never exercised against reality.

That is how Infomaniak shipped: a strategy, a credentials writer, a factory
entry, a README row, and no plugin in any image ever published. Nothing was
wrong with the code. The plugin simply was not there, and nothing looked.

This looks, inside the artefact rather than in a developer's virtualenv, where
the answer is whatever happens to be installed locally. It needs no test
dependencies and no hand-maintained table of names: the environment says which
distribution provides which certbot plugin, and the requirements files say what
we meant to ship.

    python scripts/check_providers.py [requirements-file]

The argument names the requirements file this image was built from — what it
was meant to carry. It defaults to requirements.txt, which is what the
published image installs; pass requirements-minimal.txt when checking that
variant. Getting this wrong in either direction is the difference between a
missing plugin and an optional one, so it is an explicit input rather than a
guess.

Exits non-zero when a plugin we meant to ship is missing or misnamed. Prints —
without failing — the providers this variant does not carry, which is a
legitimate state for the optional ones.
"""
import pathlib
import re
import sys
from importlib.metadata import distributions

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _normalise(name):
    """PEP 503. `certbot_dns_porkbun` and `certbot-dns-porkbun` are one package.

    The first version of this script normalised the requirements side and not
    the metadata side, so every comparison missed and it reported two perfectly
    working plugins as broken. Same mistake as the entry-point contract test
    made before it — which is why it is one function now, used on both sides.
    """
    return re.sub(r"[-_.]+", "-", name or "").lower()


def _registered():
    """entry-point name -> distribution that provides it, from the environment."""
    owner = {}
    for dist in distributions():
        name = _normalise((dist.metadata or {}).get("Name"))
        for entry in dist.entry_points:
            if entry.group == "certbot.plugins":
                owner[entry.name] = name
    return owner


def _installed_plugin_distributions():
    """Installed distributions whose name marks them as a certbot plugin."""
    found = {}
    for dist in distributions():
        name = (dist.metadata or {}).get("Name") or ""
        if re.match(r"certbot[-_](dns|plugin)[-_]", name, re.I):
            found[_normalise(name)] = dist
    return found


def _pinned_plugin_distributions(requirements):
    """Plugin distributions *this build* pins — what it was meant to carry.

    One file, not every requirements*.txt in the tree. Reading them all made
    `he-ddns` — which lives in requirements-extended.txt — look missing from an
    image that never claimed to carry it.

    Comments are not pins. `certbot-dns-namecheap` appears in requirements.txt
    only inside a comment explaining why it was removed; reading that as an
    intention to ship would fail on a deliberate exclusion.
    """
    pinned = {}
    for path in [REPO_ROOT / requirements]:
        if not path.exists():
            raise SystemExit(f"{path} does not exist — this check cannot tell "
                             f"a missing plugin from an optional one without it")
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"^([A-Za-z0-9_.-]+)==", line.strip())
            if not match:
                continue
            name = _normalise(match.group(1))
            if re.match(r"certbot-(dns|plugin)-", name):
                pinned.setdefault(name, f"{path.name}:{number}")
    return pinned


def _providers():
    """provider key -> the plugin name its strategy will hand to certbot."""
    from modules.core.dns_strategies import DNSStrategyFactory
    from modules.core.utils import _DNS_PROVIDER_CREDENTIALS

    wanted = {}
    for key in sorted(set(DNSStrategyFactory._strategies) | set(_DNS_PROVIDER_CREDENTIALS)):
        try:
            plugin = DNSStrategyFactory.get_strategy(key).plugin_name
        except Exception as error:                       # pragma: no cover
            wanted[key] = f"<{type(error).__name__}>"
            continue
        wanted[key] = plugin
    return wanted


# Providers that reach their DNS API without a certbot plugin. `manual` is the
# marker CertMate's own strategies use for these; acme-dns publishes its TXT
# record through modules/core/dns_alias_hook.py, and http-01 does not use DNS
# at all.
NATIVE = {"manual", "acme-dns", "http-01"}


def main():
    requirements = sys.argv[1] if len(sys.argv) > 1 else "requirements.txt"
    registered = _registered()
    installed = _installed_plugin_distributions()
    pinned = _pinned_plugin_distributions(requirements)
    providers = _providers()

    if not registered:
        print("no certbot plugins are registered at all — this is not a "
              "CertMate image, or certbot is broken", file=sys.stderr)
        return 1
    if not providers:
        print("the strategy factory offers no providers — nothing to check",
              file=sys.stderr)
        return 1

    failures, unshipped, native = [], [], []

    # A distribution we installed that registers nothing is broken packaging:
    # the pin says we wanted it, and certbot cannot see it.
    for name, where in sorted(pinned.items()):
        if name not in installed:
            continue
        if name not in set(registered.values()):
            failures.append(
                f"{name} is pinned ({where}) and installed, but registers no "
                f"certbot plugin — certbot cannot use it")

    # Note on what is NOT a failure: a distribution pinned only in an optional
    # requirements file is not an intention to ship in this image — the default
    # build installs requirements.txt alone. Treating any pin as an intention
    # reported he-ddns, which lives in requirements-extended.txt, as missing
    # from an image that never claimed to carry it.
    for key, plugin in sorted(providers.items()):
        if plugin in NATIVE or plugin.startswith("<"):
            native.append(f"{key} ({plugin})")
            continue
        if plugin in registered:
            continue
        # The plugin is missing. Did we mean to ship it?
        candidate = "certbot-" + plugin
        # Which distribution would provide this plugin? Derived names are not
        # always right — `dns-dynu` comes from certbot-dns-dynudns, `dns-ns1`
        # from certbot-dns-nsone — so the pinned set is searched for one whose
        # name contains the provider key before falling back to the guess.
        owner = next((d for d in pinned if key.replace("-", "") in d.replace("-", "")),
                     candidate)
        if candidate in installed:
            failures.append(
                f"{key}: certbot has no plugin '{plugin}', yet {candidate} is "
                f"installed — the entry point is named something else, so "
                f"issuance fails with 'unrecognized arguments'")
        elif owner in pinned:
            failures.append(
                f"{key}: certbot has no plugin '{plugin}', but {owner} is "
                f"pinned in {requirements} ({pinned[owner]}) — this build was "
                f"meant to carry it. Issuance fails with 'unrecognized "
                f"arguments'.")
        else:
            unshipped.append(f"{key} (plugin '{plugin}' not installed)")

    print(f"providers offered: {len(providers)}   "
          f"certbot plugins registered: {len(registered)}")
    if native:
        print(f"native, no plugin needed ({len(native)}): {', '.join(native)}")
    if unshipped:
        print(f"not carried by this image ({len(unshipped)}):")
        for item in unshipped:
            print(f"  {item}")
    if not failures:
        print("every provider this image claims to carry can reach certbot")
        return 0
    print(f"{len(failures)} problem(s):", file=sys.stderr)
    for failure in failures:
        print(f"  {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
