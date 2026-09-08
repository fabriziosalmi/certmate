#!/usr/bin/env python3
"""Every advisory against a package that actually ships must be written down.

`scripts/check_advisories.py` reconciles SECURITY.md with Dependabot. This one
reconciles it with the image, and the two answer different questions because
they read different things.

**Dependabot reads the manifests.** So does `osv-scanner` run over the
repository. Both then resolve transitive dependencies to the *lowest* version
each constraint admits, which is not what `pip install` produces. Measured
against v2.29.0 on 2026-09-08 — the manifest scan against the resolved set from
inside the published image:

    package     manifest scan says   actually ships
    pyjwt       2.9.0 (7 advisories) 2.13.0 (none)
    requests    2.9.2 (5)            2.34.2 (none)
    pygments    2.9.0 (2)            not installed at all
    idna        3.9.0 (1)            3.19   (none)
    filelock    3.9.1 (2)            3.32.5 (none)
    protobuf    4.25.9 (1)           7.36.1 (none)

Every one of those was a false positive, and an audit had already turned the
pyjwt group into a finding against this repository. Scanning manifests here
produces a list that is loud, wrong in both directions, and impossible to keep
assessed — so nobody assesses it, and a real advisory would land in the middle
of the noise unnoticed.

This script therefore takes a `pip freeze` captured **inside the built image**,
where every version is exact, asks OSV about that, and fails when a package
that ships carries an advisory SECURITY.md does not name. Against the same
image the answer was four advisories, all `cryptography`, all already
documented under "Known dependency constraint".

The OSV API is queried directly rather than through `osv-scanner` so there is
no extra binary to install and pin, and so the network layer can be replaced in
tests. Alias groups matter: OSV returns GHSA, CVE and PYSEC records for the
same flaw, and counting them separately is how "four advisories" becomes
"seven". Records are collapsed by the transitive closure of their aliases.

Usage:
    check_resolved_advisories.py <freeze-file>

where the freeze file comes from the image under test, e.g.

    docker run --rm --entrypoint /opt/venv/bin/pip certmate:scan freeze
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_advisories import documented_advisories  # noqa: E402

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
BATCH = 500

# A freeze line pins exactly. Anything else (an editable install, a URL, a
# bare name) is not a version this check can reason about.
PINNED = re.compile(r"^([A-Za-z0-9._-]+)==([^\s;#]+)")

# Advisory ids come back from OSV and are then interpolated into a URL. They
# are remote data: check the shape before building a request out of one.
ADVISORY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def parse_freeze(text):
    """The (name, version) pairs a `pip freeze` describes.

    Lines that are not exact pins are skipped, and the caller is told how many
    so a freeze that silently stopped pinning cannot read as "nothing to
    scan".
    """
    pinned, skipped = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = PINNED.match(line)
        if match:
            pinned.append((match.group(1), match.group(2)))
        else:
            skipped.append(line)
    return pinned, skipped


def _post(url, payload):
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "User-Agent": "certmate-resolved-advisory-check"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def _get(url):
    request = urllib.request.Request(
        url, headers={"User-Agent": "certmate-resolved-advisory-check"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def query_osv(packages, post=_post, get=_get):
    """Advisory ids per package, with the aliases of each.

    Returns [(name, version, id, frozenset(ids_in_the_same_group))]. The batch
    endpoint answers with ids only, so each distinct id is then fetched once
    for its aliases — currently a handful of requests, not one per package.
    """
    found = []
    for start in range(0, len(packages), BATCH):
        chunk = packages[start:start + BATCH]
        payload = {"queries": [
            {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
            for name, version in chunk]}
        results = post(OSV_QUERYBATCH, payload).get("results", [])
        if len(results) != len(chunk):
            raise SystemExit(
                f"OSV returned {len(results)} results for {len(chunk)} "
                f"queries; refusing to guess which package each belongs to")
        for (name, version), result in zip(chunk, results):
            for vuln in result.get("vulns") or []:
                found.append((name, version, vuln["id"]))

    aliases = {}
    for _, _, vuln_id in found:
        if not ADVISORY_ID.match(vuln_id):
            raise SystemExit(
                f"OSV returned an advisory id this check will not put in a "
                f"URL: {vuln_id!r}")
        if vuln_id not in aliases:
            record = get(OSV_VULN + vuln_id)
            aliases[vuln_id] = frozenset(
                [vuln_id, *(record.get("aliases") or [])])
    return [(n, v, i, aliases[i]) for n, v, i in found]


def group_by_alias(rows):
    """Collapse rows naming the same flaw under different identifier schemes.

    OSV publishes GHSA, CVE and PYSEC records for one advisory and lists them
    as each other's aliases. Counting them apart is how `cryptography`'s four
    advisories present as seven.
    """
    groups = []
    for name, version, vuln_id, ids in rows:
        keys, packages = set(ids), {(name, version)}
        merged = []
        for existing_keys, existing_packages in groups:
            if existing_keys & keys:
                keys |= existing_keys
                packages |= existing_packages
            else:
                merged.append((existing_keys, existing_packages))
        merged.append((keys, packages))
        groups = merged
    return groups


def canonical(ids):
    """The identifier to report a group by: GHSA if there is one, since that
    is what SECURITY.md and Dependabot both speak."""
    ghsa = sorted(i for i in ids if i.startswith("GHSA-"))
    return ghsa[0] if ghsa else sorted(ids)[0]


def undocumented(groups, documented):
    return [(canonical(ids), sorted(ids), sorted(packages))
            for ids, packages in groups
            if not (ids & documented)]


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)

    try:
        with open(argv[1], encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        raise SystemExit(f"cannot read the freeze file ({error}) — this check "
                         f"has lost its subject and must not pass quietly")

    packages, skipped = parse_freeze(text)
    if not packages:
        raise SystemExit(
            "the freeze file pins no packages. That is not a clean image, it "
            "is a broken measurement: check that pip freeze ran inside the "
            "image and that its output was captured.")
    print(f"{len(packages)} pinned package(s) from {argv[1]}")
    if skipped:
        print(f"  {len(skipped)} line(s) not exact pins, not scanned: "
              + ", ".join(skipped[:5]))

    try:
        rows = query_osv(packages)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        raise SystemExit(f"could not reach OSV ({e}) — failing rather than "
                         f"reporting a clean scan nobody performed")

    groups = group_by_alias(rows)
    print(f"{len(rows)} advisory record(s) -> {len(groups)} distinct "
          f"advisory(ies) after merging aliases")

    documented = documented_advisories()
    for ids, packages_hit in sorted(groups, key=lambda g: canonical(g[0])):
        mark = "documented" if ids & documented else "NOT DOCUMENTED"
        names = ", ".join(f"{n}=={v}" for n, v in sorted(packages_hit))
        print(f"  {canonical(ids):24s} {names:32s} {mark}")

    missing = undocumented(groups, documented)
    if missing:
        lines = "\n".join(
            f"  {ghsa}  ({', '.join(f'{n}=={v}' for n, v in packages_hit)})"
            f"\n      also known as: {', '.join(ids)}"
            for ghsa, ids, packages_hit in missing)
        raise SystemExit(
            f"\n{len(missing)} advisory(ies) affect a package that ships in "
            f"the image and are not named in SECURITY.md:\n{lines}\n\n"
            f"Either fix the dependency, or add it to SECURITY.md under "
            f"'Known dependency constraint' with the reachability argument "
            f"and the fix path. An advisory nobody wrote down is "
            f"indistinguishable from one nobody noticed.")

    print(f"\nAll {len(groups)} advisory(ies) against shipped packages are "
          f"documented in SECURITY.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
