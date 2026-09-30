#!/usr/bin/env python3
"""Point the Homebrew formula at a published certmate-cli/certmate-sdk release.

    python scripts/bump_homebrew_formula.py <Formula/certmate-cli.rb> <version>

The formula lives in the tap, fabriziosalmi/homebrew-certmate, not in this
repository: a copy here would need an sha256 that only exists once PyPI has
the sdist, so it could never be updated in the same pull request as the
version bump. The clients' release workflow runs this after publishing, waits
for PyPI to list the version (its JSON index lags the upload), rewrites the
cli URL/sha256 and the certmate-sdk resource, and then installs the result
with brew before pushing it.

Other resources are left alone. If a release adds a dependency, the brew
install that follows fails, and nothing broken is pushed.
"""
import json
import re
import sys
import time
import urllib.error
import urllib.request


def sdist(package, version, attempts=30, delay=10):
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    for attempt in range(attempts):
        try:
            # Fixed https://pypi.org URL; package is a constant and version was
            # checked against X.Y.Z in main(), so no other scheme can reach here.
            with urllib.request.urlopen(url, timeout=30) as response:  # nosec B310
                data = json.load(response)
            for artefact in data["urls"]:
                if artefact["packagetype"] == "sdist":
                    return artefact["url"], artefact["digests"]["sha256"]
            raise SystemExit(f"{package} {version} has no sdist on PyPI")
        except urllib.error.HTTPError as error:
            if error.code != 404 or attempt == attempts - 1:
                raise
            time.sleep(delay)
    raise SystemExit(f"{package} {version} never appeared on PyPI")


def bump(text, cli, sdk):
    cli_url, cli_sha = cli
    sdk_url, sdk_sha = sdk
    text, n = re.subn(r'(?m)^(  url ")[^"]+(")', rf'\g<1>{cli_url}\g<2>', text, count=1)
    if n != 1:
        raise SystemExit("formula has no top-level url line")
    text, n = re.subn(r'(?m)^(  sha256 ")[0-9a-f]{64}(")', rf'\g<1>{cli_sha}\g<2>', text, count=1)
    if n != 1:
        raise SystemExit("formula has no top-level sha256 line")
    text, n = re.subn(
        r'(resource "certmate-sdk" do\n\s+url ")[^"]+("\n\s+sha256 ")[0-9a-f]{64}(")',
        rf'\g<1>{sdk_url}\g<2>{sdk_sha}\g<3>', text)
    if n != 1:
        raise SystemExit("formula has no certmate-sdk resource")
    return text


def main():
    path, version = sys.argv[1], sys.argv[2]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"not a release version: {version!r}")
    with open(path, encoding="utf-8") as f:
        before = f.read()
    after = bump(before, sdist("certmate-cli", version), sdist("certmate-sdk", version))
    with open(path, "w", encoding="utf-8") as f:
        f.write(after)
    print(f"certmate-cli formula -> {version} ({'changed' if after != before else 'already current'})")


if __name__ == "__main__":
    main()
