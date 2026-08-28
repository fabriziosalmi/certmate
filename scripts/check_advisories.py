#!/usr/bin/env python3
"""Every dependency advisory we are living with must be written down.

CertMate holds `cryptography` and `pyopenssl` behind their fixed versions on
purpose: every release that clears the advisories needs a pyOpenSSL that
breaks the pinned ACME stack, and `cryptography==50.0.0` installs cleanly and
then kills `certbot --version`. That decision is recorded in SECURITY.md under
"Known dependency constraint", and the Dependabot alert is dismissed as
`tolerable_risk` pointing at it. Two steps, and the pair is the whole record.

On 2026-08-21 the record had drifted. SECURITY.md documented one advisory,
GHSA-537c-gmf6-5ccf, which had been dismissed months earlier. Three more had
been published on 2026-08-03 against the same pin and were sitting open,
undocumented, unassessed and unmentioned — through a release. Nothing was
wrong with the reasoning in SECURITY.md; it had simply stopped being the
complete list, and nothing looked.

A test cannot see live alerts, so this is a scheduled job rather than a gate
on the merge. It asks the repository which advisories it is actually carrying
and fails when one of them is missing from the file that claims to enumerate
them.

    GITHUB_TOKEN=... python scripts/check_advisories.py [owner/repo]

The rule is deliberately asymmetric:

  * An alert that is OPEN, or dismissed as `tolerable_risk`, MUST appear in
    SECURITY.md. Both are decisions to keep running with a known flaw, and a
    decision nobody wrote down is indistinguishable from an oversight.
  * An advisory documented in SECURITY.md but no longer alerting is NOT a
    failure. That is the normal end state of a dismissal: GHSA-537c-gmf6-5ccf
    is dismissed and still documented, correctly — the history of why a pin
    exists outlives the alert.
  * Alerts dismissed as `fixed`, `inaccurate`, `not_used` or `no_bandwidth`
    are ignored: those are not "we are living with this".
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO_DEFAULT = "fabriziosalmi/certmate"
SECURITY_MD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "SECURITY.md")
# A dismissal that means "we accept this and keep running" — the only kind
# that still needs the reasoning written down.
ACCEPTED_DISMISSALS = {"tolerable_risk"}


def documented_advisories():
    """Every GHSA id named in SECURITY.md."""
    try:
        with open(SECURITY_MD, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        raise SystemExit(f"cannot read SECURITY.md ({error}) — this check has "
                         f"lost its subject and must not pass quietly")
    if "Known dependency constraint" not in text:
        raise SystemExit(
            "SECURITY.md no longer has a 'Known dependency constraint' "
            "section. If the constraint is gone the pins should have moved "
            "with it; if it was renamed, this script needs renaming too.")
    return set(re.findall(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", text))


def carried_advisories(repo, token):
    """Advisories the repository is living with: open, or accepted as tolerable.

    Returns {ghsa_id: (severity, state, package)}.

    The alerts endpoint paginates by CURSOR, not by page number: passing
    `?page=2` is answered with `400 Pagination using the 'page' parameter is
    not supported`. The next page is the `rel="next"` URL in the Link header,
    and following it is the only way to see the tail on a repository with more
    than one page of alerts.
    """
    carried = {}
    url = (f"https://api.github.com/repos/{repo}/dependabot/alerts"
           f"?per_page=100")
    while url:
        request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "certmate-advisory-check"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                batch = json.loads(response.read().decode("utf-8"))
                link = response.headers.get("Link", "")
        except urllib.error.HTTPError as error:
            if error.code in (403, 404):
                raise SystemExit(
                    f"the Dependabot alerts API answered {error.code}. The "
                    f"token needs `security-events: read` on {repo}; without "
                    f"it this check cannot see what it is meant to check, and "
                    f"passing would be worse than failing.")
            raise
        for alert in batch:
            state = alert.get("state")
            if state == "open" or (state == "dismissed"
                                   and alert.get("dismissed_reason") in ACCEPTED_DISMISSALS):
                advisory = alert.get("security_advisory") or {}
                ghsa = advisory.get("ghsa_id")
                if ghsa:
                    package = ((alert.get("dependency") or {}).get("package") or {}).get("name", "?")
                    carried[ghsa] = (advisory.get("severity", "?"), state, package)
        following = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = following.group(1) if following else None
    return carried


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else REPO_DEFAULT
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN is not set; refusing to report success "
                         "on a check that never ran")

    documented = documented_advisories()
    carried = carried_advisories(repo, token)
    undocumented = {g: v for g, v in carried.items() if g not in documented}

    print(f"advisories carried by {repo}: {len(carried)}   "
          f"documented in SECURITY.md: {len(documented)}")
    for ghsa, (severity, state, package) in sorted(carried.items()):
        mark = "ok " if ghsa in documented else ">>>"
        print(f"  {mark} {severity.upper():8} {ghsa}  {package}  ({state})")

    if not undocumented:
        print("every advisory this repository carries is written down")
        return 0

    print(f"\n{len(undocumented)} advisory/advisories are being carried with no "
          f"entry in SECURITY.md:", file=sys.stderr)
    for ghsa, (severity, state, package) in sorted(undocumented.items()):
        print(f"  {severity.upper()} {ghsa} ({package}, {state})", file=sys.stderr)
    print("\nAdd them to the 'Known dependency constraint' section with their "
          "reachability, or fix the dependency. An accepted risk that is not "
          "written down cannot be told apart from one nobody noticed — which "
          "is exactly what happened on 2026-08-21.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
