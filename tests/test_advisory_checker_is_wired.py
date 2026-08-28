"""The advisory checker must exist, something must run it, and it must refuse
to report success when it cannot see.

CertMate holds `cryptography` and `pyopenssl` behind their fixed versions
deliberately: every release that clears the advisories needs a pyOpenSSL that
breaks the pinned ACME stack, and `cryptography==50.0.0` installs cleanly and
then kills `certbot --version`. The decision is recorded in SECURITY.md and
the alert is dismissed as `tolerable_risk` pointing at it.

On 2026-08-21 the record had drifted. SECURITY.md named one advisory,
dismissed months earlier; three more, published 2026-08-03 against the same
pin, were open, unassessed and unmentioned — through a release. The reasoning
in the file was correct and current. It had simply stopped being the complete
list, and nothing looked.

`scripts/check_advisories.py` looks. This file asserts the wiring and the
refusal-to-pass-quietly, not the comparison logic — that was verified by
running it against the pre-fix SECURITY.md, where it exits 1 and names the
three, and against the corrected one, where it exits 0.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_advisories.py"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SECURITY = REPO_ROOT / "SECURITY.md"

pytestmark = [pytest.mark.unit]


def test_the_checker_exists():
    assert SCRIPT.is_file(), f"{SCRIPT} is missing"


def test_a_workflow_runs_it():
    """A checker nothing runs is the shape this repository keeps removing."""
    runners = [path.name for path in WORKFLOWS.glob("*.yml")
               if "check_advisories.py" in path.read_text(encoding="utf-8")]
    assert runners, (
        "no workflow runs scripts/check_advisories.py. The drift it exists to "
        "catch is invisible to the test suite — only a scheduled job can see "
        "the live alert list, so an unwired checker catches nothing."
    )


def test_the_job_can_read_the_alerts():
    """`security-events: read` is what the Dependabot alerts API needs.

    Without it the API answers 403 and the script exits non-zero with a
    message naming the missing scope — loud, but weekly-loud. Asserting the
    permission here turns that into a failure at review time instead.
    """
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    job = ci.split("  advisories:", 1)
    assert len(job) == 2, "the `advisories` job is gone from ci.yml"
    # The job's own block ends at the next top-level job key.
    block = re.split(r"\n  [a-z][a-z0-9-]*:\n", job[1])[0]
    assert "security-events: read" in block, (
        "the advisories job no longer declares `security-events: read`; "
        "listing Dependabot alerts needs it and the job would fail on 403"
    )


def test_it_refuses_to_pass_without_a_token():
    """No token means the check did not run. That must not look like success."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "refusing to report success" in source, (
        "check_advisories.py no longer refuses to run without GITHUB_TOKEN. A "
        "check that returns 0 when it could not look is worse than no check: "
        "it is a green tick over an unread alert list."
    )


def test_a_dismissed_tolerable_risk_still_counts_as_carried():
    """The asymmetry is the whole design and must not be flattened.

    An alert dismissed as `tolerable_risk` IS a decision to keep running with
    a known flaw, so it still has to be written down — GHSA-537c-gmf6-5ccf is
    dismissed and documented, and correctly so. A dismissal for `fixed` or
    `inaccurate` is not that, and is ignored.
    """
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'ACCEPTED_DISMISSALS = {"tolerable_risk"}' in source, (
        "the set of dismissal reasons that still require documentation has "
        "changed; if `tolerable_risk` no longer counts as carried, an accepted "
        "risk can leave SECURITY.md without anything noticing"
    )


def test_security_md_still_has_the_section_the_checker_reads():
    text = SECURITY.read_text(encoding="utf-8")
    assert "Known dependency constraint" in text, (
        "check_advisories.py reads this section; renaming it makes the "
        "checker exit with an explanatory failure rather than pass, but the "
        "rename should be deliberate"
    )
    found = set(re.findall(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", text))
    assert len(found) >= 4, (
        f"SECURITY.md documents {len(found)} advisories; the constraint held "
        f"four as of 2026-08-21. Fewer means an entry was dropped without the "
        f"pin moving."
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
