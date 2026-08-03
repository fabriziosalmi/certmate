"""Static guards for three frontend defects that a green CI could not see.

These are source-level assertions in the style of tests/test_static_csp.py.
The behaviours they protect are only fully exercised by the Playwright suite
(which needs a running container), but each defect below was a *missing line*
rather than a subtle interaction — a missing listener, a missing fallback, a
missing guard — so pinning the line is what actually stops the regression.

- #424 the SSO tab rendered the blank default form when its GET failed, and
  Save then wrote those defaults over a working configuration.
- #425 the command palette navigated to '/settings#<tab>' by assigning
  location.href; a fragment-only change does not reload, and the pages read
  location.hash exactly once, so choosing a tab you were already on did
  nothing at all.
- #427 the one-time API-key token was copied with navigator.clipboard only,
  which is undefined over plain HTTP — a silent no-op on a token shown once.
"""

import re
from pathlib import Path

import pytest


pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent


def _js_function_body(source, name):
    """Return the body of ``function <name>(...) { ... }`` by matching braces.

    Slicing to a hard-coded closing-brace string (``"\\n    }"``) made these
    guards depend on the current indentation, so a pure reformat could fail a
    test whose behaviour was still correct. Counting braces from the function's
    opening one is indentation-agnostic; only genuinely removing the code the
    assertions look for turns them red.
    """
    match = re.search(r"function\s+%s\s*\([^)]*\)\s*\{" % re.escape(name), source)
    assert match, f"function {name} not found — was it renamed?"
    depth, start = 0, match.end() - 1
    for index in range(start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unbalanced braces while reading {name}")


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# --- #424 ------------------------------------------------------------------

def test_the_sso_form_is_hidden_when_its_config_failed_to_load():
    html = _read("templates/partials/settings_oidc.html")
    assert 'x-if="!loading && loadFailed"' in html, "no failure state rendered"
    assert 'x-if="!loading && !loadFailed"' in html, \
        "the form still renders on a failed load — Save would wipe the config"


def test_the_sso_loader_records_the_failure_instead_of_falling_back_to_defaults():
    js = _read("static/js/settings-oidc.js")
    assert "loadFailed: false" in js
    assert "self.loadFailed = true;" in js, \
        "the catch branch leaves cfg at defaultCfg() with the form visible"


# --- #425 ------------------------------------------------------------------

@pytest.mark.parametrize("template,state", [
    ("templates/settings.html", "tab"),
    ("templates/index.html", "certView"),
])
def test_pages_react_to_a_hash_change(template, state):
    html = _read(template)
    assert "hashchange" in html, f"{template} reads the hash once and never again"
    assert state in html


def test_the_palette_does_not_navigate_by_bare_href_assignment():
    js = _read("static/js/cmd-palette.js")
    assert "navigateTo(item.url)" in js
    assert "window.location.href = item.url" not in js, \
        "fragment-only navigation silently does nothing on the same page"


def test_the_palette_navigator_handles_the_same_page_case():
    js = _read("static/js/cmd-palette.js")
    nav = js[js.index("function navigateTo("):]
    assert "window.location.hash = target.hash" in nav
    assert "HashChangeEvent" in nav, \
        "selecting the tab you are already on must still act"


# --- #427 ------------------------------------------------------------------

def test_the_api_key_token_is_copied_through_the_shared_helper():
    js = _read("static/js/settings-apikeys.js")
    assert "CertMate.copyText(self.createdToken)" in js
    assert "navigator.clipboard.writeText(self.createdToken)" not in js, \
        "no fallback: over plain HTTP this is a silent no-op on a one-time token"


def test_the_copy_helper_falls_back_when_the_async_api_is_unavailable():
    js = _read("static/js/certmate.js")
    assert "CM.copyText = function" in js
    helper = js[js.index("CM._copyTextFallback = function"):]
    assert "document.execCommand('copy')" in helper
    assert "document.body.removeChild(textarea)" in helper, \
        "the fallback textarea must not be left in the DOM"


def test_there_is_one_clipboard_implementation_not_three():
    """Three copies of this logic is how one of them ended up without a
    fallback in the first place."""
    dashboard = _read("static/js/dashboard.js")
    assert "fallbackCopyTextToClipboard" not in dashboard
    assert "CertMate.copyText(commandText)" in dashboard


# --- #426 ------------------------------------------------------------------
# Not frontend, but the same class of defect: a rule that reads as if it
# applies everywhere and silently applies only at the root.

def test_dockerignore_patterns_are_recursive():
    """A .dockerignore pattern without '**' matches the context root ONLY.

    `__pycache__/`, `*.pyc` and `node_modules/` therefore left every nested
    match in the published image, and `tests/`, `docs/` and `.claude/` were
    not listed at all — so `COPY . .` shipped the test suite (whose conftest
    shells out to docker) and the agent worktrees, which are full copies of
    the repository (#426).
    """
    ignore = _read(".dockerignore")
    for pattern in ("**/__pycache__", "**/*.py[cod]", "**/node_modules",
                    "**/test_*.py", "tests/", "docs/", ".claude/"):
        assert pattern in ignore, f"{pattern} missing from .dockerignore"
    # The non-recursive forms must be gone, not merely supplemented.
    for stale in ("\n__pycache__/", "\n*.pyc", "\nnode_modules/", "\ntest_*.py"):
        assert stale not in ignore, f"{stale.strip()} still matches root only"


# --- #416 / #429 / #430 ----------------------------------------------------
# Documentation that contradicts the code is a defect with a longer half-life
# than most bugs: every reader acts on it.

def test_no_doc_points_at_the_old_dns_accounts_prefix():
    """The multi-account API lives at /api/dns/<provider>/accounts (#416)."""
    for path in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]:
        text = path.read_text(encoding="utf-8")
        assert "/api/settings/dns-providers/" not in text, \
            f"{path.relative_to(ROOT)} documents a prefix that 404s"


def test_no_doc_promises_the_default_account_endpoint():
    """It has never existed; the default travels as set_as_default (#416)."""
    for path in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]:
        assert "default-account" not in path.read_text(encoding="utf-8"), \
            f"{path.relative_to(ROOT)} documents a route with no handler"


def test_no_doc_presents_host_or_flask_debug_as_working_env_vars():
    """Neither is read anywhere, and HOST reads as a security control (#429)."""
    for path in (ROOT / "README.md", ROOT / "README.dockerhub.md"):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith(("HOST=", "FLASK_DEBUG=")):
                pytest.fail(f"{path.name}: '{stripped}' has no effect")


def test_the_documented_batch_limit_matches_the_code():
    """The CSV batch endpoint 400s above 100 rows. No page may promise more.

    This gate existed before and caught nothing for months, in a way worth
    recording. It looked for the literal "30,000" in two English files. The
    English pages wrote "30k", so it never matched them; the Italian, German
    and Spanish pages wrote "30.000" and the French "30 000", and none of those
    four files were in the list at all. So a check that read as if it enforced
    the batch limit could not have failed for any page in any language.

    Nine pages promised a user could import up to thirty thousand certificates
    per request, against an API that 400s above a hundred.
    """
    import re

    code = _read("modules/api/client_certificates.py")
    assert "max_batch = 100" in code, "the cap moved; update the docs with it"

    # Every way the five languages phrase a batch claim, against every way
    # they write a large number - "30k" included, since that is the spelling
    # the old check could not see.
    batch_word = (r"(?:batch|lotti|lotes|lots|Batch-Oper|in batch|per request|"
                  r"per richiesta|pro Anfrage|por (?:solicitud|petici\u00f3n)|"
                  r"par requ\u00eate)")
    big_number = r"(?:[1-9][0-9]{3,}|[0-9]+[.,\s\u00a0\u202f][0-9]{3}\b|[0-9]+\s?k\b)"
    overclaim = re.compile(
        rf"{batch_word}.*{big_number}|{big_number}.*{batch_word}", re.IGNORECASE)
    # URLs carry port numbers that look like large numbers; strip them so a
    # `curl http://localhost:8000/api/client-certs/batch` line is not read as
    # a claim about batch size.
    url = re.compile(r"https?://\S+")

    offenders = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            if overclaim.search(url.sub("", line)):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert not offenders, (
        "docs promise a batch import the API refuses with a 400 "
        "(max_batch = 100):\n  " + "\n  ".join(offenders)
    )


def test_no_file_under_tests_is_silently_gitignored():
    """An ignore rule that swallows a test file is worse than no test.

    `.gitignore` carried unanchored patterns meant for ad-hoc scripts at the
    repository root — `test_api_*.py`, `*_backup.*` — which also matched files
    under tests/. Two real test files sat on disk looking committed, tracked by
    nothing and run by no CI. Same defect class as the .dockerignore one above:
    a rule that reads as if it applies to one place and quietly applies
    everywhere.
    """
    import shutil
    import subprocess

    # Only meaningful inside a git checkout: from a source archive (sdist,
    # vendored copy) there is nothing to ask.
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout — nothing to verify")

    result = subprocess.run(
        ["git", "ls-files", "-o", "-i", "--exclude-standard", "tests/"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"git could not read the checkout: {result.stderr.strip()}")
    out = result.stdout.split()
    swallowed = [f for f in out if f.endswith(".py")]
    assert not swallowed, f"gitignore is hiding test files: {swallowed}"


def test_missing_ca_email_does_not_block_saving_unrelated_settings():
    """#491: a CA without an email must not make the Settings page unsaveable.

    The email registers an ACME account at issuance time. The backend never
    required it to *save* settings — `validate_settings_post` does not look at
    it — but settings.js threw unconditionally when the selected CA had no
    email, so a DNS provider change, a storage backend change or a regenerated
    bearer token could not be saved at all. Switching the default CA hit it
    immediately, since the new CA's email field starts empty.

    The guard is kept for initial setup only, mirroring the API-bearer-token
    check a few lines below it, and degrades to a warning afterwards.
    """
    js = _read("static/js/settings.js")

    assert "Email address is required in the " in js, (
        "the initial-setup guard disappeared entirely"
    )

    # The throw must sit inside a setup_completed check. Whitespace-tolerant so
    # reindenting or rewrapping the block does not fail a still-correct file —
    # only dropping the condition does.
    assert re.search(
        r"if\s*\(\s*!\s*currentSettings\.setup_completed\s*\)\s*\{\s*"
        r"throw new Error\(\s*'Email address is required in the ",
        js,
    ), (
        "the missing-CA-email error is thrown unconditionally again — that is "
        "#491: it blocks saving settings that have nothing to do with the CA"
    )

    # And the post-setup path must still tell the user, without failing.
    assert "missingCaEmailWarning" in js, (
        "the non-blocking warning was removed; a silently missing CA email "
        "surfaces only as a failed issuance later"
    )
    assert re.search(
        r"showMessage\(\s*missingCaEmailWarning\s*,\s*'warning'\s*\)", js
    )


def test_closing_the_cert_drawer_abandons_an_in_progress_reissue_edit():
    """#492: the "Edit & reissue" state used to survive closing the drawer.

    Close the edit drawer with the X or by clicking the scrim, then press
    "New certificate": the drawer re-opened still bound to the previous
    certificate, domain field read-only, with no obvious way out — the only
    escape was a small "Cancel edit" button inside the form body.

    Closing a dialog is how people abandon an edit, so closeCertDrawer resets
    the mode. cancelEditReissue no-ops outside edit mode, so this cannot wipe
    a create form the user was half-way through.
    """
    close_fn = _js_function_body(_read("templates/index.html"), "closeCertDrawer")
    assert "cancelEditReissue" in close_fn, (
        "closeCertDrawer no longer clears the reissue edit state — that is "
        "#492: the next 'New certificate' re-opens the previous edit"
    )

    # The no-op guard is what makes the call above safe to make unconditionally.
    cancel_fn = _js_function_body(_read("static/js/dashboard.js"), "cancelEditReissue")
    assert re.search(
        r"if\s*\(\s*!\s*reissueEditingDomain\s*\)\s*\{?\s*return", cancel_fn
    ), (
        "cancelEditReissue lost its not-editing guard; closing the drawer now "
        "wipes a half-filled create form"
    )


def test_the_dashboard_reattaches_to_in_flight_jobs_on_load():
    """#399: the "Issuing" row vanished on refresh and looked like a failure.

    pendingJobs lives only in the page's memory, so reloading dropped the row
    while the server was still working — @ITJamie reported it reads as if the
    request had stopped. The dashboard now asks the server what is in flight
    (GET /api/certificates/jobs) and re-attaches, which also covers a session
    opened in a different browser.
    """
    js = _read("static/js/dashboard.js")

    assert "/api/certificates/jobs" in js, (
        "the dashboard no longer asks the server for in-flight jobs — that is "
        "#399: a refresh loses the issuing row"
    )

    adopt = _js_function_body(js, "adoptInFlightJobs")
    assert "pollCertJob" in adopt, "adopted jobs must resume polling"
    assert "renderPendingRows" in adopt, "adopted jobs must be drawn"

    # An adopted job carries no original request body. Two independent
    # protections, because retryCreateJob is exposed on window and can be
    # reached without the button: the row omits Retry, and the handler refuses.
    failed_row = _js_function_body(js, "failedRowHtml")
    assert re.search(r"job\.payload\s*\?", failed_row), (
        "the Retry button is offered unconditionally again; a job adopted "
        "after a refresh has no payload to replay and would POST an empty create"
    )
    retry = _js_function_body(js, "retryCreateJob")
    assert re.search(r"if\s*\(\s*!\s*job\.payload\s*\)", retry), (
        "retryCreateJob no longer refuses a payload-less job; calling it "
        "directly would POST an empty create"
    )
