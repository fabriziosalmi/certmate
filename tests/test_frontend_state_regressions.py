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

from pathlib import Path

import pytest


pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent


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
    code = _read("modules/api/client_certificates.py")
    assert "max_batch = 100" in code, "the cap moved; update the docs with it"
    for path in (ROOT / "docs/README.md", ROOT / "docs/index.md"):
        assert "30,000" not in path.read_text(encoding="utf-8")


def test_no_file_under_tests_is_silently_gitignored():
    """An ignore rule that swallows a test file is worse than no test.

    `.gitignore` carried unanchored patterns meant for ad-hoc scripts at the
    repository root — `test_api_*.py`, `*_backup.*` — which also matched files
    under tests/. Two real test files sat on disk looking committed, tracked by
    nothing and run by no CI. Same defect class as the .dockerignore one above:
    a rule that reads as if it applies to one place and quietly applies
    everywhere.
    """
    import subprocess

    out = subprocess.run(
        ["git", "ls-files", "-o", "-i", "--exclude-standard", "tests/"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout.split()
    swallowed = [f for f in out if f.endswith(".py")]
    assert not swallowed, f"gitignore is hiding test files: {swallowed}"
