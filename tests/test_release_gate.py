"""Guards on the gate that decides whether a release needs a real certificate.

`scripts/release.sh` runs an end-to-end issuance against Let's Encrypt staging
before cutting a release. `SENSITIVE_RE` decides whether that run is MANDATORY
— i.e. whether `--skip-real-cert` is refused. It is the safety catch on the
escape hatch, and until 2026-08-08 it had a hole big enough to drive the whole
DNS subsystem through:

    modules/(core/(certificate|client_cert|deployer|acme|storage)|dns|...)
                                                                 ^^^
`modules/dns` matches nothing. There is no such directory — the DNS code lives
at `modules/core/dns_*.py`. So a change to `dns_providers.py`,
`dns_strategies.py`, `dns_alias_hook.py` or `dns_zone_discovery.py` did not make
the real certificate mandatory, in the gate written *because* two DNS providers
had each shipped never having worked in any release. Sixteen issuance-critical
files were uncovered in all, `modules/core/shell.py` — how certbot is invoked —
among them.

Nobody spotted it because nobody reads a regex that long closely enough. So the
tests below check two different things:

  * the specific files that must be covered, and
  * that **every branch of the pattern matches something real**, which is the
    check that would have caught a dead `modules/dns` on the day it was written.
"""
import pathlib
import re
import subprocess

import pytest


pytestmark = [pytest.mark.unit]

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RELEASE_SH = REPO_ROOT / "scripts" / "release.sh"


def _sensitive_re():
    """The live pattern, read from the script rather than duplicated here.

    Duplicating it would make these tests pass against a copy while the script
    shipped something else — the failure mode they exist to prevent.
    """
    match = re.search(r"^SENSITIVE_RE='([^']+)'", RELEASE_SH.read_text(encoding="utf-8"),
                      re.M)
    assert match, "scripts/release.sh no longer defines SENSITIVE_RE"
    return match.group(1)


def _tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, "git ls-files failed"
    return out.stdout.splitlines()


def _expand(pattern):
    """Expand a restricted regex into its alternative branches.

    Handles exactly the constructs the pattern uses: literals and `(a|b|c)`
    groups, nested one level. Anything else raises rather than being silently
    ignored — a branch this cannot understand must not be reported as covered.
    """
    depth, start, current = 0, None, ""
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":                      # escaped char, take both
            # Only when outside a group: inside one, the characters belong to
            # the branch being collected by the recursive call, not to the
            # prefix. Getting this wrong prepended the escapes of every inner
            # branch to every expansion.
            if depth == 0:
                current += pattern[i:i + 2]
            i += 2
            continue
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                inner = pattern[start + 1:i]
                head = current
                tail = pattern[i + 1:]
                out = []
                # Each alternative is expanded in turn, not taken whole: a
                # nested group like `tests/(a|b|c)` must yield one expansion
                # per option, or a dead option inside it would still match via
                # its siblings and be reported as live — the same blind spot,
                # one level down, as the `modules/dns` branch this file exists
                # to catch.
                for alt in _split_top_level(inner):
                    for alt_expanded in _expand(alt):
                        for rest in _expand(tail):
                            out.append(head + alt_expanded + rest)
                return out
        elif depth == 0:
            current += ch
        i += 1
    assert depth == 0, f"unbalanced parentheses in {pattern!r}"
    return [current]


def _split_top_level(pattern):
    """Split on `|` that is not inside a group."""
    depth, parts, current = 0, [], ""
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            current += pattern[i:i + 2]
            i += 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "|" and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
        i += 1
    parts.append(current)
    return parts


# Files that must make the real-cert run mandatory. Every one of these can
# break certificate issuance in a way only a real issuance would reveal.
MUST_BE_COVERED = [
    # the orchestration
    "modules/core/certificates.py",
    "modules/core/cert_service.py",
    "modules/core/cert_jobs.py",
    # the DNS-01 challenge — the branch that used to be dead
    "modules/core/dns_providers.py",
    "modules/core/dns_strategies.py",
    "modules/core/dns_alias_hook.py",
    "modules/core/dns_zone_discovery.py",
    # how certbot is actually invoked
    "modules/core/shell.py",
    # the private CA issuance path
    "modules/core/private_ca.py",
    "modules/core/ca_manager.py",
    "modules/core/csr_handler.py",
    "modules/core/ocsp_crl.py",
    "modules/core/client_certificates.py",
    # where certificates are written and sent
    "modules/core/storage_backends.py",
    "modules/core/deployer.py",
    "modules/core/deploy_targets.py",
    # provider configuration and credential files
    "modules/core/settings.py",
    "modules/core/utils.py",
    # the API and web entry points
    "modules/api/resources.py",
    "modules/api/models.py",
    "modules/api/client_certificates.py",
    "modules/web/cert_routes.py",
    # what the image is built from
    "requirements.txt",
    "requirements-minimal.txt",
    "requirements-extended.txt",
    "Dockerfile",
]

# Changes that must NOT force a real issuance, or the escape hatch is useless
# and a docs-only release becomes a four-minute ceremony.
MUST_NOT_BE_COVERED = [
    "README.md",
    "RELEASE_NOTES.md",
    # Where the notes actually live now; the index above is generated
    # from this directory. A release whose only change is its own notes
    # must not be forced through a four-minute real issuance.
    "docs/releases/v2.32.2.md",
    "SECURITY.md",
    "docs/api.md",
    "docs/it/guide.md",
    ".github/workflows/ci.yml",
    "static/css/tailwind.min.css",
    "templates/help.html",
    "tests/test_docs_navigation.py",
]


@pytest.mark.parametrize("path", MUST_BE_COVERED)
def test_issuance_critical_paths_make_the_real_cert_mandatory(path):
    assert (REPO_ROOT / path).exists(), (
        f"{path} no longer exists — update this list to match the code, do not "
        f"delete the entry to make the test pass."
    )
    assert re.search(_sensitive_re(), path), (
        f"{path} does not match SENSITIVE_RE, so a release changing only that "
        f"file would accept --skip-real-cert. This is the hole that let the "
        f"whole DNS subsystem through."
    )


@pytest.mark.parametrize("path", MUST_NOT_BE_COVERED)
def test_non_issuance_paths_keep_the_escape_hatch(path):
    assert not re.search(_sensitive_re(), path), (
        f"{path} matches SENSITIVE_RE. If every change forces a real "
        f"certificate, the skip flag is dead and a docs release costs four "
        f"minutes of Let's Encrypt staging for nothing."
    )


def test_no_branch_of_the_pattern_is_dead():
    """Every alternative must match at least one tracked file.

    This is the test that was missing. `modules/dns` sat in the pattern for
    months matching a directory that has never existed, and nothing said so
    because nothing ever asked whether the branches described real paths.
    """
    tracked = _tracked_files()
    dead = []
    for branch in _expand(_sensitive_re()):
        # Drop the anchors so a branch can be matched as a prefix.
        probe = branch.lstrip("^").rstrip("$")
        if not any(re.match(probe, f) for f in tracked):
            dead.append(branch)
    assert not dead, (
        f"these branches of SENSITIVE_RE match no file in the repository: "
        f"{dead}. A dead branch silently disarms the gate for whatever it was "
        f"meant to cover."
    )


def test_the_gate_is_still_wired_to_the_skip_flag():
    """The pattern only matters if refusing --skip-real-cert still depends on it."""
    script = RELEASE_SH.read_text(encoding="utf-8")
    assert "--skip-real-cert is not allowed here" in script, (
        "release.sh no longer refuses --skip-real-cert; SENSITIVE_RE is decorative"
    )
    assert 'grep -Eq "$SENSITIVE_RE"' in script, (
        "release.sh no longer tests changed paths against SENSITIVE_RE"
    )


def test_release_tooling_does_not_hardcode_an_author():
    """Generated commits must not claim an author the script cannot know.

    `release.sh` appended `Co-Authored-By: Claude Opus 4.8 (1M context)` to
    every release commit. The commit is generated — it rewrites version strings
    from a template — so the trailer attributed authorship to something that
    did not write it, permanently, in the git record. It also named a model
    that had not been used for months, which is how it was spotted: a hardcoded
    fact nobody had a reason to revisit.

    Covers the executable tooling only. Prose may discuss whatever it likes.
    """
    tooling = []
    for pattern in ("scripts/*.sh", "scripts/*.py", ".github/workflows/*.yml"):
        tooling.extend(REPO_ROOT.glob(pattern))
    makefile = REPO_ROOT / "Makefile"
    if makefile.exists():
        tooling.append(makefile)

    assert tooling, "found no release tooling to check — has the layout moved?"

    offenders = []
    for path in tooling:
        for number, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if re.search(r"Co-Authored-By:|Claude (Opus|Sonnet|Haiku|Fable)",
                         line, re.IGNORECASE):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")
    assert not offenders, (
        "release tooling hardcodes an author or model name:\n  "
        + "\n  ".join(offenders)
        + "\nA generated commit should not claim an author the generator "
          "cannot know."
    )


def test_prepare_refuses_a_stale_local_checkout():
    """cmd_prepare gates the checked-out tree but cuts the release branch from
    origin/main. If the local checkout is behind origin/main (the ordinary
    state after merging a PR on GitHub), the gated tree and the released tree
    differ and a commit on origin/main is never tested. prepare must refuse
    unless HEAD == origin/main, BEFORE any gate runs.
    """
    src = RELEASE_SH.read_text(encoding="utf-8")

    # the check compares HEAD to origin/main and dies on mismatch
    assert 'git rev-parse HEAD' in src
    assert 'git rev-parse origin/main' in src
    head_check = re.search(
        r'\[ "\$head_sha" = "\$origin_sha" \] \|\| die', src)
    assert head_check, "no HEAD==origin/main fail-closed check in release.sh"

    # and it runs before the first gate, or a stale tree would still be gated
    check_pos = head_check.start()
    first_gate = src.find('gate "flake8')
    assert first_gate != -1
    assert check_pos < first_gate, \
        "the HEAD==origin/main check must precede the gates"


# --- the notes travel in the release PR -------------------------------------------
#
# `prepare` used to refuse any dirty tree and require the notes to exist, so the
# notes had to be merged to main first. Main then named a version that did not
# exist for as long as the gates took: hours usually, days once (v2.55.2, while
# Let's Encrypt staging was unreachable). Now the notes of the version being
# released and the index are the only files `prepare` accepts uncommitted, and
# they go in the release commit.

def _scratch_repo(tmp_path):
    """A git repository with the files release.sh looks at, committed and clean."""
    repo = tmp_path / "repo"
    (repo / "docs" / "releases").mkdir(parents=True)
    (repo / "RELEASE_NOTES.md").write_text("# Release notes\n")
    (repo / "docs" / "releases" / "v1.0.0.md").write_text("## v1.0.0 (first)\n")
    (repo / "app.py").write_text("print('hi')\n")
    for command in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "-c", "user.email=t@example.com", "-c", "user.name=t",
                     "commit", "-q", "-m", "base"]):
        subprocess.run(command, cwd=repo, check=True, capture_output=True)
    return repo


def _dirty_outside_the_notes(repo, version):
    out = subprocess.run(
        ["bash", "-c", f'source "{RELEASE_SH}"; cd "{repo}"; dirty_outside_the_notes {version}'],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.splitlines()


def test_the_notes_of_the_release_and_the_index_may_be_uncommitted(tmp_path):
    repo = _scratch_repo(tmp_path)
    (repo / "docs" / "releases" / "v1.0.1.md").write_text("## v1.0.1 (next)\n")     # new, untracked
    (repo / "RELEASE_NOTES.md").write_text("# Release notes\n\n## v1.0.1 (next)\n")  # modified

    assert _dirty_outside_the_notes(repo, "1.0.1") == []


def test_any_other_uncommitted_file_is_refused_and_named(tmp_path):
    repo = _scratch_repo(tmp_path)
    (repo / "docs" / "releases" / "v1.0.1.md").write_text("## v1.0.1 (next)\n")
    (repo / "app.py").write_text("print('changed')\n")
    (repo / "scratch.txt").write_text("x\n")

    stray = _dirty_outside_the_notes(repo, "1.0.1")

    assert any(line.endswith("app.py") for line in stray)
    assert any(line.endswith("scratch.txt") for line in stray)
    assert not any("v1.0.1.md" in line or "RELEASE_NOTES.md" in line for line in stray)


def test_the_notes_of_another_version_are_not_excused(tmp_path):
    repo = _scratch_repo(tmp_path)
    (repo / "docs" / "releases" / "v1.0.0.md").write_text("## v1.0.0 (edited after release)\n")

    stray = _dirty_outside_the_notes(repo, "1.0.1")

    assert any("v1.0.0.md" in line for line in stray), \
        "an edit to the notes of a release already made must not ride along in the next one"


def test_a_clean_tree_is_clean(tmp_path):
    assert _dirty_outside_the_notes(_scratch_repo(tmp_path), "1.0.1") == []


def test_prepare_uses_that_rule_not_a_plain_clean_check():
    src = RELEASE_SH.read_text(encoding="utf-8")

    assert 'dirty_outside_the_notes "$version"' in src
    assert '[ -z "$(git status --porcelain)" ]' not in src, \
        "prepare is back to refusing the notes it needs to carry"


def test_the_release_commit_carries_the_notes_and_the_index():
    src = RELEASE_SH.read_text(encoding="utf-8")

    add = re.search(r'^\s*git add ([^\n]*)', src, re.M)
    assert add, "no git add in the release commit"
    assert '"$(notes_file "$version")"' in add.group(1)
    assert 'RELEASE_NOTES.md' in add.group(1)


def test_sourcing_the_script_runs_nothing():
    """The dispatch is guarded, so the functions above can be loaded and tried."""
    out = subprocess.run(["bash", "-c", f'source "{RELEASE_SH}"; echo loaded'],
                         capture_output=True, text=True, timeout=60)

    assert out.returncode == 0 and out.stdout.strip() == "loaded", out.stderr
