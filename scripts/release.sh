#!/usr/bin/env bash
#
# CertMate release - the single, gated path to a release. Fail-closed: any gate
# that does not pass aborts the release. No step depends on remembering to run
# it. Mirrors the process the repo already enforces (fresh branch off main,
# squash-merge, tag, GH release) and the real-cert policy (path-aware, with an
# explicit, logged override for non-issuance patches only).
#
# Usage:
#   scripts/release.sh prepare X.Y.Z [--skip-real-cert "reason"] [--dry-run]
#       Validate + run every gate, then (unless --dry-run) branch off main,
#       bump the version, commit, push and open the release PR.
#   scripts/release.sh publish X.Y.Z
#       After that PR is merged to main: tag vX.Y.Z and create the GH release
#       from the RELEASE_NOTES.md section. Run this only once CI is green.
#
# Gates (prepare): flake8 (syntax/undefined), bandit, unit+integration suite,
# UI (Playwright), real-cert E2E (LE staging via Cloudflare from .env), Docker
# build. The unit suite includes the version-consistency and CI-marker-coverage
# guards. Docker must be running for the UI and real-cert gates.
#
set -euo pipefail

# --- setup --------------------------------------------------------------------
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PY="${ROOT}/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
# macOS: Docker Desktop's CLI is not always on PATH.
if ! command -v docker >/dev/null 2>&1 && [ -x /Applications/Docker.app/Contents/Resources/bin/docker ]; then
  export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
fi

# Paths whose change makes the real-cert E2E MANDATORY (issuance pipeline).
SENSITIVE_RE='^(modules/(core/(certificate|client_cert|deployer|acme|storage)|dns|api/(certificate|resources|client_cert))|requirements.*\.txt|Dockerfile|tests/(e2e_support|test_cert_lifecycle|test_async_issuance|test_health_ready))'

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo ">>> $*"; }
gate() { echo; echo "[GATE] $1"; shift; "$@"; }

emoji_scan() {  # fail on emoji (arrows / em-dash allowed) in the given file
  "$PY" - "$1" <<'PY'
import re, sys, pathlib
EMOJI = re.compile("[\U0001F000-\U0001FAFF\U00002600-\U000026FF"
                   "\U00002700-\U000027BF\U00002B50\U00002B55\U0000FE0F]")
p = pathlib.Path(sys.argv[1])
bad = [(n, l.strip()) for n, l in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
       if EMOJI.search(l)]
if bad:
    for n, l in bad:
        print(f"  {p}:{n}: {l}", file=sys.stderr)
    sys.exit(1)
PY
}

notes_section() {  # print the RELEASE_NOTES.md block for vX.Y.Z (stops at the --- rule)
  awk -v v="## v$1 " '
    index($0, v)==1 {f=1}
    f && /^---$/ {exit}
    f {print}
  ' RELEASE_NOTES.md
}

semver_ok() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
version_gt() {  # $1 > $2 ?
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# --- prepare ------------------------------------------------------------------
cmd_prepare() {
  local version="" skip_reason="" dry=0
  version="${1:-}"; shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --skip-real-cert) skip_reason="${2:-}"; shift 2 || die "--skip-real-cert needs a reason";;
      --dry-run) dry=1; shift;;
      *) die "unknown flag: $1";;
    esac
  done
  [ -n "$version" ] || die "usage: release.sh prepare X.Y.Z [--skip-real-cert \"reason\"] [--dry-run]"
  semver_ok "$version" || die "not a semver X.Y.Z: $version"

  info "Preconditions"
  [ -f modules/__init__.py ] || die "run from the repo root"
  [ -z "$(git status --porcelain)" ] || die "working tree is dirty - commit or stash first"
  git fetch origin --quiet
  git rev-parse --verify origin/main >/dev/null 2>&1 || die "no origin/main"
  local cur; cur="$("$PY" -c 'from modules import __version__; print(__version__)')"
  version_gt "$version" "$cur" || die "version $version is not greater than current $cur"

  info "RELEASE_NOTES.md must document v$version"
  [ -n "$(notes_section "$version")" ] || die "no '## v$version' section in RELEASE_NOTES.md - write the notes first"
  emoji_scan RELEASE_NOTES.md || die "emoji in RELEASE_NOTES.md (arrows/em-dash are fine)"

  info "Real-cert policy (path-aware)"
  local last_tag changed touches=0
  last_tag="$(git describe --tags --abbrev=0 origin/main 2>/dev/null || true)"
  if [ -n "$last_tag" ]; then
    changed="$(git diff --name-only "$last_tag..origin/main")"
  else
    changed=""; touches=1  # no tag reachable -> be safe, require real-cert
  fi
  if [ -n "$changed" ] && echo "$changed" | grep -Eq "$SENSITIVE_RE"; then touches=1; fi
  local run_real_cert=1
  if [ "$touches" = 1 ]; then
    [ -z "$skip_reason" ] || die "real-cert is MANDATORY (release touches the issuance pipeline); --skip-real-cert is not allowed here. Changed:
$(echo "$changed" | grep -E "$SENSITIVE_RE" | sed 's/^/  /')"
    info "  issuance pipeline changed since ${last_tag:-<no tag>} -> real-cert MANDATORY"
  elif [ -n "$skip_reason" ]; then
    run_real_cert=0
    info "  no issuance-pipeline change; real-cert SKIPPED (logged): $skip_reason"
  else
    info "  no issuance-pipeline change; real-cert still run by default (use --skip-real-cert to override)"
  fi

  # --- gates (fail-closed) ---
  docker info >/dev/null 2>&1 || die "Docker daemon is not running (needed for UI + real-cert gates)"
  export FLASK_ENV=testing TESTING=true

  gate "flake8 (syntax / undefined names)" bash -c '
    "'"$PY"'" -m flake8 . --count --select=E9,F63,F7,F82,F811,F632,E711,E712,E713,E714 --show-source --statistics'
  gate "bandit (medium+)" bash -c '"'"$PY"'" -m bandit -r modules/ app.py --severity-level medium -q'
  gate "unit + integration suite (incl. version + marker-coverage guards)" \
    "$PY" -m pytest -q -m "not ui and not e2e" -p no:cacheprovider
  gate "UI suite (Playwright)" "$PY" -m pytest -q -m ui -p no:cacheprovider
  if [ "$run_real_cert" = 1 ]; then
    [ -f .env ] || die "real-cert gate needs .env with CLOUDFLARE_API_TOKEN / CERTMATE_TEST_DOMAIN"
    gate "real-cert E2E (LE staging via Cloudflare)" bash -c '
      set -a; . ./.env; set +a
      [ -n "${CLOUDFLARE_API_TOKEN:-}" ] || { echo "CLOUDFLARE_API_TOKEN empty in .env" >&2; exit 1; }
      CERTMATE_E2E_CA_PROVIDER=letsencrypt_staging "'"$PY"'" -m pytest -q -m e2e \
        tests/test_health_ready_e2e.py tests/test_cert_lifecycle.py tests/test_async_issuance_e2e.py \
        -p no:cacheprovider'
  fi
  gate "Docker build" docker build -t certmate:release-check .

  echo; info "ALL GATES PASSED for v$version"
  if [ "$dry" = 1 ]; then info "--dry-run: stopping before any branch/commit/push"; return 0; fi

  # --- orchestration ---
  local branch="release-v$version"
  git rev-parse --verify "$branch" >/dev/null 2>&1 && die "branch $branch already exists"
  info "Branch $branch off origin/main"
  git checkout -q -b "$branch" origin/main
  "$PY" - "$version" <<'PY'
import json, pathlib, re, sys
v = sys.argv[1]
init = pathlib.Path("modules/__init__.py")
init.write_text(re.sub(r"__version__ = '[^']+'", f"__version__ = '{v}'", init.read_text()), encoding="utf-8")
pkg = pathlib.Path("package.json"); d = json.loads(pkg.read_text())
d["version"] = v
pkg.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
# The /health example in the Docker Hub README prints a version. Bump it here
# rather than by hand: an example that has to be remembered is an example that
# goes stale, and test_version_consistency pins it.
dh = pathlib.Path("README.dockerhub.md")
dh.write_text(
    re.sub(r'("version": ")[0-9]+\.[0-9]+\.[0-9]+(")', rf"\g<1>{v}\g<2>", dh.read_text()),
    encoding="utf-8",
)
PY
  [ "$("$PY" -c 'import json;from modules import __version__;print(json.load(open("package.json"))["version"]==__version__)')" = "True" ] \
    || die "version files disagree after bump"
  local body="chore(release): v$version"
  [ "$run_real_cert" = 0 ] && body="$body

real-cert E2E skipped (non-issuance change): $skip_reason"
  # README.dockerhub.md too: the bump above rewrites it, and leaving it out of
  # the commit produced a release PR whose own CI failed on the version-
  # consistency test — a gate the local run cannot catch, because the bump
  # happens after the gates.
  git add modules/__init__.py package.json README.dockerhub.md
  git commit -q -m "$body

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  info "Push + open PR"
  git push -u origin "$branch" --quiet
  local pr_body; pr_body="$(notes_section "$version")
$( [ "$run_real_cert" = 1 ] && echo "Gates: unit+integration, UI, real-cert E2E (LE staging), Docker build - all green locally." \
     || echo "Gates: unit+integration, UI, Docker build - all green locally. Real-cert E2E skipped (non-issuance): $skip_reason." )"
  gh pr create --base main --head "$branch" \
    --title "v$version - $(notes_section "$version" | head -1 | sed 's/^## v[0-9.]* (\?//; s/)\?$//')" \
    --body "$pr_body"
  echo; info "PR opened. When CI is green and it is merged, run: scripts/release.sh publish $version"
}

# --- publish ------------------------------------------------------------------
cmd_publish() {
  local version="${1:-}"
  [ -n "$version" ] || die "usage: release.sh publish X.Y.Z"
  semver_ok "$version" || die "not a semver X.Y.Z: $version"
  git fetch origin --quiet
  git checkout -q main
  git pull --ff-only origin main --quiet
  local head_v; head_v="$("$PY" -c 'from modules import __version__; print(__version__)')"
  [ "$head_v" = "$version" ] || die "main is at v$head_v, not v$version - is the release PR merged?"
  git log -1 --format='%s' | grep -q "v$version" || die "main HEAD is not the v$version release commit"
  git rev-parse --verify "v$version" >/dev/null 2>&1 && die "tag v$version already exists"
  emoji_scan RELEASE_NOTES.md || die "emoji in RELEASE_NOTES.md"
  local notes; notes="$(notes_section "$version")"
  [ -n "$notes" ] || die "no RELEASE_NOTES section for v$version"
  local title; title="$(echo "$notes" | head -1 | sed 's/^## //')"

  # CI status on the exact commit being released (#413). Every other gate
  # here checks the *contents* of the release; none checked whether main
  # actually builds. A Dependabot bump landing between `prepare` and
  # `publish` was enough to tag and push a broken tree — and the tag push
  # is what publishes :latest.
  info "CI status on the release commit"
  local sha; sha="$(git rev-parse HEAD)"
  # --limit 100: the default page size is 20, and reruns plus the
  # non-required workflows can push a required one off the first page —
  # which would read as MISSING and block a perfectly good release.
  local runs; runs="$(gh run list --commit "$sha" --limit 100 \
    --json name,conclusion,status,workflowName,createdAt 2>/dev/null || echo '')"
  [ -n "$runs" ] || die "could not read CI status for $sha (is gh authenticated?)"
  local verdict; verdict="$(printf '%s' "$runs" | "$PY" -c '
import json, sys

# Only the workflows behind the REQUIRED branch-protection checks gate the
# release. UI tests and E2E (staging) run on the self-hosted runner and are
# deliberately not required: if that box is offline their runs sit queued
# forever, and a release must not hang on it. They are still reported.
REQUIRED = {"CI", "Build Multi-Platform Docker Images", "CodeQL", "Lint (emoji)"}
runs = json.load(sys.stdin)

# Keep only the most recent run per workflow: a rerun creates a second run,
# and judging the older attempt would fail a release whose rerun is green.
latest = {}
for r in sorted(runs, key=lambda r: r.get("createdAt") or ""):
    latest[r.get("workflowName")] = r
runs = list(latest.values())

pending, bad, other = set(), set(), []
for r in runs:
    name = r.get("workflowName", "?")
    state = r.get("conclusion") or r.get("status")
    if name not in REQUIRED:
        other.append(name + "=" + str(state))
        continue
    if r.get("status") != "completed":
        pending.add(name)
    # cancelled counts as failed: a cancelled required check is exactly how
    # a broken build slipped through before (see the v2.21.4 release).
    elif r.get("conclusion") not in ("success", "skipped", "neutral"):
        bad.add(name + "=" + str(r.get("conclusion")))
missing = REQUIRED - {r.get("workflowName") for r in runs}
if pending:
    print("PENDING " + ", ".join(sorted(pending)))
elif bad:
    print("FAILED " + ", ".join(sorted(bad)))
elif missing:
    print("MISSING " + ", ".join(sorted(missing)))
else:
    print("OK " + ("; not-required: " + ", ".join(sorted(other)) if other else ""))')"
  case "$verdict" in
    OK*)      info "  ${verdict}" ;;
    PENDING*) die "CI still running on $sha (${verdict#PENDING }) - wait for it" ;;
    FAILED*)  die "CI is not green on $sha: ${verdict#FAILED }" ;;
    MISSING*) die "no CI run found on $sha for: ${verdict#MISSING } - push the commit and let CI run" ;;
    *)        die "could not interpret CI status for $sha: $verdict" ;;
  esac

  info "Tag + push v$version"
  git tag -a "v$version" -m "$title" HEAD
  git push origin "v$version" --quiet
  info "GH release"
  printf '%s\n' "$notes" | gh release create "v$version" --title "$title" --notes-file - --latest
  info "Released v$version"
}

# --- dispatch -----------------------------------------------------------------
case "${1:-}" in
  prepare) shift; cmd_prepare "$@";;
  publish) shift; cmd_publish "$@";;
  *) die "usage: release.sh {prepare|publish} X.Y.Z [...]";;
esac
