# Contributing to CertMate

Contributions are welcome. Open a pull request at any time.

CertMate issues TLS certificates for other people's infrastructure, so the bar
for merging is deliberately high — and most of it is automated. Nothing below is
a matter of taste: it is the list of gates that will run on your branch. Running
them locally is faster than finding out from CI.

## How to contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push the branch
5. Open a pull request

## Development setup

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-test.txt   # pytest + playwright, and the in-repo SDK/CLI editable
python app.py
```

`requirements-test.txt` installs `clients/certmate-sdk` and `clients/certmate-cli`
editable, in that order — the CLI depends on the SDK — so the end-to-end tests
exercise the real clients against the server they wrap.

The linters are **not** in `requirements-test.txt`; CI pins them explicitly and
so should you:

```bash
pip install flake8==7.3.0 bandit==1.9.4
```

## Running the tests

```bash
./run-tests.sh                                   # or, equivalently:
pytest -v --tb=short -m "not ui and not e2e"
```

**The marker expression is not optional.** A bare `pytest` runs the Playwright
`ui` suite in the same process as everything else and hands you four failures
that have nothing to do with your change; `e2e` needs a running instance.
`make test` and `scripts/release.sh` use exactly this selection.

The UI suite runs on its own and needs Docker:

```bash
pytest -m ui           # builds a container and drives it with Playwright
```

## Before you push

These are the gates that will run on the PR, in rough order of how often they
catch something:

| Gate | Command |
|---|---|
| Syntax + bug-class lint (**fails CI**) | `flake8 . --count --select=E9,F63,F7,F82,F811,F632,E711,E712,E713,E714 --show-source` |
| Security scan (**fails CI**) | `bandit -r modules/ app.py --severity-level medium` |
| Tests + coverage floor of 65% on `modules/` | `pytest -m "not ui" --cov=modules --cov-fail-under=65` |
| Theme tokens | `python3 scripts/theme_codemod.py --check` |
| CSS bundle freshness | `npm ci && npm run css:build`, then commit `static/css/tailwind.min.css` |
| No emoji in `RELEASE_NOTES.md` | `.github/workflows/lint-emoji.yml` |
| Image builds | `docker build -t certmate:test .` |

The full style pass (`flake8 .` with no `--select`) is informational — the
codebase is not clean against it and CI runs it with `--exit-zero`. Do not
reformat unrelated files to quieten it.

The coverage floor is a floor, not a target. Raise it as a ratchet; never lower
it to make a red build pass.

### Editing templates or CSS

Rebuild the bundle and commit it — CI fails if the committed
`static/css/tailwind.min.css` differs from a fresh build. Use the semantic theme
tokens rather than raw `*-600 dark:*-400` colour pairs; `theme_codemod.py --check`
enforces that.

### Editing docs

`tests/test_docs_navigation.py` fails if a page stops being linked from its
`index.md`, if an index points at a file that is not there, or if the README's
documentation table drops a page.

Translations live one directory deeper than the English originals, so a relative
link out of `docs/<lang>/` needs `../../`, not `../`. Copying an English page
without adjusting that broke thirteen links before anyone noticed.

## Getting a PR merged

Branch protection is on, and admins are not exempt:

- **Every review conversation must be resolved**, bots included. Copilot and
  CodeQL comment on most PRs and the branch will not merge until each thread is
  resolved — read them rather than resolving on sight. In one recent batch, four
  of five bot findings were real bugs.
- CI must be green. Auto-merge is disabled repo-wide, so merging is a deliberate
  act by a human.

### Touching the issuance pipeline

If your change touches certificate issuance, a DNS provider, or the ACME path,
say so in the PR. `scripts/release.sh` detects those paths and requires a real
certificate issued against Let's Encrypt **staging** before a release carrying
the change can be cut. That gate is not skippable for those paths — it exists
because two DNS providers once shipped in a state where they had never worked in
any release, and nothing caught it for months.

### Version strings

Don't add one by hand. Every user-facing copy of the version is bumped by
`scripts/release.sh` and pinned by `tests/test_version_consistency.py`. If you
create a new place where the version appears, add it to both: a version string
that has to be remembered is a version string that goes stale.

## Code style

- Match the conventions of the file you are editing.
- Comments should explain *why*, particularly where the obvious implementation
  is wrong. Much of the commentary in this codebase records a bug that was paid
  for once; that is the house style, and it is worth more than a comment
  restating the code.
- Add tests for new behaviour. For a bug fix, check that your test **fails
  against the old code** — a gate nobody has watched fail is not a gate.

## Reporting issues

Open an issue with:

- steps to reproduce;
- expected vs. actual behaviour;
- the CertMate version (`GET /health`, or `certmate --version` for the CLI) and
  the environment — Docker tag, DNS provider, CA.

Security issues follow [SECURITY.md](SECURITY.md), not the public tracker.
