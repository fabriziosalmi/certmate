<!--
Thanks for contributing. The checklist below is the same set of gates CI runs;
ticking it locally is faster than a round trip. Delete anything that does not
apply — an honest "not run, here is why" is more useful than a tick you are not
sure about.
-->

## What this changes

<!-- What behaviour is different after this merges, and why. If it fixes a bug,
     say what the bug did — not just which line was wrong. -->

Fixes #

## How it was verified

<!-- Not "tests pass" — what did you actually run or observe? For a bug fix,
     the useful sentence is: this test fails against the old code and passes
     against the new one. -->

## Checklist

- [ ] `pytest -v --tb=short -m "not ui and not e2e"` is green
      *(the marker expression is not optional — a bare `pytest` fails on the UI suite)*
- [ ] `flake8 . --count --select=E9,F63,F7,F82,F811,F632,E711,E712,E713,E714` reports 0
- [ ] `bandit -r modules/ app.py --severity-level medium` reports 0
- [ ] New behaviour has a test, and I checked that it **fails without the fix**

If you touched templates or CSS:

- [ ] `npm ci && npm run css:build`, and `static/css/tailwind.min.css` is committed
- [ ] `python3 scripts/theme_codemod.py --check` is clean

If you touched docs:

- [ ] `pytest tests/test_docs_navigation.py` is green
      *(links out of `docs/<lang>/` need `../../`, not `../`)*

## Issuance pipeline

- [ ] This change touches certificate issuance, a DNS provider, or the ACME path

If ticked, `scripts/release.sh` will require a real certificate against Let's
Encrypt **staging** before a release carrying this can be cut. Say here which
provider and path you exercised, if you did.

---

<!--
Before merge: every review conversation has to be resolved, bots included.
Copilot and CodeQL comment on most PRs and branch protection will block the
merge until each thread is closed. Please read them rather than resolving on
sight — they are more often right than not.
-->
