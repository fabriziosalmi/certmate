#!/usr/bin/env python3
"""A translated page records the English it was translated from, and says when
that English has moved on.

#674 calls the four extra locales "a standing correctness liability on
documentation that includes security guidance", because "stale translated
security docs are worse than none". That is not a worry about the future here.
Measured on 2026-09-16, 24 of the 64 translated pages were behind, and two of
them were not merely incomplete:

* `docs/mcp.md` was fixed on 2026-08-10 by a commit titled "the documented
  job-polling loop could not run". All four translations were last touched on
  2026-06-24, so all four still described the loop that does not run.
* the `docs/api.md` translations predated the change that unified the error
  envelope and made `code` a string everywhere: a breaking change, contract
  2.0 to 2.1. Four translations described a contract that had stopped being
  true.

A reader has no way to tell, which is what makes those worse than a missing
page.

This does not require the translations to be current. No gate can produce that,
and whether to keep four locales at all is the decision #674 is about. It
requires that improving the English either brings the translation with it or
leaves the translation saying, in its own language, that it is behind. That
choice is always available, so this can never be the reason not to improve the
English.

**Why a content hash and not a date.** The first version of this compared
commit dates, and it defeated itself in the commit that introduced it: adding
the stale notice to a page is an edit, an edit makes the page the most recently
committed of the pair, and all 24 pages it had just marked came out looking
fresher than their sources. Every one then failed the opposite arm. What
matters is not when a file was touched but which English text the translation
was made from, so each page records that:

    <!-- CERTMATE-TRANSLATED-FROM 13de52d0ee4b09b1 -->

the first 16 hex of the sha256 of the English page as it stood. Editing the
translation cannot change it, and refreshing it is the explicit act of saying
"this translation is in step again". It needs no git history either, so it runs
in any checkout, shallow included.

Usage:  check_translation_freshness.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / 'docs'
LOCALES = ('de', 'es', 'fr', 'it')

MARKER = 'CERTMATE-TRANSLATED-FROM'
NOTICE = 'CERTMATE-STALE-TRANSLATION'

# One English page is named differently from its translations, and the
# repository already decided how to pair it: tests/test_docs_navigation.py
# carries the same mapping, with the comment "probes.md is probes.en.md under
# a shorter name in the translated trees". Mirrored rather than renamed, so
# this does not become a second convention; tests/test_translation_freshness.py
# fails if the two ever disagree.
ENGLISH_NAME = {'probes.md': 'probes.en.md'}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def recorded_source(text: str) -> str | None:
    for line in text.splitlines():
        if MARKER in line:
            parts = line.replace('-->', '').split()
            return parts[-1] if parts and parts[-1] != MARKER else None
    return None


def evaluate() -> list[str]:
    problems: list[str] = []
    pairs = 0
    for locale in LOCALES:
        directory = DOCS / locale
        if not directory.is_dir():
            problems.append(
                f'docs/{locale}/ is gone. Drop it from LOCALES in the same '
                f'commit, or this passes over a locale nobody is looking at.')
            continue
        for translated in sorted(directory.glob('*.md')):
            english = DOCS / ENGLISH_NAME.get(translated.name, translated.name)
            here = translated.relative_to(REPO)
            if not english.exists():
                problems.append(
                    f'{here} has no English source at '
                    f'{(english.relative_to(REPO))}. A translation of nothing '
                    f'cannot be checked against anything.')
                continue
            pairs += 1
            text = translated.read_text(encoding='utf-8')
            source = recorded_source(text)
            current = digest(english.read_bytes())
            if source is None:
                problems.append(
                    f'{here} does not record which English it was translated '
                    f'from. Add `<!-- {MARKER} {current} -->` under its title '
                    f'if it is in step with {english.relative_to(REPO)} today.')
                continue
            behind = source != current
            marked = NOTICE in text
            if behind and not marked:
                problems.append(
                    f'{here} was translated from {english.relative_to(REPO)} at '
                    f'{source}, which is now {current}. Update the translation '
                    f'and the recorded hash, or add the stale-translation '
                    f'notice in {locale}.')
            if marked and not behind:
                problems.append(
                    f'{here} carries the stale-translation notice and is in '
                    f'step with {english.relative_to(REPO)}. Remove the notice: '
                    f'a warning that is always there stops being read.')
    if pairs == 0:
        problems.append(
            'no translated page was compared against an English source. The '
            'layout changed and this check passed over nothing.')
    return problems


def main() -> int:
    problems = evaluate()
    if not problems:
        print('Translation freshness OK: every page records its source, and '
              'every page that is behind says so.')
        return 0
    print('\nTranslation freshness failed:\n')
    for problem in problems:
        print('  ' + problem)
    print(f'\n{len(problems)} problem(s). See the docstring in '
          f'scripts/check_translation_freshness.py.\n')
    return 1


if __name__ == '__main__':
    sys.exit(main())
