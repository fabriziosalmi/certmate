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

**Why the stamp is checked against the page.** A stamp is a claim, and nothing
checked it. Measured on 2026-10-16, 27 of the 60 translated pages that recorded
the current English were not translations of it:

* the four `docker.md` translations lacked 5 of the English page's 24 code
  blocks and carried others with different commands, and the four
  `dns-providers.md` translations had 59 headings against 35;
* `fr/testing.md` had renamed the functions inside its code examples, and
  `it/mcp.md` had translated the placeholder path in a configuration a reader
  copies;
* `it/compliance.md` linked to an anchor its own `api.md` does not have.

So a page counts as in step only when it also has the English page's shape:
the same code, except comment text; the same headings, tables, inline code,
link targets and paragraphs; links that resolve and anchors that exist. Prose
cannot be compared across languages, and this does not try to. It compares
everything a translation has no reason to change, which is where a page that
was never brought in step shows. A page that differs is behind, whatever its
stamp says, and has to say so like any other.

Usage:  check_translation_freshness.py
"""
from __future__ import annotations

import collections
import hashlib
import re
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


FENCE = re.compile(r'^\s*(`{3,}|~{3,})')
# A comment line inside a code block: the one text a translation may change.
# `#!` is a shebang, which is code.
COMMENT = re.compile(r'^\s*(#(?!!)|//)')
LINK = re.compile(r'\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)')
SCHEME = re.compile(r'^[a-z][a-z0-9+.-]*:')
# The two marker comments, and the notice text that follows the second, say
# what the page is; they are no part of it.
MARKERS = re.compile(rf'^<!--\s*({MARKER}|{NOTICE})\b.*-->$')
# Each docs README draws its own directory as a tree, and
# tests/test_docs_navigation.py::test_file_structure_listing_matches_disk
# holds every one of them to the files on disk in that directory. A translated
# README therefore lists its own locale's files, not the English ones, and that
# block is compared there rather than here; it still has to be there.
LISTING = re.compile(r'^docs/')


def _split(text: str) -> tuple[list[str], list[list[str]], list[list[str]]]:
    """Prose lines, fenced code blocks, and paragraphs. A paragraph is a run of
    non-blank lines, and a fenced block is one paragraph however many blank
    lines it holds. The markers and the notice are left out: a page that
    carries the notice is compared as the page it would be without it."""
    prose: list[str] = []
    blocks: list[list[str]] = []
    paragraphs: list[list[str]] = []
    current: list[str] = []
    block: list[str] | None = None
    fence = ''
    notice = False
    for line in text.splitlines():
        if block is None and MARKERS.match(line.strip()):
            notice = NOTICE in line
            continue
        if notice and line.startswith('>'):
            continue
        notice = False
        if block is not None:
            block.append(line)
            current.append(line)
            closing = line.strip()
            if closing and set(closing) == {fence[0]} and len(closing) >= len(fence):
                blocks.append(block)
                block = None
            continue
        opening = FENCE.match(line)
        if opening:
            fence = opening.group(1)
            block = [line]
            current.append(line)
            continue
        if line.strip():
            prose.append(line)
            current.append(line)
        elif current:
            paragraphs.append(current)
            current = []
    if block is not None:
        blocks.append(block)
    if current:
        paragraphs.append(current)
    return prose, blocks, paragraphs


def _code_line_matches(english: str, translated: str) -> bool:
    if english == translated:
        return True
    if COMMENT.match(english) and COMMENT.match(translated):
        return (english[:len(english) - len(english.lstrip())]
                == translated[:len(translated) - len(translated.lstrip())])
    for marker in (' #', ' //'):
        if marker in english and marker in translated:
            if english.split(marker, 1)[0] == translated.split(marker, 1)[0]:
                return True
    return False


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lowercase, no punctuation but `-` and
    `_`, each space a hyphen, letters with accents kept."""
    text = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', heading).replace('`', '')
    text = re.sub(r'<[^>]+>', '', text.strip().lower())
    return re.sub(r'\s', '-', re.sub(r'[^\w\s-]', '', text))


def _anchors(page: Path) -> set[str]:
    prose, _, _ = _split(page.read_text(encoding='utf-8'))
    seen: collections.Counter[str] = collections.Counter()
    found = set()
    for line in prose:
        heading = re.match(r'^#{1,6}\s+(.*?)\s*#*\s*$', line)
        if heading:
            slug = _slug(heading.group(1))
            found.add(slug if not seen[slug] else f'{slug}-{seen[slug]}')
            seen[slug] += 1
        found.update(re.findall(r'<a\s+(?:id|name)="([^"]+)"', line))
    return found


def _links(prose: list[str]) -> list[str]:
    found = []
    for line in prose:
        line = re.sub(r'`[^`]*`', '', line)
        found += LINK.findall(line)
        reference = re.match(r'^\s*\[[^\]]+\]:\s*(\S+)', line)
        if reference:
            found.append(reference.group(1))
    return found


def _target(page: Path, url: str, docs: Path) -> tuple[str, str | None]:
    """Where a link goes, named as the English tree names it, and what is
    wrong with it, if anything. A translated page and its English twin are
    the same target."""
    if SCHEME.match(url):
        return url, None
    path, _, anchor = url.partition('#')
    destination = (page.parent / path).resolve() if path else page.resolve()
    if not destination.exists():
        return url, f'links to {url}, which does not exist'
    root = docs.resolve()
    try:
        inside = destination.relative_to(root)
    except ValueError:
        return f'../{destination.relative_to(root.parent)}', None
    if len(inside.parts) == 2 and inside.parts[0] in LOCALES:
        name = inside.parts[1]
        inside = Path(ENGLISH_NAME.get(name, name))
    elif inside.parts and inside.parts[0] in LOCALES and destination.is_dir():
        # A translated page's link to its own index, `./` from docs/it/, plays
        # the part the English link to docs/ does.
        inside = Path('.')
    if anchor and destination.suffix == '.md' and anchor not in _anchors(destination):
        return str(inside), f'links to #{anchor} in {url}, which no heading there produces'
    return str(inside), None


def _cells(prose: list[str]) -> list[int]:
    return [line.strip().strip('|').count('|') + 1
            for line in prose if line.lstrip().startswith('|')]


def _inline_code(prose: list[str]) -> collections.Counter[str]:
    found: collections.Counter[str] = collections.Counter()
    for line in prose:
        found.update(re.findall(r'(?<!`)`([^`]+)`(?!`)', line))
        found.update(re.findall(r'``\s?(.+?)\s?``', line))
    return found


def _comments(text: str) -> collections.Counter[str]:
    return collections.Counter(
        c for c in re.findall(r'<!--.*?-->', text, re.S)
        if MARKER not in c and NOTICE not in c)


def drift(english: Path, translated: Path, docs: Path = DOCS) -> list[str]:
    """How a translation differs from its English page in what a translation
    has no reason to change. Empty when it has the English page's shape."""
    english_text = english.read_text(encoding='utf-8')
    translated_text = translated.read_text(encoding='utf-8')
    english_prose, english_blocks, english_paragraphs = _split(english_text)
    prose, blocks, paragraphs = _split(translated_text)
    found = []

    if len(english_blocks) != len(blocks):
        found.append(f'{len(blocks)} code blocks where the English has '
                     f'{len(english_blocks)}')
    for number, (theirs, ours) in enumerate(zip(english_blocks, blocks, strict=False), 1):
        if (translated.name == 'README.md' and len(theirs) > 1 and len(ours) > 1
                and LISTING.match(theirs[1]) and LISTING.match(ours[1])):
            continue
        if len(theirs) != len(ours):
            found.append(f'code block {number} has {len(ours)} lines where the '
                         f'English has {len(theirs)}')
        else:
            changed = [line for line, original in zip(ours, theirs, strict=True)
                       if not _code_line_matches(original, line)]
            if changed:
                found.append(f'code block {number} changes code, not only '
                             f'comments: {changed[0].strip()!r}')

    levels = [len(m.group(1)) for line in prose
              if (m := re.match(r'^(#{1,6})\s', line))]
    english_levels = [len(m.group(1)) for line in english_prose
                      if (m := re.match(r'^(#{1,6})\s', line))]
    if levels != english_levels:
        found.append(f'{len(levels)} headings where the English has '
                     f'{len(english_levels)}, or at other levels')
    if _cells(prose) != _cells(english_prose):
        found.append('its tables have other rows or cells than the English')
    if len(paragraphs) != len(english_paragraphs):
        found.append(f'{len(paragraphs)} paragraphs where the English has '
                     f'{len(english_paragraphs)}')

    code, english_code = _inline_code(prose), _inline_code(english_prose)
    if code != english_code:
        missing = sorted((english_code - code).elements())
        extra = sorted((code - english_code).elements())
        found.append(f'its inline code differs: missing {missing[:3]}, '
                     f'not in the English {extra[:3]}')
    if _comments(translated_text) != _comments(english_text):
        found.append('its HTML comments differ from the English')

    targets: collections.Counter[str] = collections.Counter()
    for url in _links(prose):
        target, problem = _target(translated, url, docs)
        targets[target] += 1
        if problem:
            found.append(problem)
    english_targets = collections.Counter(
        _target(english, url, docs)[0] for url in _links(english_prose))
    if targets != english_targets:
        missing = sorted((english_targets - targets).elements())
        extra = sorted((targets - english_targets).elements())
        found.append(f'its links go elsewhere: missing {missing[:3]}, '
                     f'not in the English {extra[:3]}')
    return found


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
            if behind:
                continue
            differences = drift(english, translated, DOCS)
            if differences and not marked:
                problems.append(
                    f'{here} records the English it is in step with, and is '
                    f'not: {"; ".join(differences[:3])}. Bring it in step, or '
                    f'add the stale-translation notice in {locale}.')
            if marked and not differences:
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
