"""A translated page that is behind its English source has to say so.

#674 calls the four extra locales "a standing correctness liability on
documentation that includes security guidance", because "stale translated
security docs are worse than none". That is not a worry about the future here:
on 2026-09-16 all four translations of `docs/mcp.md` still described a
job-polling loop the English page had been fixed on 2026-08-10 for not being
able to run, and all four translations of `docs/api.md` predated the change
that made `code` a string everywhere, which was a breaking contract change.

The checker does not demand current translations. No gate can produce those,
and whether to keep four locales at all is the decision #674 is about. It
demands that improving the English either brings the translation with it or
leaves the translation saying, in its own language, that it is behind.
"""
import pathlib
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
CHECKER = REPO / 'scripts' / 'check_translation_freshness.py'
WORKFLOW = REPO / '.github' / 'workflows' / 'ci.yml'


def _namespace():
    namespace = {'__file__': str(CHECKER), '__name__': 'check_translation_freshness'}
    exec(compile(CHECKER.read_text(encoding='utf-8'), str(CHECKER), 'exec'),
         namespace)
    return namespace


CHECK = _namespace()


def test_editing_a_translation_does_not_make_it_look_fresh():
    """The defect the first version of this had, kept as a test.

    Freshness was compared by commit date, so adding the stale notice to a
    page made that page the most recently committed of the pair, and all 24
    pages it had just marked came out looking fresher than their sources. The
    recorded hash is of the ENGLISH text, so nothing done to the translation
    can move it.
    """
    page = REPO / 'docs' / 'it' / 'mcp.md'
    before = CHECK['recorded_source'](page.read_text(encoding='utf-8'))
    after = CHECK['recorded_source'](
        page.read_text(encoding='utf-8') + '\n\nqualcosa in piu\n')

    assert before == after and before is not None


def test_every_stale_page_says_so_today():
    result = subprocess.run([sys.executable, str(CHECKER)],
                            cwd=REPO, capture_output=True, text=True, timeout=600)

    assert result.returncode == 0, result.stdout + result.stderr


def test_it_compares_something():
    """CONTROL for the instrument: a layout change that broke the pairing would
    make this pass over nothing, and only the no-pairs arm would notice."""
    problems = CHECK['evaluate']()

    assert problems == [], '\n'.join(problems)
    assert len(CHECK['LOCALES']) == 4
    assert sum(1 for _ in (REPO / 'docs' / 'it').glob('*.md')) > 10


def test_every_translated_page_records_its_source():
    """Without the marker there is nothing to compare, and the page would pass
    by being unreadable rather than by being current."""
    missing = []
    for locale in CHECK['LOCALES']:
        for page in sorted((REPO / 'docs' / locale).glob('*.md')):
            english = REPO / 'docs' / CHECK['ENGLISH_NAME'].get(page.name, page.name)
            if english.exists() and CHECK['recorded_source'](
                    page.read_text(encoding='utf-8')) is None:
                missing.append(str(page.relative_to(REPO)))

    assert not missing, f'no recorded source on: {missing}'


def test_the_odd_english_name_is_not_a_second_convention():
    """`probes.en.md` is the one English page named unlike its translations.

    tests/test_docs_navigation.py already decided how to pair it. The checker
    mirrors that mapping rather than renaming the file or inventing its own,
    and this fails if the two ever disagree.
    """
    navigation = {}
    source = (REPO / 'tests' / 'test_docs_navigation.py').read_text(encoding='utf-8')
    namespace: dict = {}
    for line in source.splitlines():
        if line.startswith('TRANSLATED_NAME'):
            exec(line, namespace)
            navigation = namespace['TRANSLATED_NAME']
            break

    assert navigation, 'test_docs_navigation.py no longer defines TRANSLATED_NAME'
    mirrored = {value: key for key, value in navigation.items()}

    assert CHECK['ENGLISH_NAME'] == mirrored, (
        f'the checker pairs {CHECK["ENGLISH_NAME"]} and the navigation test '
        f'pairs {navigation}. Two conventions for one file is how the pairing '
        f'silently stops matching.'
    )


def test_ci_runs_it():
    assert 'check_translation_freshness.py' in WORKFLOW.read_text(encoding='utf-8')


def test_the_notice_is_in_the_readers_language():
    """A warning a reader cannot read is not a warning.

    Each locale's notice carries a word that only appears in that language, so
    a copy-paste of the English one into all four would fail here.
    """
    docs = REPO / 'docs'
    signature = {'de': 'Übersetzung', 'es': 'traducción',
                 'fr': 'traduction', 'it': 'traduzione'}
    for locale, word in signature.items():
        marked = [p for p in sorted((docs / locale).glob('*.md'))
                  if CHECK['NOTICE'] in p.read_text(encoding='utf-8')]
        assert marked, f'no page in docs/{locale}/ carries the notice'
        for page in marked:
            body = page.read_text(encoding='utf-8')
            index = body.index(CHECK['NOTICE'])
            assert word.lower() in body[index:index + 400].lower(), (
                f'{page.relative_to(REPO)} carries the notice but not in '
                f'{locale}: the reader it is for cannot read it'
            )


ENGLISH_PAGE = '''# Page

Intro with `inline_code`, see [other](./other.md#second) and [below](#first).

## First

```bash
# make it
run --flag
```

| A | B |
|---|---|
| 1 | 2 |

<!-- keep me -->

Last paragraph.
'''

TRANSLATED_PAGE = '''# Pagina

<!-- CERTMATE-TRANSLATED-FROM {stamp} -->

Introduzione con `inline_code`, vedi [altro](./other.md#secondo) e [sotto](#primo).

## Primo

```bash
# fallo
run --flag
```

| A | B |
|---|---|
| 1 | 2 |

<!-- keep me -->

Ultimo paragrafo.
'''


def _tree(tmp_path, translated=TRANSLATED_PAGE):
    """docs/page.md and its Italian translation, plus a page both link to."""
    docs = tmp_path / 'docs'
    (docs / 'it').mkdir(parents=True)
    (docs / 'other.md').write_text('# Other\n\n## Second\n', encoding='utf-8')
    (docs / 'it' / 'other.md').write_text('# Altro\n\n## Secondo\n', encoding='utf-8')
    english = docs / 'page.md'
    english.write_text(ENGLISH_PAGE, encoding='utf-8')
    page = docs / 'it' / 'page.md'
    stamp = CHECK['digest'](english.read_bytes())
    page.write_text(translated.replace('{stamp}', stamp), encoding='utf-8')
    return docs, english, page


def test_a_translation_with_the_english_shape_has_no_drift(tmp_path):
    """CONTROL for the cases below: headings, prose and comment text are
    translated, links point at the translated page and its translated anchor,
    and none of that is drift."""
    docs, english, page = _tree(tmp_path)

    assert CHECK['drift'](english, page, docs) == []


@pytest.mark.parametrize('old, new, expected', [
    ('run --flag', 'esegui --flag', 'changes code'),
    ('```bash\n# fallo\nrun --flag\n```\n\n', '', 'code blocks'),
    ('# fallo\n', '# fallo\n# di nuovo\n', 'lines where the English has'),
    ('## Primo\n\n', '### Primo\n\n', 'headings'),
    ('| 1 | 2 |\n', '', 'tables'),
    ('Ultimo paragrafo.', 'Ultimo\n\nparagrafo.', 'paragraphs'),
    ('`inline_code`', '`codice_inline`', 'inline code'),
    ('./other.md#secondo', './other.md#second', 'no heading there produces'),
    ('(#primo)', '(#primo-capitolo)', 'no heading there produces'),
    ('./other.md#secondo', './missing.md', 'does not exist'),
    ('./other.md#secondo', '../page.md', 'links go elsewhere'),
    ('<!-- keep me -->', '<!-- tienimi -->', 'HTML comments'),
], ids=['code', 'block-gone', 'block-longer', 'heading-level', 'table-row',
        'paragraph', 'inline-code', 'cross-page-anchor', 'in-page-anchor',
        'dead-link', 'other-target', 'html-comment'])
def test_each_difference_a_translation_has_no_reason_for_is_drift(
        tmp_path, old, new, expected):
    assert old in TRANSLATED_PAGE
    docs, english, page = _tree(tmp_path, TRANSLATED_PAGE.replace(old, new, 1))

    found = CHECK['drift'](english, page, docs)

    assert any(expected in difference for difference in found), found


def test_a_translated_comment_is_not_drift(tmp_path):
    """The one text inside a code block a translation may change."""
    docs, english, page = _tree(
        tmp_path, TRANSLATED_PAGE.replace('# fallo', '# fallo davvero'))

    assert CHECK['drift'](english, page, docs) == []


def _evaluate_on(tmp_path, monkeypatch, translated):
    docs, _, _ = _tree(tmp_path, translated)
    for locale in ('de', 'es', 'fr'):
        (docs / locale).mkdir()
    monkeypatch.setitem(CHECK, 'DOCS', docs)
    monkeypatch.setitem(CHECK, 'REPO', tmp_path)
    return [p for p in CHECK['evaluate']() if 'page.md' in p]


NOTICE_LINES = ('<!-- CERTMATE-STALE-TRANSLATION -->\n'
                '> **Questa traduzione non è allineata alla versione inglese** '
                '([`docs/page.md`](../page.md)).\n')


def test_a_stamped_page_that_drifts_has_to_say_so(tmp_path, monkeypatch):
    """The stamp is the current English, so only the page itself can show it
    is not in step: before 2026-10-16 this passed."""
    found = _evaluate_on(tmp_path, monkeypatch,
                         TRANSLATED_PAGE.replace('run --flag', 'esegui --flag'))

    assert len(found) == 1 and 'records the English it is in step with' in found[0]


def test_a_stamped_page_that_drifts_and_says_so_passes(tmp_path, monkeypatch):
    translated = TRANSLATED_PAGE.replace('run --flag', 'esegui --flag').replace(
        '-->\n', '-->\n' + NOTICE_LINES, 1)

    assert _evaluate_on(tmp_path, monkeypatch, translated) == []


def test_a_page_in_step_may_not_carry_the_notice(tmp_path, monkeypatch):
    """The notice and its link are left out of the comparison. Counted in, they
    made every marked page differ from its English, so this arm could never
    fire."""
    found = _evaluate_on(tmp_path, monkeypatch,
                         TRANSLATED_PAGE.replace('-->\n', '-->\n' + NOTICE_LINES, 1))

    assert len(found) == 1 and 'Remove the notice' in found[0]


def _readme_pair(tmp_path, english, translated, name='README.md'):
    docs = tmp_path / 'docs'
    (docs / 'it').mkdir(parents=True)
    (docs / name).write_text(english, encoding='utf-8')
    (docs / 'it' / name).write_text(translated, encoding='utf-8')
    return docs, docs / name, docs / 'it' / name


ENGLISH_INDEX = '''# Documentation

```
docs/
  README.md      this file
  api.md         the API
  webhooks.md    webhooks
```

[Documentation](./)
'''

ITALIAN_INDEX = '''# Documentazione

```
docs/it/
  README.md      questo file
```

[Documentazione](./)
'''


def test_a_readme_lists_its_own_directory(tmp_path):
    """tests/test_docs_navigation.py holds each README's listing to the files
    in its own directory, so a translated listing differs from the English
    one by design, and its link to its own index plays the part of the
    English link to docs/. Before this, no translated README could pass."""
    docs, english, page = _readme_pair(tmp_path, ENGLISH_INDEX, ITALIAN_INDEX)

    assert CHECK['drift'](english, page, docs) == []


def test_only_the_readme_listing_is_left_to_the_navigation_test(tmp_path):
    """CONTROL: the same block in any other page is code like any other."""
    docs, english, page = _readme_pair(tmp_path, ENGLISH_INDEX, ITALIAN_INDEX,
                                       name='index.md')

    assert any('code block 1' in d for d in CHECK['drift'](english, page, docs))


def test_the_listing_still_has_to_be_there(tmp_path):
    docs, english, page = _readme_pair(
        tmp_path, ENGLISH_INDEX,
        ITALIAN_INDEX.replace('```\ndocs/it/\n  README.md      questo file\n```\n\n', ''))

    assert any('code blocks' in d for d in CHECK['drift'](english, page, docs))
