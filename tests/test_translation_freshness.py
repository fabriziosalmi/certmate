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
