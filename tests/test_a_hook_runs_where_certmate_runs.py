"""Every command the deploy-hook examples show exists where a hook runs.

A deploy hook runs inside the CertMate container, as the process that issued
the certificate. `docs/deploy-hooks.md` used to demonstrate `systemctl reload
haproxy`, `/usr/sbin/nginx -s reload`, `scp` and `ssh`, which read as though
they act on the load balancer and in fact run in a container that has none of
them. #856 is a user who followed the page and got `exit code 127`.

Five of the six example commands could not work. Nothing caught it, because
the examples are prose to every gate in this repository and the image contents
are checked by a different test that does not read them.

So the two are joined here:

* the **unit** test reads the fenced `sh` blocks out of the page and refuses
  any command not on the declared list below;
* the **e2e** test proves the declared list is the image's, so declaring a
  command does not make it exist.

Either alone is decoration. The declaration could drift from reality, or the
image could be checked against nothing in particular.

`$VARIABLES` and absolute paths under `/opt` are allowed through: the first is
substituted at runtime and the second is the operator's own mounted script,
which is a documented pattern rather than a command this image must carry.
"""
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent

# All five, not just English. The translated pages carried the same broken
# recipes and check_translation_freshness passed throughout, because it
# compares source hashes and not truth — which is how this project's oldest
# blind spot keeps producing pages that contradict the code.
DOCS = [REPO / 'docs' / 'deploy-hooks.md'] + [
    REPO / 'docs' / lang / 'deploy-hooks.md' for lang in ('de', 'es', 'fr', 'it')]
DOC = DOCS[0]

# What the runtime stage installs, plus what the base image brings. Kept as a
# literal so the unit test needs no container; `test_the_declared_set_is_the
# _image_s` is what stops it becoming a wish.
#
# This is not the image's whole command set — it is the set the page's examples
# are allowed to draw on, and the e2e test below proves each of them is really
# there. It says nothing about what else the base image carries.
COMMANDS_THE_IMAGE_HAS = {'sh', 'bash', 'curl', 'openssl', 'echo', 'exit',
                          'set', 'cd', 'test', '[', 'grep'}

# Commands named in the page only to say they are NOT available. Listing them
# here rather than excluding the section wholesale means removing the warning
# does not silently re-permit them.
NAMED_AS_ABSENT = {'ssh', 'scp', 'sftp', 'rsync', 'jq', 'nginx', 'systemctl',
                   'haproxy'}


def _example_commands(doc=None):
    """The first word of every command line in a page's ``sh`` blocks."""
    text = (doc or DOC).read_text(encoding='utf-8')
    found = []
    for match in re.finditer(r'```sh\n(.*?)```', text, re.S):
        line_no = text[:match.start()].count('\n') + 1
        for raw in match.group(1).splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            # One command per line in these examples; `&&` and `;` are
            # rejected by the validator, so anything after them is not a
            # command CertMate would run.
            first = line.split()[0]
            if first.startswith('$') or first.startswith('"'):
                continue          # a variable, substituted at runtime
            found.append((line_no, first))
    return found


def _inline_pipelines(doc=None):
    """Commands shown in a pipeline written inline in the prose.

    The fenced-block reader above misses these, and one slipped through: the
    page explained that a simple pipe is allowed on purpose with the example
    `curl ... | jq .`, forty-five lines above a table that lists `jq` among the
    commands the image does not have. The same page, contradicting itself, past
    a gate that only looked at fenced blocks.

    **Only pipelines, and that is deliberate.** A gate over all inline code
    would have to tell a recipe apart from a counter-example, and this page is
    full of the latter — `systemctl reload haproxy` appears precisely to say it
    does not work. No syntax distinguishes them, and a gate needing an
    exception list for prose is a gate that rots. A pipeline is different: it
    is always something being shown as writable.

    Segments that do not begin with a word character or `/` are skipped, which
    is how the escaped `\\|\\|` in the blocked-patterns table stays out.
    """
    text = (doc or DOC).read_text(encoding='utf-8')
    text = re.sub(r'```.*?```', '', text, flags=re.S)
    found = []
    for span in re.findall(r'`([^`\n]+)`', text):
        if '|' not in span:
            continue
        for segment in span.split('|'):
            token = segment.strip().split()[0] if segment.strip() else ''
            if not token or not re.match(r'[\w/]', token):
                continue
            if token.startswith('$'):
                continue
            found.append((span, token))
    return found


def test_the_page_still_has_examples():
    """Guard the guard: an empty list would make the check below vacuous."""
    assert len(_example_commands()) >= 4


@pytest.mark.unit
@pytest.mark.parametrize('doc', DOCS, ids=[d.parent.name for d in DOCS])
def test_every_example_command_exists_in_the_image(doc):
    """The check #856 needed and nobody had, in every language."""
    offenders = [
        (line, cmd) for line, cmd in _example_commands(doc)
        if cmd not in COMMANDS_THE_IMAGE_HAS
        and not cmd.startswith('/opt/')
    ]
    assert not offenders, (
        f'{doc.relative_to(REPO)} demonstrates commands the image does not carry, '
        'and a hook runs inside that image:\n' +
        '\n'.join(f'  line {line}: {cmd}' for line, cmd in offenders) +
        '\nEither use a command the image has, or show it as a derived-image '
        'or over-the-network pattern rather than as a recipe.'
    )


@pytest.mark.unit
@pytest.mark.parametrize('doc', DOCS, ids=[d.parent.name for d in DOCS])
def test_a_pipeline_shown_in_the_prose_can_run(doc):
    """Both sides of a pipe the page offers as an example must exist.

    The English and Italian pages showed `curl ... | jq .`; `jq` is named on
    the same page as absent from the image.
    """
    offenders = [(span, cmd) for span, cmd in _inline_pipelines(doc)
                 if cmd not in COMMANDS_THE_IMAGE_HAS and not cmd.startswith('/opt/')]
    assert not offenders, (
        f'{doc.relative_to(REPO)} shows a pipeline using a command the image '
        f'does not carry:\n' +
        '\n'.join(f'  `{span}` -> {cmd}' for span, cmd in offenders))


def test_at_least_one_page_shows_a_pipeline():
    """Guard the guard: if the prose stops containing pipelines the check
    above passes over nothing, and would keep passing if one came back."""
    assert any(_inline_pipelines(doc) for doc in DOCS)


WHERE_IT_RUNS = {'docs': 'Inside the CertMate container',
                 'de': 'Im CertMate-Container',
                 'es': 'Dentro del contenedor de CertMate',
                 'fr': 'Dans le conteneur CertMate',
                 'it': 'Dentro il container di CertMate'}


@pytest.mark.unit
@pytest.mark.parametrize('doc', DOCS, ids=[d.parent.name for d in DOCS])
def test_the_page_says_where_a_hook_runs(doc):
    """The commands being right is not enough if a reader still believes the
    hook runs on the Docker host."""
    text = doc.read_text(encoding='utf-8')
    assert WHERE_IT_RUNS[doc.parent.name] in text


@pytest.mark.unit
@pytest.mark.parametrize('doc', DOCS, ids=[d.parent.name for d in DOCS])
@pytest.mark.parametrize('command', sorted(NAMED_AS_ABSENT))
def test_the_page_names_what_is_missing_rather_than_staying_silent(doc, command):
    """An operator who reaches for scp should find out from the page, not
    from exit code 127 — in whichever language they read."""
    text = doc.read_text(encoding='utf-8')
    assert f'`{command}`' in text, (
        f'{command} is not in the image and {doc.relative_to(REPO)} does not say so'
    )


@pytest.mark.e2e
def test_the_declared_set_is_the_images():
    """Proves COMMANDS_THE_IMAGE_HAS describes the built image.

    Without this the unit test above checks the page against a list somebody
    wrote down, which is exactly the kind of agreement that drifts.
    """
    probe = '; '.join(
        f'command -v {c} >/dev/null 2>&1 || echo MISSING:{c}'
        for c in sorted(COMMANDS_THE_IMAGE_HAS)
    )
    from tests.conftest import IMAGE_NAME
    result = subprocess.run(
        ['docker', 'run', '--rm', '--entrypoint', 'sh', IMAGE_NAME, '-c', probe],
        capture_output=True, text=True, timeout=120)
    missing = [line.split(':', 1)[1]
               for line in result.stdout.splitlines() if line.startswith('MISSING:')]
    assert not missing, (
        f'declared as present and absent from the image: {missing}. '
        f'The examples in docs/deploy-hooks.md are checked against this list.'
    )


@pytest.mark.e2e
def test_what_the_page_calls_absent_really_is():
    """The other direction. If `scp` were added to the image one day, this
    fails and the page's warning gets removed with the same change — rather
    than telling people for years that it is missing."""
    probe = '; '.join(
        f'command -v {c} >/dev/null 2>&1 && echo PRESENT:{c}'
        for c in sorted(NAMED_AS_ABSENT)
    )
    from tests.conftest import IMAGE_NAME
    result = subprocess.run(
        ['docker', 'run', '--rm', '--entrypoint', 'sh', IMAGE_NAME, '-c', probe],
        capture_output=True, text=True, timeout=120)
    present = [line.split(':', 1)[1]
               for line in result.stdout.splitlines() if line.startswith('PRESENT:')]
    assert not present, (
        f'the page says these are not in the image, and they are: {present}. '
        f'Update docs/deploy-hooks.md and NAMED_AS_ABSENT together.'
    )
