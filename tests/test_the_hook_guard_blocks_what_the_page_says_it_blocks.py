"""Every pattern `docs/deploy-hooks.md` lists as blocked is actually rejected.

The page has a **Blocked shell patterns** table. It is the thing an operator
reads before deciding a hook is safe to save, and nothing tied it to
`DeployManager._is_command_safe`.

One row was false, and had been since it was written. The rule for the `.`
source shorthand was `\\b\\.\\s+/`, and `\\b` before a dot requires a **word**
character immediately before it. A command either starts with `. `, or has
` . ` after a space or a pipe — in every one of those the character before the
dot is a space or nothing, so no word boundary exists and the rule never fired.
Measured before the fix:

    . /opt/x.sh            -> (True, None)
    echo a | . /opt/x.sh   -> (True, None)
    x . /opt/x.sh          -> (True, None)

`tests/test_security_policy_matches_the_code.py` does this for SECURITY.md's
five named secrets and its metacharacter sentence, and it is the reason those
cannot drift. It does not cover this table, and the `.` row is not among the
metacharacters it probes. So: same shape, this page.

**The probes are written by hand, and that is the part that needs a guard of
its own.** A table cell like ``\\r`` / ``\\n`` does not turn itself into a
command. So the table and the probes are checked against each other in **both**
directions: a row added without a probe fails, and a probe whose row has gone
fails too. The first version had only the first direction, and a mutation that
deleted the `eval` / `source` / `.` row from the page passed the whole file —
coverage that looks complete and is half.
"""
import pathlib

import pytest

from modules.core.deployer import DeployManager

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
PAGE = REPO / 'docs' / 'deploy-hooks.md'

# One concrete command per table row, keyed by a substring of the row's first
# cell. Each must be rejected, and rejected AS A METACHARACTER — a command that
# happened to be refused for its length or for naming settings.json would pass
# a weaker assertion while saying nothing about the rule under test.
PROBES = {
    '` ``':      'echo `whoami`',
    '$(...)':    'echo $(id)',
    '${...}':    'echo ${CERTMATE_DOMAIN:-/etc/passwd}',
    '&&':        'echo hi && rm -rf /',
    ';':         'echo hi; rm -rf /',
    r'\r':       'echo hi\nrm -rf /',
    '> /':       'echo hi > /etc/passwd',
    '<<':        'cat <<EOF',
    'eval':      'eval rm -rf /',
}

# The row that was false. Every shape of it, because the defect was that the
# rule matched one shape nobody writes and none of the three that people do.
SOURCE_SHORTHAND = [
    '. /opt/x.sh',            # at the start of the command
    'echo a | . /opt/x.sh',   # after a pipe, which the validator allows
    'x . /opt/x.sh',          # after another word
    '. ./x.sh',               # a relative path
    '. x.sh',                 # no path separator at all
]


def _table_rows():
    """The first cell of every row in the Blocked shell patterns table."""
    text = PAGE.read_text(encoding='utf-8')
    section = text[text.index('### Blocked shell patterns'):]
    section = section[:section.index('\n\n', section.index('|---'))]
    rows = [line.split('|')[1].strip()
            for line in section.splitlines()
            if line.startswith('|') and not line.startswith('|---')]
    return [r for r in rows if r != 'Pattern']


def test_the_table_is_still_there():
    """Guard the guard: an empty table would make every check below vacuous."""
    rows = _table_rows()
    assert len(rows) >= 8, rows


def test_every_row_has_a_probe():
    """A row added to the page without a probe here is a claim nobody checks.

    `eval`, `source` and `.` share a row, so that row is matched by 'eval' and
    covered further by the source-shorthand test below.
    """
    unprobed = [row for row in _table_rows()
                if not any(key in row for key in PROBES)]
    assert not unprobed, (
        f'docs/deploy-hooks.md lists these as blocked and nothing here proves '
        f'they are: {unprobed}. Add a probe to PROBES.'
    )


@pytest.mark.parametrize('key', sorted(PROBES))
def test_every_probe_still_matches_a_row(key):
    """The other direction, and it was missing.

    `test_every_row_has_a_probe` only walks rows -> probes, so deleting the
    `eval` / `source` / `.` row from the page broke nothing: a mutation that
    removed it passed the whole file. An operator would simply stop being told
    about a restriction the validator still enforces, and would meet it as a
    refusal they cannot explain.

    Checking both directions is what makes the table and the probes hold each
    other up, rather than one of them being free to drift.
    """
    assert any(key in row for row in _table_rows()), (
        f'nothing in the Blocked shell patterns table matches {key!r} any '
        f'more. Either the page stopped documenting a rule the validator '
        f'still has, or the probe is stale — both need a decision, not a '
        f'silent pass.'
    )


@pytest.mark.parametrize('key', sorted(PROBES))
def test_each_documented_pattern_is_rejected(key):
    command = PROBES[key]
    safe, reason = DeployManager._is_command_safe(command)
    assert safe is False, (
        f'the page lists {key} as blocked and {command!r} was accepted'
    )
    assert 'metacharacter' in (reason or ''), (
        f'{command!r} was rejected for {reason!r}, not as a metacharacter'
    )


@pytest.mark.parametrize('command', SOURCE_SHORTHAND)
def test_the_source_shorthand_is_rejected_in_every_shape(command):
    """The row that was false. Three of these were accepted before the fix."""
    safe, reason = DeployManager._is_command_safe(command)
    assert safe is False, f'{command!r} sources a file and was accepted'
    assert 'metacharacter' in (reason or '')


def test_source_and_its_shorthand_are_treated_alike():
    """The asymmetry was the defect. `source` is blocked whatever its
    argument; the old rule only looked for an absolute path after the dot, so
    `. x.sh` was accepted while `source x.sh` was not."""
    for pair in (('source x.sh', '. x.sh'), ('source /opt/x.sh', '. /opt/x.sh')):
        long_form, short_form = (DeployManager._is_command_safe(c)[0] for c in pair)
        assert long_form == short_form is False, pair


# ── the other direction: nothing useful got caught in the net ────────

STILL_ALLOWED = [
    '/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"',
    'curl -fsS https://lb.internal/api/reload',
    'openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates',
    'curl -fsS https://lb.internal/api/reload | grep -q ok',
    'echo done > out.txt',
    'cat /opt/certs/fullchain.pem',
]


@pytest.mark.parametrize('command', STILL_ALLOWED)
def test_the_hooks_people_actually_write_still_pass(command):
    """A blanket rule on the dot would refuse every path with an extension in
    it. These are the page's own examples, and a fix that broke them would be
    worse than the gap it closed."""
    safe, reason = DeployManager._is_command_safe(command)
    assert safe is True, f'{command!r} was rejected: {reason}'
