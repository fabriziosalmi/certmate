"""docs/custom-dns-script.md says what the code does (#642).

`custom-script` is the answer for a DNS provider with no certbot plugin and no
`dns-lexicon` support — Total Uptime and Netriplex, in the report that prompted
this. The answer was correct and it lived in a GitHub issue comment: the repo's
own DNS page gave `custom-script` two lines of JSON, so the next person with an
unsupported provider had to ask rather than read.

The page is new, which is the moment its claims are cheapest to anchor. Every
assertion here names something a reader would act on, and reads it from the
code rather than from a previous copy of the prose.
"""
import inspect
import pathlib
import re

import pytest

from modules.core.dns_strategies import CustomScriptStrategy

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
PAGE = REPO / 'docs' / 'custom-dns-script.md'


@pytest.fixture(scope='module')
def page():
    return PAGE.read_text(encoding='utf-8')


def test_the_certbot_arguments_are_the_ones_the_page_shows(page):
    """The page prints the command CertMate builds. If the flags change, the
    reader debugging a failed hook is looking at the wrong command."""
    source = inspect.getsource(CustomScriptStrategy.configure_certbot_arguments)
    for flag in ('--manual', '--preferred-challenges', '--manual-auth-hook',
                 '--manual-cleanup-hook'):
        assert flag in source, f'{flag} is no longer emitted'
        assert flag in page, f'the page does not show {flag}'
    assert "'dns'" in source and 'dns' in page


def test_every_path_rule_the_page_lists_is_a_rule_the_code_enforces(page):
    """Six checks, and the page tabulates all six. Two of them — world- and
    group-writable — are refusals rather than advice, and an earlier draft of
    this page got that wrong in both directions: it counted five checks and
    described the permission ones as good practice."""
    source = inspect.getsource(CustomScriptStrategy._validated_hook_path)
    checks = {
        'absolute': 'is_absolute',
        'an existing file': 'is_file',
        'executable': 'os.X_OK',
        'shell-safe': 'shlex.quote',
        'not world-writable': '0o002',
        'not group-writable': '0o020',
    }
    for label, marker in checks.items():
        assert marker in source, f'the {label} check is gone from the code'
    # The page must name the two permission modes, because "chmod 755 or
    # stricter" is advice a reader can act on only if they know what is refused.
    assert '0o002' in page and '0o020' in page
    assert page.count('world-writable') >= 2
    assert page.count('group-writable') >= 2


def test_the_page_does_not_promise_a_propagation_flag(page):
    """`--manual` has no propagation flag, so waiting is the script's job. A
    page that implied otherwise would produce hooks that return too early, and
    the failure reads as a DNS problem rather than a timing one."""
    assert CustomScriptStrategy().supports_propagation_seconds_flag is False
    assert 'no propagation flag' in page
    assert 'CERTMATE_DNS_PROPAGATION_SECONDS' in page

    exported = inspect.getsource(CustomScriptStrategy.prepare_environment)
    assert 'CERTMATE_DNS_PROPAGATION_SECONDS' in exported, (
        'the page tells scripts to read a variable nothing exports'
    )


def test_the_required_credential_is_the_one_the_page_marks_required(page):
    """`auth_hook` required, `cleanup_hook` optional. The page's table says so
    and the registry is where that is decided."""
    from modules.core.utils import _DNS_PROVIDER_CREDENTIALS

    assert _DNS_PROVIDER_CREDENTIALS['custom-script'] == ['auth_hook']

    table = page.split('| field | required |', 1)[1].split('\n\n', 1)[0]
    auth = next(line for line in table.splitlines() if '`auth_hook`' in line)
    cleanup = next(line for line in table.splitlines() if '`cleanup_hook`' in line)
    assert '**yes**' in auth
    assert '| no |' in cleanup

    source = inspect.getsource(CustomScriptStrategy.create_config_file)
    assert "requires an 'auth_hook'" in source


def test_the_environment_table_matches_certbot_itself(page):
    """The variables come from certbot, not from CertMate, so they are read
    from the installed certbot rather than asserted from memory.

    `CERTBOT_TOKEN` is the one worth pinning: the page says it is NOT set for
    DNS-01, and certbot pops it from the environment in the non-HTTP-01 branch.
    A reader who wrote a hook expecting it would get an empty string and a
    confusing failure."""
    import certbot

    manual = next(pathlib.Path(certbot.__file__).parent.rglob('manual.py'))
    source = manual.read_text(encoding='utf-8')

    for variable in ('CERTBOT_DOMAIN', 'CERTBOT_VALIDATION', 'CERTBOT_ALL_DOMAINS',
                     'CERTBOT_REMAINING_CHALLENGES', 'CERTBOT_AUTH_OUTPUT'):
        assert f'"{variable}"' in source or f"'{variable}'" in source, (
            f'{variable} is not in certbot {certbot.__version__} any more'
        )
        assert variable in page, f'the page omits {variable}'

    assert "os.environ.pop('CERTBOT_TOKEN', None)" in source, (
        'certbot no longer removes CERTBOT_TOKEN for non-HTTP-01 challenges; '
        'the page claims it is not set for DNS-01'
    )
    token_row = next(line for line in page.splitlines() if 'CERTBOT_TOKEN' in line)
    assert 'not set' in token_row.lower()


def test_the_page_names_the_certbot_version_it_was_checked_against(page):
    """It cites a version, and that version is the one pinned. A contract read
    out of a different release is a contract read out of a different product."""
    import certbot

    cited = re.search(r'certbot (\d+\.\d+\.\d+)', page)
    assert cited, 'the page does not say which certbot it was verified against'
    assert cited.group(1) == certbot.__version__, (
        f'the page cites certbot {cited.group(1)}; {certbot.__version__} is '
        'installed. Re-read manual.py before changing the number.'
    )


def test_the_page_is_reachable_from_the_places_a_reader_starts():
    """A page nobody links to is a page nobody finds, which is the defect this
    fixes rather than a detail of it. tests/test_docs_navigation.py enforces the
    index and the translated trees; this names the DNS page specifically,
    because that is where someone with an unsupported provider actually lands."""
    dns_page = (REPO / 'docs' / 'dns-providers.md').read_text(encoding='utf-8')
    assert 'custom-dns-script.md' in dns_page

    for lang in ('it', 'de', 'fr', 'es'):
        translated = (REPO / 'docs' / lang / 'dns-providers.md').read_text(encoding='utf-8')
        assert '../custom-dns-script.md' in translated, (
            f'{lang} does not point at the English original'
        )
