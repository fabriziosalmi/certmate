"""A failed issuance says what the CA said, first (#1427).

On a failed authorization certbot writes "Some challenges have failed." to stderr
and the CA's reason to stdout. The failure message was built from stderr and used
stdout only when stderr was empty, so it read "Some challenges have failed. Ask for
help or search for solutions at ..." and the reason was in certbot's log file alone.
The certificate list shows 140 characters of the message, which ended at "See the".

The output below is certbot 5.8.0's, captured on 2026-11-11 from an order against
Let's Encrypt staging for a name with no TXT record (manual hook that publishes
nothing), with the log paths shortened.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

STDERR = (
    'Saving debug log to /data/certificates/x/logs/letsencrypt.log\n'
    'Some challenges have failed.\n'
    'Ask for help or search for solutions at https://community.letsencrypt.org. See the logfile '
    '/data/certificates/x/logs/letsencrypt.log or re-run Certbot with -v for more details.\n')

STDOUT = (
    'Account registered.\n'
    'Requesting a certificate for nx-1427.certmate.org\n'
    '\n'
    'Certbot failed to authenticate some domains (authenticator: manual). The Certificate '
    'Authority reported these problems:\n'
    '  Identifier: nx-1427.certmate.org\n'
    '  Type:   unauthorized\n'
    '  Detail: No TXT record found at _acme-challenge.nx-1427.certmate.org\n'
    '\n'
    'Hint: The Certificate Authority failed to verify the DNS TXT records created by the '
    '--manual-auth-hook.\n')

REASON = 'nx-1427.certmate.org: No TXT record found at _acme-challenge.nx-1427.certmate.org'


def _failure(stdout, stderr=STDERR, returncode=1, prefix='Certificate creation failed'):
    manager = CertificateManager.__new__(CertificateManager)
    return manager._certbot_failure(prefix, 'nx-1427.certmate.org',
                                    MagicMock(returncode=returncode, stdout=stdout, stderr=stderr))


@pytest.mark.parametrize('prefix', ['Certificate creation failed', 'Renewal failed'])
def test_the_message_starts_with_the_cas_reason(prefix):
    text = _failure(STDOUT, prefix=prefix)

    assert text.startswith(f'{prefix}: {REASON}\n'), text
    # certbot's own line is still there, after the reason.
    assert 'Some challenges have failed.' in text


def test_the_list_row_shows_the_reason():
    """The certificate list shows the first 140 characters of the message."""
    assert 'No TXT record found' in _failure(STDOUT)[:140]


def test_every_refused_identifier_is_named_once():
    """certbot's own tests: one block per identifier, the same error repeated."""
    stdout = ('The Certificate Authority reported these problems:\n'
              '  Identifier: foo.example\n  Type:   dns\n  Detail: DNS problem: NXDOMAIN looking up TXT\n\n'
              '  Identifier: bar.example\n  Type:   dns\n  Detail: DNS problem: SERVFAIL looking up TXT\n\n'
              '  Identifier: foo.example\n  Type:   dns\n  Detail: DNS problem: NXDOMAIN looking up TXT\n')
    text = _failure(stdout)

    assert text.count('foo.example: DNS problem: NXDOMAIN looking up TXT') == 1
    assert 'bar.example: DNS problem: SERVFAIL looking up TXT' in text


def test_the_wording_of_older_certbots_is_read_too():
    stdout = ('The Certificate Authority reported these problems:\n'
              '  Domain: old.example\n  Type:   unauthorized\n  Detail: Incorrect TXT record\n')

    assert 'old.example: Incorrect TXT record' in _failure(stdout)


def test_detail_lines_without_certbots_marker_are_not_taken_for_the_cas_answer():
    stdout = 'Requesting a certificate\n  Identifier: x.example\n  Detail: something a plugin printed\n'

    assert 'something a plugin printed' not in _failure(stdout)


def test_a_certbot_that_wrote_nothing_on_stderr_still_leads_with_the_reason():
    text = _failure(STDOUT, stderr='')

    assert text.startswith(f'Certificate creation failed: {REASON}\n'), text
    assert 'certbot exited with code 1' in text


def test_a_credential_in_a_detail_line_is_redacted():
    stdout = ('The Certificate Authority reported these problems:\n'
              '  Identifier: x.example\n  Type:   dns\n'
              '  Detail: dns_cloudflare_api_token = sEcReT-do-not-print\n')

    assert 'sEcReT' not in _failure(stdout)
