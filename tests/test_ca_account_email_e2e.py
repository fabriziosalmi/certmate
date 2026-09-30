"""The CA account's email is the one the CA registers (#1045).

Until #1045 the email passed to certbot was the global `email` setting, whatever
CA account the certificate was issued under: the email typed into a CA account
was stored and never used. The unit tests pin the arguments handed to certbot;
what they cannot show is what the CA was actually told, and that is the only
thing that matters to the person whose address it is.

So this issues a REAL certificate from Let's Encrypt STAGING through Cloudflare
DNS-01, under a CA account whose email differs from the global one, and reads
what certbot SENT to the CA in its `newAccount` request (its own debug log).
Before the change that contact is the global email; after it, the account's.

Not `regr.json`: Let's Encrypt no longer echoes the contact back in the account
object, so the file certbot keeps has an empty `body` whichever email was sent.
The first version of this test read it and failed on the right code (measured
2026-09-30). What the CA was TOLD is the claim, so that is what is read.

In-process rather than against the container, like the ARI test: the assertion
is a file certbot writes into the certificate directory.

Requires CLOUDFLARE_API_TOKEN and CERTMATE_TEST_DOMAIN (a zone the token can
edit). Issuance is pinned to staging and the issuer is read off the leaf.
"""
import os
import re
import secrets
import uuid

import pytest

from tests.e2e_support import TEST_EMAIL, assert_staging_issuer

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get('CERTMATE_TEST_DOMAIN', 'gpfree.org')
TEST_DOMAIN = f'ca-acct-{uuid.uuid4().hex[:8]}.{BASE_DOMAIN}'
DNS_ACCOUNT = 'ca-account-e2e'
CA_ACCOUNT = 'second'
# Same mail domain as TEST_EMAIL, which staging is known to accept.
ACCOUNT_EMAIL = f'ca-account-e2e@{TEST_EMAIL.split("@", 1)[1]}'


@pytest.fixture(scope='module')
def instance(tmp_path_factory, cloudflare_token):
    """A real CertMate, in this process, pinned to Let's Encrypt staging, with
    two accounts on the staging CA whose emails differ."""
    assert ACCOUNT_EMAIL != TEST_EMAIL
    tmp = tmp_path_factory.mktemp('ca-account-e2e')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
        from modules.factory import create_app
        _, container = create_app()
        managers = container.managers

        settings_manager = managers['settings']
        settings = settings_manager.load_settings()
        settings.update({
            'email': TEST_EMAIL,
            'default_ca': 'letsencrypt_staging',
            'ca_providers': {
                'letsencrypt': {'email': TEST_EMAIL},
                'letsencrypt_staging': {'accounts': {
                    'default': {'email': TEST_EMAIL},
                    CA_ACCOUNT: {'email': ACCOUNT_EMAIL},
                }},
            },
            'default_ca_accounts': {'letsencrypt_staging': 'default'},
            'dns_provider': 'cloudflare',
            'domains': [{'domain': TEST_DOMAIN, 'dns_provider': 'cloudflare',
                         'account_id': DNS_ACCOUNT, 'auto_renew': False}],
        })
        assert settings_manager.save_settings(settings, 'ca-account-e2e') is not False
        managers['dns'].add_account(
            DNS_ACCOUNT, 'cloudflare', {'api_token': cloudflare_token})
        yield managers['certificates']


def _contacts_sent_to_the_ca(manager):
    """The contact(s) in every `newAccount` request certbot made for the domain.

    certbot logs the payload it POSTs at debug level, as a JSON object. An
    account that already existed would send no such request at all, which is
    why an empty list is a failure below rather than a pass.
    """
    logs = sorted((manager.cert_dir / TEST_DOMAIN / 'logs').rglob('letsencrypt.log*'))
    assert logs, 'certbot left no log for this domain'
    text = '\n'.join(f.read_text(errors='replace') for f in logs)
    # The payload is logged as the repr of a bytes object, so its newlines are
    # the two characters backslash-n, not whitespace.
    return re.findall(r'"contact":(?:\s|\\n)*\[(?:\s|\\n)*"(mailto:[^"]+)"', text)


def test_01_issue_under_the_second_account(instance):
    result = instance.create_certificate(
        TEST_DOMAIN, TEST_EMAIL, 'cloudflare', account_id=DNS_ACCOUNT,
        ca_provider='letsencrypt_staging', ca_account_id=CA_ACCOUNT)
    assert result, result
    pem = (instance.cert_dir / TEST_DOMAIN / 'cert.pem').read_text()
    print('issuer:', assert_staging_issuer(pem))
    assert instance._load_metadata(TEST_DOMAIN).get('ca_account_id') == CA_ACCOUNT


def test_02_the_ca_was_told_the_accounts_email(instance):
    """THE test. The global email is TEST_EMAIL and was passed in above; the
    account says ACCOUNT_EMAIL, and the CA has to have been given that."""
    contacts = _contacts_sent_to_the_ca(instance)
    print('contact(s) sent to the CA:', contacts)
    assert contacts == [f'mailto:{ACCOUNT_EMAIL}'], (
        f'the CA was sent {contacts}, not the CA account email '
        f'(the global email is {TEST_EMAIL})')
