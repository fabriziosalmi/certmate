"""A webhook could announce a renewal; now it can deliver one (#218).

The payload template shipped in #580 with `{{event}} {{title}} {{message}}
{{timestamp}} {{domain}} {{details}} {{details.<field>}}` — everything the
event carries. The reporter's actual need was the other thing: "the
`CERTMATE_` variables point at paths on disk, and an ingestion endpoint wants
the material in the body". The maintainer's own summary of the gap was
"what shipped is a webhook that can **announce** a renewal. What you asked
for is one that can **deliver** it."

So `{{cert}}` and `{{fullchain}}`, and the two constraints that shape them:

**On demand, never on the bus.** Every other variable comes out of the event's
`details` dict, and `details` goes to every subscriber of the event bus. A PEM
placed there would be handed to listeners that asked for nothing. These two
are read from disk at delivery time, and only when the template being rendered
actually names them.

**`{{privkey}}` is not here.** It is the one secret in the directory, and the
question it is waiting on — whether an ingestion endpoint wants the key in the
same request as the certificate — is open in #218 since 2026-08-28. An unknown
placeholder renders empty, so a template that asks for it gets nothing rather
than an error, and `privkey.pem` is never opened.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core import notifier as notifier_mod
from modules.core.notifier import (
    CERT_MATERIAL_FILES, Notifier, template_references,
    webhook_template_variables,
)

pytestmark = [pytest.mark.unit]

DOMAIN = 'deliver.example.com'
LEAF = '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n'
CHAIN = LEAF + '-----BEGIN CERTIFICATE-----\nISSUER\n-----END CERTIFICATE-----\n'
KEY = '-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n'


@pytest.fixture
def instance(tmp_path):
    """A Notifier over a certificate directory with one domain in it."""
    cert_dir = tmp_path / 'certificates'
    (cert_dir / DOMAIN).mkdir(parents=True)
    (cert_dir / DOMAIN / 'cert.pem').write_text(LEAF)
    (cert_dir / DOMAIN / 'fullchain.pem').write_text(CHAIN)
    (cert_dir / DOMAIN / 'privkey.pem').write_text(KEY)

    settings = MagicMock()
    settings.load_settings.return_value = {}
    return Notifier(settings, data_dir=str(tmp_path / 'data'),
                    cert_dir=str(cert_dir))


@pytest.fixture
def sent(monkeypatch):
    """Capture what would have gone on the wire."""
    captured = {}

    class _Response:
        status = 200

        def read(self):
            return b'{}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured['url'] = req.full_url
        captured['body'] = req.data.decode('utf-8') if req.data else ''
        return _Response()

    monkeypatch.setattr(notifier_mod, 'urlopen', fake_urlopen)
    return captured


def _webhook(template):
    return {'type': 'generic', 'name': 'ingest',
            'url': 'https://ingest.example.net/certs',
            'payload_template': template}


def _deliver(instance, sent, template, details):
    result = instance._send_webhook(_webhook(template), 'certificate_renewed',
                                    'Certificate Renewed', 'renewed', details)
    assert result.get('success') is True, result
    return json.loads(sent['body'])


# --- the feature -----------------------------------------------------------

def test_a_template_can_carry_the_certificate(instance, sent):
    """THE regression, driven through the delivery path rather than the
    renderer: the body that reaches the wire holds the real PEM."""
    body = _deliver(instance, sent,
                    '{"domain": "{{domain}}", "chain": "{{fullchain}}"}',
                    {'domain': DOMAIN})

    assert body['domain'] == DOMAIN
    assert body['chain'] == CHAIN
    assert body['chain'].count('BEGIN CERTIFICATE') == 2, (
        'fullchain carried only the leaf')


def test_the_leaf_is_its_own_variable(instance, sent):
    """An endpoint that stores the leaf and builds its own chain wants one,
    not the other."""
    body = _deliver(instance, sent, '{"cert": "{{cert}}"}', {'domain': DOMAIN})

    assert body['cert'] == LEAF
    assert 'ISSUER' not in body['cert']


def test_the_pem_survives_json_escaping(instance, sent):
    """A PEM is multi-line, and the renderer escapes a value used inside a
    JSON string. The receiver has to get newlines back, or it cannot parse
    what it was sent."""
    body = _deliver(instance, sent, '{"chain": "{{fullchain}}"}',
                    {'domain': DOMAIN})

    assert body['chain'].startswith('-----BEGIN CERTIFICATE-----\n')
    assert body['chain'].endswith('-----END CERTIFICATE-----\n')


# --- on demand, and nowhere else ------------------------------------------

def test_a_template_that_does_not_ask_reads_nothing(instance, sent, monkeypatch):
    """THE control on "on demand". A read per delivery, for every webhook, of
    every certificate, would be the cost of this feature for operators who
    never wanted it."""
    reads = []
    monkeypatch.setattr(
        instance, '_certificate_material',
        lambda domain, wanted: reads.append(wanted) or {})

    _deliver(instance, sent, '{"domain": "{{domain}}"}', {'domain': DOMAIN})

    assert reads == [], 'the certificate was read for a template that never named it'


def test_the_material_is_not_in_what_the_bus_carries():
    """The variables the bus-side helper builds come from `details`, which
    reaches every subscriber. If the PEM were added there, every listener
    would receive it — including ones that exist to forward events."""
    variables = webhook_template_variables(
        'certificate_renewed', 'Certificate Renewed', 'renewed',
        {'domain': DOMAIN})

    assert set(CERT_MATERIAL_FILES) & set(variables) == set()
    assert 'LEAF' not in json.dumps(variables, default=str)


@pytest.mark.parametrize('template,expected', [
    ('{"a": "{{cert}}"}', {'cert'}),
    ('{"a": "{{ fullchain }}"}', {'fullchain'}),
    ('{"a": "{{cert}}", "b": "{{fullchain}}"}', {'cert', 'fullchain'}),
    ('{"a": "{{domain}}"}', set()),
    ('{"a": "certificate"}', set()),          # the word, not the placeholder
    (None, set()),
])
def test_what_counts_as_asking(template, expected):
    """Matched with the renderer's own placeholder regex, so the two cannot
    disagree about what a placeholder is — a substring search for 'cert'
    would fire on the word in a message."""
    assert template_references(template, CERT_MATERIAL_FILES) == expected


# --- when there is nothing to send ----------------------------------------

def test_an_event_about_no_domain_renders_empty(instance, sent):
    """A Test delivery, a settings change, a backup: no domain, so no
    certificate. Empty is what every unknown placeholder renders as, so a
    template does not have to branch on the event type."""
    body = _deliver(instance, sent, '{"chain": "{{fullchain}}"}', {})

    assert body['chain'] == ''


def test_a_domain_that_is_not_here_renders_empty(instance, sent):
    """A CT-log or discovery event names a domain this instance does not
    hold. Not an error — the delivery still has to happen."""
    body = _deliver(instance, sent, '{"chain": "{{fullchain}}"}',
                    {'domain': 'somewhere-else.example.org'})

    assert body['chain'] == ''


def test_a_notifier_without_a_certificate_directory_renders_empty(tmp_path, sent):
    """The constructor's `cert_dir` is optional and several call sites build a
    Notifier without one. Guessing a path from the working directory would be
    worse than answering empty."""
    settings = MagicMock()
    settings.load_settings.return_value = {}
    bare = Notifier(settings, data_dir=str(tmp_path))

    result = bare._send_webhook(_webhook('{"chain": "{{fullchain}}"}'),
                                'certificate_renewed', 'T', 'm',
                                {'domain': DOMAIN})

    assert result.get('success') is True
    assert json.loads(sent['body'])['chain'] == ''


# --- what must not happen --------------------------------------------------

@pytest.mark.parametrize('domain', [
    '../../etc/passwd',
    '/etc/passwd',
    'a/../../../root',
    'https://x/../y',
])
def test_a_domain_that_is_a_path_is_refused(instance, sent, domain):
    """`details['domain']` is about to become a path segment. It comes from
    CertMate's own events today, but so did the issuance-side value that
    `reject_unsafe_domain` exists for — and the guard is the same one, rather
    than a second opinion written here."""
    body = _deliver(instance, sent, '{"chain": "{{fullchain}}"}',
                    {'domain': domain})

    assert body['chain'] == ''


def test_a_traversal_that_points_at_a_real_file_still_gets_nothing(instance, sent,
                                                                   tmp_path):
    """The traversal test above, made capable of failing.

    `../../etc/passwd/fullchain.pem` does not exist, so the read fails on its
    own and the assertion passes whether or not a guard ran — measured: with
    `reject_unsafe_domain` deleted, every case in the parametrisation above
    still passed. This one puts a readable `fullchain.pem` outside the
    certificate directory and points the domain at it, so the only thing
    keeping it out of the request body is a guard.

    The guard is `domain_paths.validate_domain_path` — the same call the
    certificate routes make at the same sink, rather than a second spelling
    of it written here. (The first draft did hand-roll it, in two parts; each
    part alone still passed every case, which is how the duplication showed
    up.) Removing the call fails this test with `NOT-YOURS` in the request
    body, and four more besides.
    """
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'fullchain.pem').write_text('-----BEGIN CERTIFICATE-----\nNOT-YOURS\n')

    body = _deliver(instance, sent, '{"chain": "{{fullchain}}"}',
                    {'domain': '../outside'})

    assert body['chain'] == ''
    assert 'NOT-YOURS' not in sent['body']


def test_the_private_key_is_not_reachable(instance, sent):
    """`{{privkey}}` is not a variable, so it renders as an unknown
    placeholder — empty — and no key file is opened. The file is right there
    next to the two that are readable, which is the whole reason to assert
    it."""
    opened = []
    real_open = open

    def watched_open(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    import builtins
    original = builtins.open
    builtins.open = watched_open
    try:
        body = _deliver(instance, sent,
                        '{"key": "{{privkey}}", "chain": "{{fullchain}}"}',
                        {'domain': DOMAIN})
    finally:
        builtins.open = original

    assert body['key'] == ''
    assert 'SECRET' not in sent['body']
    assert not any(p.endswith('privkey.pem') for p in opened), opened


def test_an_implausibly_large_file_is_not_sent(instance, sent, tmp_path):
    """The cap is not about a certificate — it is about what happens when the
    file is not one. An unbounded read here puts whatever is on disk into a
    request body."""
    from modules.core.notifier import CERT_MATERIAL_MAX_BYTES

    big = Path(instance._cert_dir) / DOMAIN / 'fullchain.pem'
    big.write_text('x' * (CERT_MATERIAL_MAX_BYTES + 10))

    body = _deliver(instance, sent, '{"chain": "{{fullchain}}"}',
                    {'domain': DOMAIN})

    assert body['chain'] == ''


def test_the_delivery_log_still_records_no_body(instance, sent):
    """The log outlives the request and leaves through the API. It records
    metadata and an origin, never the body — asserted here because this
    change is the first one that puts a certificate in that body.

    Through `_send_webhook_with_retry`, which is the method that writes the
    log: the first draft called `_send_webhook` and skipped when no file
    appeared, which is a test that can only ever pass.
    """
    result = instance._send_webhook_with_retry(
        _webhook('{"chain": "{{fullchain}}"}'), 'certificate_renewed',
        'Certificate Renewed', 'renewed', {'domain': DOMAIN})
    assert result.get('success') is True, result

    log = Path(instance._delivery_log_path)
    assert log.exists(), 'the delivery log was not written at all'
    text = log.read_text()
    assert 'BEGIN CERTIFICATE' not in text
    assert 'LEAF' not in text
    # The control: the record IS there, so the two asserts above are about
    # what it omits rather than about an empty file.
    assert json.loads(text.strip().splitlines()[-1])['event'] == 'certificate_renewed'


# --- the list the interface shows -----------------------------------------

def test_the_advertised_variables_include_the_new_ones():
    """The Preview endpoint sends the variable list to the browser, and the
    chips are built from it. A variable that works but is not listed is one
    nobody finds."""
    from modules.core.notifier import TEMPLATE_VARIABLES

    names = {name for name, _description in TEMPLATE_VARIABLES}

    assert {'cert', 'fullchain'} <= names
    assert 'privkey' not in names


def test_the_chips_in_the_interface_match_the_module():
    """Two lists, one of them in JavaScript, is how a variable ships and is
    never offered. Read from the file rather than kept in step by hand."""
    import re

    js = (Path(__file__).resolve().parent.parent
          / 'static' / 'js' / 'settings-notifications.js').read_text()
    match = re.search(r'templateVariables:\s*\[(.*?)\]', js, re.S)
    assert match, 'the chip list moved'
    chips = set(re.findall(r"'([^']+)'", match.group(1)))

    assert {'cert', 'fullchain'} <= chips
    assert 'privkey' not in chips


def test_a_wildcard_certificate_is_deliverable(instance, sent):
    """`*.example.com` is the directory name on disk, and the guard accepts
    it (`DOMAIN_RE` allows a leading `*.`). Asserted because the obvious
    reading of "refuse a path-bearing domain" would also refuse the one
    character that makes a wildcard a wildcard — and a wildcard is exactly
    the certificate an operator most wants pushed somewhere."""
    wildcard = '*.example.com'
    cert_dir = Path(instance._cert_dir)
    (cert_dir / wildcard).mkdir()
    (cert_dir / wildcard / 'fullchain.pem').write_text(CHAIN)

    body = _deliver(instance, sent, '{"chain": "{{fullchain}}"}',
                    {'domain': wildcard})

    assert body['chain'] == CHAIN
