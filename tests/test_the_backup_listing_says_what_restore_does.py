"""What the backup list says about a masked archive is what restore does.

Item 4 of #876, which turned out to be a different defect from the one it
described. The issue said restoring a share-safe archive onto an empty instance
"writes the mask sentinel as the credentials". Measured on a real backup and
restore cycle, with the settings tree the app actually writes:

    restore onto an empty instance -> True
    email                          -> 'ops@example.com'      (kept)
    domains                        -> [a.example.com]        (kept)
    dns_providers                  -> {cloudflare: {accounts: {default: {name}}}}
    the account's token            -> absent
    the mask sentinel in the file  -> No

The credential is **removed**, not masked. That is the right behaviour, and it
is a useful one: a configuration snapshot you can restore onto a fresh instance
and then re-enter credentials into.

Three statements said otherwise, all of them the same wrong thing:

* the listing's `restore_blocked_reason` — "restoring it would install the mask
  in place of every credential and lock this instance out". This is the one an
  operator actually reads, in the backup list, and it frightened them away from
  a path that works.
* the restore path's own warning — "secret fields will remain as the mask
  sentinel".
* the comment in `static/js/settings.js` — "the restore endpoint refuses them".

`can_restore: false` is **not** among them. In its real meaning — can this
archive bring *this* instance back — it is correct, and #655 put it there to
remove decoy restore points. Its name is what misled the comment.

So nothing about restore behaviour changed here. Three sentences did.
"""
import json
import pathlib
import tempfile

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import SECRET_MASK_SENTINEL

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
TOKEN = 'REAL-CF-TOKEN'

# The shape the app writes, not a flattened one. An earlier probe of mine set
# `dns_providers.cloudflare.api_token`, which does not exist — the account tree
# is `dns_providers.<provider>.accounts.<id>.<field>` — and every conclusion
# drawn from it was about a key nothing reads.
LIVE_SETTINGS = {
    'email': 'ops@example.com',
    'dns_providers': {'cloudflare': {'accounts': {'default': {
        'name': 'Default', 'api_token': TOKEN}}}},
    'domains': [{'domain': 'a.example.com', 'dns_provider': 'cloudflare'}],
}


def _instance():
    root = pathlib.Path(tempfile.mkdtemp())
    for sub in ('certs', 'data', 'backups', 'logs'):
        (root / sub).mkdir()
    return root, FileOperations(cert_dir=root / 'certs', data_dir=root / 'data',
                                backup_dir=root / 'backups', logs_dir=root / 'logs')


@pytest.fixture
def masked_archive():
    """A share-safe archive, and the instance that produced it."""
    root, file_ops = _instance()
    assert file_ops.create_unified_backup(
        LIVE_SETTINGS, backup_reason='t', include_secrets=False)
    archive = sorted((root / 'backups' / 'unified').glob('*.zip'))[0]
    return archive, file_ops


def test_the_probe_carries_a_secret_worth_removing():
    """Guard the guard: an empty needle is removed from every haystack."""
    assert TOKEN in json.dumps(LIVE_SETTINGS)


def test_the_credential_is_removed_not_masked(masked_archive):
    """The measurement the three sentences were wrong about."""
    archive, _ = masked_archive
    destination, restoring = _instance()

    assert restoring.restore_unified_backup(str(archive)) is True

    written = (destination / 'data' / 'settings.json').read_text(encoding='utf-8')
    assert TOKEN not in written
    assert SECRET_MASK_SENTINEL not in written, (
        'the mask reached the settings file; the listing\'s warning about '
        'being locked out would be true again'
    )
    restored = json.loads(written)
    account = (restored.get('dns_providers', {}).get('cloudflare', {})
               .get('accounts', {}).get('default', {}))
    assert 'api_token' not in account or not account['api_token']


def test_what_survives_is_worth_restoring(masked_archive):
    """The reason text now promises these back. If they stopped coming back,
    the sentence would be the next false one."""
    archive, _ = masked_archive
    destination, restoring = _instance()
    restoring.restore_unified_backup(str(archive))
    restored = json.loads(
        (destination / 'data' / 'settings.json').read_text(encoding='utf-8'))

    assert restored.get('email') == 'ops@example.com'
    assert restored.get('domains') == LIVE_SETTINGS['domains']
    assert 'cloudflare' in (restored.get('dns_providers') or {})


# ── the three sentences ──────────────────────────────────────────────

def test_the_listing_still_calls_it_unrestorable(masked_archive):
    """`can_restore: false` was never the wrong part. It means "cannot bring
    this instance back", which is true, and #655 relies on it."""
    archive, file_ops = masked_archive
    can_restore, reason = file_ops._backup_restorability(archive)
    assert can_restore is False
    assert reason


def test_the_listing_no_longer_says_the_mask_would_be_installed(masked_archive):
    """The sentence an operator reads. It described a consequence that does
    not happen, about an archive whose real limitation is narrower."""
    archive, file_ops = masked_archive
    _, reason = file_ops._backup_restorability(archive)
    lowered = reason.lower()
    assert 'lock this instance out' not in lowered
    assert 'in place of every credential' not in lowered


def test_the_listing_names_what_the_archive_can_still_do(masked_archive):
    """Correcting a false warning into a bare "no" would lose the operator
    the same recovery path by omission."""
    archive, file_ops = masked_archive
    reason = file_ops._backup_restorability(archive)[1].lower()
    assert 'no certificates' in reason, reason
    for promised in ('domains', 'deploy hooks', 'inventory', 'audit chain'):
        assert promised in reason, f'{promised!r} missing from: {reason}'
    assert 're-entered' in reason


def test_the_restore_warning_describes_what_it_does():
    """Read from the source: the warning fires on a path that needs a whole
    restore to reach, and what is pinned is the claim, not the reaching."""
    source = (REPO / 'modules' / 'core' / 'file_operations.py').read_text(
        encoding='utf-8')
    assert 'will remain as the mask sentinel' not in source
    # Asserted in fragments: the message is wrapped across source lines, and
    # the first version of this test looked for the whole sentence contiguously
    # and failed on a message that was already correct.
    assert 'the archive carries no ' in source
    assert 'credentials, so DNS / storage / SMTP ' in source


def test_the_ui_comment_no_longer_claims_a_refusal_that_does_not_happen():
    """`static/js/settings.js` said "the restore endpoint refuses them". It
    refuses them over an instance that already holds certificates, and takes
    them onto an empty one."""
    source = (REPO / 'static' / 'js' / 'settings.js').read_text(encoding='utf-8')
    assert 'the restore endpoint refuses them' not in source, (
        'the comment states the refusal again; quoting the old sentence '
        'verbatim would also make this check unable to tell the two apart')
    assert 'refuses a masked' in source
    assert 'accepts one onto an empty instance' in source


def test_the_endpoint_really_does_refuse_over_existing_certificates(masked_archive):
    """The half of the old comment that was true, kept true. Without this the
    corrected comment could drift into describing a guard that is gone."""
    archive, _ = masked_archive
    destination, restoring = _instance()
    existing = destination / 'certs' / 'already.example.com'
    existing.mkdir(parents=True)
    (existing / 'cert.pem').write_text('not a real certificate')

    import zipfile
    with zipfile.ZipFile(archive) as zipf:
        refusal = restoring._refuse_keyless_restore_over_certificates(zipf)
    assert refusal, 'a masked archive is accepted over existing certificates'
    # Compared against the directory the test created rather than a repeated
    # literal. It reads better, and it keeps CodeQL from reporting a
    # host-shaped literal on the left of `in` as incomplete URL sanitisation —
    # which it does, at high severity, and which blocks the merge.
    assert existing.name in refusal
