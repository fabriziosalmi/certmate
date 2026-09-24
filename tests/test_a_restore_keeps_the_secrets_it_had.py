"""Restoring a share-safe backup wrote the mask over the real credential.

A share-safe backup masks secrets on the way out — that is what makes it
shareable. On the way back in, the restore is supposed to merge against what
is on disk so the masked values are left alone: the archive says
`'********'`, the instance keeps what it had.

That worked for a secret nested in dicts and not for one nested in a list.
`_strip_masked_values` recurses into dicts and returns lists unchanged, so a
Kubernetes deploy target's token — which lives at
`deploy_hooks.targets[*].config.token` — came through the strip as the
literal sentinel and was written straight over the working value.

    _strip_masked_values({'a': {'b': {'token': '********'}}})  -> {}
    _strip_masked_values({'a': {'t': [{'config': {'token': '********'}}]}})
        -> {'a': {'t': [{'config': {'token': '********'}}]}}

So restoring a backup destroyed the credential it was taken to protect, and
returned True. The restore path is the one an operator reaches when something
has already gone wrong, which is the worst possible place for a silent write.

The fix is a helper the project already had: the generic settings POST path
has solved exactly this since webhooks got list-nested secrets. It is applied
over the whole merged tree here, because `deploy_hooks` is not in
`_DEEP_MERGE_SETTINGS_KEYS` and so never reaches the per-key deep-merge
branch.
"""
import json

import pytest

from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]

MASK = '********'
REAL_TOKEN = 'k8s-service-account-token-do-not-lose-me'
REAL_WEBHOOK = 'https://hooks.slack.com/services/REAL/WEBHOOK/URL'


@pytest.fixture
def ops(tmp_path):
    dirs = [tmp_path / name for name in
            ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    return FileOperations(*dirs), tmp_path / 'data' / 'settings.json'


def _live_settings():
    """What the instance holds: two secrets, one in a list, one in a dict."""
    return {
        'email': 'ops@example.com',
        'deploy_hooks': {
            'enabled': True,
            'global_hooks': [],
            'domain_hooks': {},
            # The full shape the target validator requires. The restore
            # VALIDATES deploy targets and refuses the whole archive if one
            # does not hold up — found while writing this: a short target
            # made `restore_unified_backup` return False with the on-disk
            # settings untouched, which is the right behaviour and would
            # have made this test pass for the wrong reason.
            'targets': [{
                'name': 'k8s-prod',
                'type': 'kubernetes-secret',
                'config': {'secret_name': 'tls', 'namespace': 'prod',
                           'api_server': 'https://k8s.internal:6443',
                           'token': REAL_TOKEN},
            }],
        },
        'notifications': {'channels': {
            'webhooks': [{'name': 'ops', 'type': 'slack', 'url': REAL_WEBHOOK}],
            'smtp': {'host': 'smtp.example.com', 'password': 'REAL-SMTP-PW'},
        }},
        'dns_providers': {'cloudflare': {'default': {'api_token': 'REAL-CF'}}},
    }


def _masked_archive_settings():
    """What a share-safe backup carries: the same tree, secrets masked."""
    data = _live_settings()
    data['deploy_hooks']['targets'][0]['config']['token'] = MASK
    data['notifications']['channels']['webhooks'][0]['url'] = MASK
    data['notifications']['channels']['smtp']['password'] = MASK
    data['dns_providers']['cloudflare']['default']['api_token'] = MASK
    return data


# --- the helper, where the asymmetry lives -------------------------------

def test_the_strip_leaves_a_sentinel_inside_a_list():
    """Not a defect on its own — it is why the restore needed the second
    pass, and it is what makes this class of bug invisible in review: the
    dict case is obviously handled."""
    from modules.core.settings import _strip_masked_values

    in_dict = _strip_masked_values({'a': {'b': {'token': MASK}}})
    in_list = _strip_masked_values({'a': {'t': [{'config': {'token': MASK}}]}})

    assert in_dict == {}
    assert in_list['a']['t'][0]['config']['token'] == MASK


def test_the_restore_path_applies_the_list_aware_pass():
    """Asserted on the call, so the two paths cannot drift apart again: the
    generic settings POST has had this since webhooks grew list-nested
    secrets, and the restore did not."""
    import ast
    import inspect

    from modules.core import file_operations, settings

    for module in (file_operations, settings):
        calls = [ast.unparse(node) for node in
                 ast.walk(ast.parse(inspect.getsource(module)))
                 if isinstance(node, ast.Call)]
        assert any('_restore_masked_list_secrets_deep(' in call
                   for call in calls), (
            f'{module.__name__} no longer restores list-nested secrets')


# --- end to end ----------------------------------------------------------

def test_a_masked_token_in_a_list_survives_the_restore(ops, tmp_path):
    """THE regression, through the real restore."""
    file_ops, settings_file = ops
    settings_file.write_text(json.dumps(_live_settings()), encoding='utf-8')

    written = _merge_through_restore(file_ops, settings_file,
                                     _masked_archive_settings())

    token = written['deploy_hooks']['targets'][0]['config']['token']
    assert token == REAL_TOKEN, (
        'restoring a share-safe backup overwrote the deploy target token '
        f'with {token!r}'
    )


def test_a_masked_webhook_url_survives_too(ops):
    """The other list-of-dicts in the tree, and the one the helper was
    originally written for."""
    file_ops, settings_file = ops
    settings_file.write_text(json.dumps(_live_settings()), encoding='utf-8')

    written = _merge_through_restore(file_ops, settings_file,
                                     _masked_archive_settings())

    url = written['notifications']['channels']['webhooks'][0]['url']
    assert url == REAL_WEBHOOK


def test_the_dict_nested_secrets_still_survive(ops):
    """CONTROL. Those were never broken; a fix that traded one for the other
    would pass the tests above."""
    file_ops, settings_file = ops
    settings_file.write_text(json.dumps(_live_settings()), encoding='utf-8')

    written = _merge_through_restore(file_ops, settings_file,
                                     _masked_archive_settings())

    assert written['dns_providers']['cloudflare']['default']['api_token'] == 'REAL-CF'
    assert written['notifications']['channels']['smtp']['password'] == 'REAL-SMTP-PW'


def test_a_real_value_in_the_archive_still_replaces(ops):
    """CONTROL, and the point of a restore: an archive that carries a REAL
    value must win. A fix that always kept the on-disk value would make a
    full backup unrestorable."""
    file_ops, settings_file = ops
    settings_file.write_text(json.dumps(_live_settings()), encoding='utf-8')
    archive = _masked_archive_settings()
    archive['deploy_hooks']['targets'][0]['config']['token'] = 'A-DIFFERENT-REAL-TOKEN'

    written = _merge_through_restore(file_ops, settings_file, archive)

    assert written['deploy_hooks']['targets'][0]['config']['token'] == \
        'A-DIFFERENT-REAL-TOKEN'


def test_a_target_the_archive_adds_is_kept(ops):
    """CONTROL on the merge itself: restoring must not silently drop a
    target the archive carries and the instance does not have."""
    file_ops, settings_file = ops
    settings_file.write_text(json.dumps(_live_settings()), encoding='utf-8')
    archive = _masked_archive_settings()
    archive['deploy_hooks']['targets'].append({
        'name': 'k8s-staging', 'type': 'kubernetes-secret',
        'config': {'secret_name': 'tls', 'namespace': 'staging',
                   'api_server': 'https://k8s.internal:6443',
                   'token': 'STAGING-TOKEN'}})

    written = _merge_through_restore(file_ops, settings_file, archive)

    names = [t['name'] for t in written['deploy_hooks']['targets']]
    assert names == ['k8s-prod', 'k8s-staging']


def _merge_through_restore(file_ops, settings_file, archive_settings):
    """Drive the restore's settings merge and return what it would write.

    The merge is inline in `restore_unified_backup`, so this reproduces the
    call the way that function makes it — against the same helpers, in the
    same order — rather than re-implementing the rule.
    """
    from modules.core.settings import (
        _DEEP_MERGE_SETTINGS_KEYS, _deep_merge_dict,
        _restore_masked_list_secrets_deep, _strip_masked_values,
    )

    cleaned = _strip_masked_values(archive_settings)
    existing = json.loads(settings_file.read_text(encoding='utf-8'))
    merged = dict(existing)
    for key, value in cleaned.items():
        if (key in _DEEP_MERGE_SETTINGS_KEYS
                and isinstance(existing.get(key), dict)
                and isinstance(value, dict)):
            merged[key] = _deep_merge_dict(existing[key], value)
        else:
            merged[key] = value
    _restore_masked_list_secrets_deep(existing, merged)
    return merged


def test_the_reproduction_matches_the_shipped_merge():
    """The helper above restates the restore's inline merge. If that merge
    changes shape, this file stops testing the product — so the two are
    compared rather than assumed."""
    import inspect

    from modules.core.file_operations import FileOperations

    source = inspect.getsource(FileOperations.restore_unified_backup)

    for fragment in ('_strip_masked_values(settings_data)',
                     '_DEEP_MERGE_SETTINGS_KEYS',
                     '_deep_merge_dict(existing[key], value)',
                     '_restore_masked_list_secrets_deep(existing, merged)'):
        assert fragment in source, (
            f'the restore merge no longer contains {fragment!r}; this test '
            f'reproduces a merge the product does not perform'
        )


def test_the_archive_really_did_carry_the_mask():
    """Guard on the fixture: if the masked archive stopped carrying
    sentinels, every assertion above would pass for the wrong reason."""
    archive = _masked_archive_settings()

    assert archive['deploy_hooks']['targets'][0]['config']['token'] == MASK
    assert archive['notifications']['channels']['webhooks'][0]['url'] == MASK


# --- and the same thing through the shipped restore ----------------------

def test_the_real_restore_keeps_the_token(ops):
    """The reproduction above is a restatement; this drives the product.

    A share-safe backup is created by `create_unified_backup` and put back by
    `restore_unified_backup`, with nothing in between but the archive.
    """
    file_ops, settings_file = ops
    settings_file.write_text(json.dumps(_live_settings()), encoding='utf-8')

    name = file_ops.create_unified_backup(_live_settings(), 'share-safe',
                                          include_secrets=False)
    archive = file_ops.backup_dir / 'unified' / name

    assert file_ops.restore_unified_backup(archive) is True

    written = json.loads(settings_file.read_text(encoding='utf-8'))
    token = written['deploy_hooks']['targets'][0]['config']['token']
    assert token == REAL_TOKEN, (
        f'the shipped restore wrote {token!r} over the deploy target token')
    assert written['notifications']['channels']['webhooks'][0]['url'] == REAL_WEBHOOK
    assert written['dns_providers']['cloudflare']['default']['api_token'] == 'REAL-CF'


def test_the_share_safe_archive_really_masked_them(ops):
    """Guard on the premise: if the backup stopped masking, the test above
    would pass while proving nothing."""
    import zipfile

    file_ops, _ = ops
    name = file_ops.create_unified_backup(_live_settings(), 'share-safe',
                                          include_secrets=False)
    archive = file_ops.backup_dir / 'unified' / name

    with zipfile.ZipFile(archive) as zf:
        member = next(n for n in zf.namelist() if n.endswith('settings.json'))
        # The archive nests the tree under `settings`, beside `metadata`.
        stored = json.loads(zf.read(member))['settings']

    assert REAL_TOKEN not in json.dumps(stored), (
        'the share-safe archive carries the real token — a different and '
        'much worse defect than the one this file is about')
    assert stored['deploy_hooks']['targets'][0]['config']['token'] == MASK
