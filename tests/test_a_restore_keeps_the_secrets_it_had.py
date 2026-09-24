"""Restoring a share-safe backup wrote the mask over the real credential.

A share-safe backup masks secrets on the way out — that is what makes it
shareable. On the way back in, the restore merges against what is on disk so
the masked values are left alone: the archive says `'********'`, the instance
keeps what it had.

That worked for a secret nested in dicts and not for one nested in a list.
`_strip_masked_values` recurses into dicts and returns lists unchanged, so a
Kubernetes deploy target's token — which lives at
`deploy_hooks.targets[*].config.token` — came through the strip as the
literal sentinel and was written straight over the working value.

    _strip_masked_values({'a': {'b': {'token': '********'}}})  -> {}
    _strip_masked_values({'a': {'t': [{'config': {'token': '********'}}]}})
        -> unchanged

So restoring a share-safe backup destroyed the credential it was taken to
protect, and returned True. The restore is the path an operator reaches when
something has already gone wrong, which is the worst place for a silent
write.

The fix is a helper this project already had: the generic settings POST path
has solved exactly this since webhooks grew list-nested secrets.

**On the shape of this file.** An earlier draft reproduced the restore's
inline merge and asserted against the restatement. Those tests called the fix
themselves, so they could not fail — removing it from the product left them
green. Everything here drives `create_unified_backup` and
`restore_unified_backup`.
"""
import json
import zipfile

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


def _target(name='k8s-prod', namespace='prod', token=REAL_TOKEN):
    """The full shape the target validator requires.

    Found while writing this file: the restore VALIDATES deploy targets and
    refuses the whole archive when one does not hold up. A short target in
    the first draft made `restore_unified_backup` return False with the
    settings untouched — correct behaviour, and it would have made every
    assertion below pass for the wrong reason.
    """
    return {'name': name, 'type': 'kubernetes-secret',
            'config': {'secret_name': 'tls', 'namespace': namespace,
                       'api_server': 'https://k8s.internal:6443',
                       'token': token}}


def _live_settings():
    """What the instance holds: secrets in a list AND in dicts."""
    return {
        'email': 'ops@example.com',
        'deploy_hooks': {'enabled': True, 'global_hooks': [],
                         'domain_hooks': {}, 'targets': [_target()]},
        'notifications': {'channels': {
            'webhooks': [{'name': 'ops', 'type': 'slack', 'url': REAL_WEBHOOK}],
            'smtp': {'host': 'smtp.example.com', 'password': 'REAL-SMTP-PW'},
        }},
        'dns_providers': {'cloudflare': {'default': {'api_token': 'REAL-CF'}}},
    }


def _round_trip(file_ops, settings_file, live, include_secrets=False):
    """Back up *live*, restore the archive, return what ends up on disk."""
    settings_file.write_text(json.dumps(live), encoding='utf-8')
    name = file_ops.create_unified_backup(live, 'round-trip',
                                          include_secrets=include_secrets)
    archive = file_ops.backup_dir / 'unified' / name
    assert file_ops.restore_unified_backup(archive) is True, (
        'the restore refused the archive, so nothing was written and the '
        'assertions below would pass for the wrong reason')
    return json.loads(settings_file.read_text(encoding='utf-8'))


def _archived_settings(archive):
    with zipfile.ZipFile(archive) as zf:
        member = next(n for n in zf.namelist() if n.endswith('settings.json'))
        # The archive nests the tree under `settings`, beside `metadata`.
        return json.loads(zf.read(member))['settings']


# --- the asymmetry that caused it ----------------------------------------

def test_the_strip_leaves_a_sentinel_inside_a_list():
    """Not a defect on its own — it is why the restore needed a second pass,
    and it is what makes this class of bug invisible in review: the dict case
    is so obviously handled that nobody checks the other one."""
    from modules.core.settings import _strip_masked_values

    in_dict = _strip_masked_values({'a': {'b': {'token': MASK}}})
    in_list = _strip_masked_values({'a': {'t': [{'config': {'token': MASK}}]}})

    assert in_dict == {}
    assert in_list['a']['t'][0]['config']['token'] == MASK


def test_both_paths_restore_list_nested_secrets():
    """The generic settings POST has had this since webhooks grew
    list-nested secrets; the restore did not. Asserted on the call so the
    two cannot drift apart again."""
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


# --- the round trip, through the shipped functions -----------------------

def test_the_archive_really_carries_the_mask(ops):
    """Guard on the premise. If a share-safe backup stopped masking, every
    test below would pass while proving the opposite of what it claims — and
    that would be a far worse defect than this one."""
    file_ops, settings_file = ops
    live = _live_settings()
    settings_file.write_text(json.dumps(live), encoding='utf-8')
    name = file_ops.create_unified_backup(live, 'probe', include_secrets=False)

    stored = _archived_settings(file_ops.backup_dir / 'unified' / name)

    assert REAL_TOKEN not in json.dumps(stored)
    assert stored['deploy_hooks']['targets'][0]['config']['token'] == MASK
    assert stored['notifications']['channels']['webhooks'][0]['url'] == MASK


def test_a_masked_token_in_a_list_survives_the_restore(ops):
    """THE regression."""
    file_ops, settings_file = ops

    written = _round_trip(file_ops, settings_file, _live_settings())

    token = written['deploy_hooks']['targets'][0]['config']['token']
    assert token == REAL_TOKEN, (
        f'restoring a share-safe backup wrote {token!r} over the deploy '
        f'target token')


def test_a_masked_webhook_url_survives_too(ops):
    """The other list-of-dicts in the tree, and the one the helper was
    originally written for."""
    file_ops, settings_file = ops

    written = _round_trip(file_ops, settings_file, _live_settings())

    assert written['notifications']['channels']['webhooks'][0]['url'] == \
        REAL_WEBHOOK


def test_the_dict_nested_secrets_still_survive(ops):
    """CONTROL. Those were never broken; a fix that traded one for the other
    would pass the tests above."""
    file_ops, settings_file = ops

    written = _round_trip(file_ops, settings_file, _live_settings())

    assert written['dns_providers']['cloudflare']['default']['api_token'] == \
        'REAL-CF'
    assert written['notifications']['channels']['smtp']['password'] == \
        'REAL-SMTP-PW'


def test_a_target_the_archive_adds_is_kept(ops):
    """CONTROL on the merge: a restore must not drop a target the archive
    carries and the instance does not have."""
    file_ops, settings_file = ops
    live = _live_settings()
    live['deploy_hooks']['targets'].append(
        _target('k8s-staging', 'staging', 'STAGING-TOKEN'))

    written = _round_trip(file_ops, settings_file, live)

    names = [target['name'] for target in written['deploy_hooks']['targets']]
    assert names == ['k8s-prod', 'k8s-staging']


def test_a_full_backup_still_writes_its_own_secrets(ops):
    """CONTROL, and the point of include_secrets=True: an archive carrying
    REAL values must write them. A fix that always preferred what is on disk
    would make a disaster-recovery archive unrestorable — which is a defect
    this area has already had once."""
    file_ops, settings_file = ops
    live = _live_settings()
    settings_file.write_text(json.dumps(live), encoding='utf-8')
    name = file_ops.create_unified_backup(live, 'dr', include_secrets=True)
    archive = file_ops.backup_dir / 'unified' / name

    drifted = _live_settings()
    drifted['deploy_hooks']['targets'][0]['config']['token'] = 'SOMETHING-ELSE'
    settings_file.write_text(json.dumps(drifted), encoding='utf-8')

    assert file_ops.restore_unified_backup(archive) is True
    written = json.loads(settings_file.read_text(encoding='utf-8'))
    assert written['deploy_hooks']['targets'][0]['config']['token'] == REAL_TOKEN
