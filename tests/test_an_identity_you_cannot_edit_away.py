"""A webhook keeps its secrets when you rename it (#950).

Masked secrets are put back on save by matching the submission to the entry
already on disk. The match was `(type, name)` — the two fields an operator
edits. So renaming a webhook, or changing its type, meant the save could not
find the entry the secrets belonged to and dropped them: the webhook stayed
`enabled`, lost its URL and every custom header, the save answered **200**, and
nothing on screen said so, because the URL is never displayed.

The fix is an `id` the operator cannot edit, assigned at load so that entries
already on disk have one *before* anyone can rename them. Assigning at save
would leave exactly one unprotected save — the first after upgrading — and that
is the save someone makes to fix a name.

`(type, name)` remains as the fallback, for configurations written before ids
existed and for a client that sends back a shape it did not receive. Those keep
exactly the behaviour they had, which is the point: nothing gets worse.
"""
import pytest

from modules.core.settings import (
    SECRET_MASK_SENTINEL as MASK,
    _restore_masked_list_secrets,
    assign_stable_entry_ids,
)

pytestmark = [pytest.mark.unit]


def _stored(**over):
    entry = {
        'id': 'id-ops', 'name': 'ops', 'type': 'generic', 'enabled': True,
        'url': 'https://hooks.example.com/services/T0/B0/REAL-SECRET',
        'auth_token': 'REAL-BEARER',
        'headers': {'X-Auth': 'REAL-HEADER'},
    }
    entry.update(over)
    return [entry]


def _submitted(**over):
    """What the UI echoes back: the masked GET, with the edits applied."""
    entry = {
        'id': 'id-ops', 'name': 'ops', 'type': 'generic', 'enabled': True,
        'url': MASK, 'auth_token': MASK, 'headers': {'X-Auth': MASK},
    }
    entry.update(over)
    return [entry]


# ── the report ────────────────────────────────────────────────────────

@pytest.mark.parametrize('edit,what', [
    ({'name': 'ops-renamed'}, 'renamed'),
    ({'type': 'slack'}, 'retyped'),
    ({'name': 'ops-renamed', 'type': 'slack'}, 'renamed and retyped'),
])
def test_an_edited_webhook_keeps_every_secret(edit, what):
    result = _restore_masked_list_secrets(_stored(), _submitted(**edit))[0]
    assert result['url'].endswith('REAL-SECRET'), f'the URL was lost when {what}'
    assert result['auth_token'] == 'REAL-BEARER', f'the token was lost when {what}'
    assert result['headers'] == {'X-Auth': 'REAL-HEADER'}, (
        f'the custom headers were lost when {what} — the defect took these too, '
        'and a webhook without its Authorization header fails silently'
    )


def test_two_webhooks_can_swap_names_without_swapping_secrets():
    """The case the old design feared, and the reason it refused to match by
    position: a save that both reorders identities and leaves secrets masked
    must not hand one endpoint another's credential."""
    stored = [
        {'id': 'id-a', 'name': 'first', 'type': 'generic', 'url': 'URL-A'},
        {'id': 'id-b', 'name': 'second', 'type': 'generic', 'url': 'URL-B'},
    ]
    submitted = [
        {'id': 'id-a', 'name': 'second', 'type': 'generic', 'url': MASK},
        {'id': 'id-b', 'name': 'first', 'type': 'generic', 'url': MASK},
    ]
    result = _restore_masked_list_secrets(stored, submitted)
    assert [entry['url'] for entry in result] == ['URL-A', 'URL-B']


# ── what must NOT change ──────────────────────────────────────────────

def test_a_configuration_written_before_ids_behaves_exactly_as_it_did():
    """CONTROL: no id on either side falls back to (type, name).

    An upgrade must not make anything worse before the migration has run, and
    the untouched save — the ordinary one — must still carry its secret."""
    stored = [{'name': 'ops', 'type': 'generic', 'url': 'LEGACY-SECRET'}]
    kept = _restore_masked_list_secrets(
        stored, [{'name': 'ops', 'type': 'generic', 'url': MASK}])[0]
    assert kept['url'] == 'LEGACY-SECRET'

    renamed = _restore_masked_list_secrets(
        stored, [{'name': 'ops-2', 'type': 'generic', 'url': MASK}])[0]
    assert 'url' not in renamed, (
        'without ids this is the old behaviour and must stay the old behaviour'
    )


def test_a_client_that_drops_the_id_still_matches_by_name():
    """CONTROL: an id on disk and none in the submission is a stale page or a
    client that strips fields it does not know. It falls back rather than
    losing the secret, which is what such a client would have got before."""
    result = _restore_masked_list_secrets(
        _stored(), [{'name': 'ops', 'type': 'generic', 'url': MASK}])[0]
    assert result['url'].endswith('REAL-SECRET')


def test_an_id_that_names_nothing_does_not_fall_back_to_the_name():
    """An id is a positive claim about WHICH entry this is.

    Falling back on a mismatch would hand a submission whatever secret happens
    to share its name — which is the cross-endpoint leak the whole identity
    scheme exists to prevent. A submission naming an entry that is not there is
    new, or is claiming to be something it is not; either way it gets nothing."""
    result = _restore_masked_list_secrets(
        _stored(), _submitted(id='id-that-does-not-exist'))[0]
    assert 'url' not in result
    assert 'auth_token' not in result


def test_duplicate_ids_are_ambiguous_and_get_nothing():
    """CONTROL: the ambiguity rule still holds, for ids as it did for names.

    Two stored entries under one identity leave list order as the only thing to
    match on, and order is what must never decide which credential goes where.
    Duplicate ids should not occur; if they do, the operator re-enters."""
    stored = [
        {'id': 'same', 'name': 'a', 'type': 'generic', 'url': 'URL-A'},
        {'id': 'same', 'name': 'b', 'type': 'generic', 'url': 'URL-B'},
    ]
    result = _restore_masked_list_secrets(
        stored, [{'id': 'same', 'name': 'a', 'type': 'generic', 'url': MASK}])[0]
    assert 'url' not in result


@pytest.mark.parametrize('blank', ['', '   ', None])
def test_a_blank_id_is_not_an_id(blank):
    """`''` and `'   '` are what a form posts for a field nobody filled in.

    Two entries are needed to see the difference. With one, a blank matches a
    blank either way and the test proves nothing — which is exactly what the
    first version of this test did, and a mutation that treated `''` as a real
    id sailed straight through it. With two, treating blank as an identity
    makes them AMBIGUOUS and both lose their secrets, where falling back to the
    name keeps them apart."""
    stored = [
        {'id': blank, 'name': 'ops', 'type': 'generic', 'url': 'URL-OPS'},
        {'id': blank, 'name': 'pager', 'type': 'generic', 'url': 'URL-PAGER'},
    ]
    result = _restore_masked_list_secrets(stored, [
        {'id': blank, 'name': 'ops', 'type': 'generic', 'url': MASK},
        {'id': blank, 'name': 'pager', 'type': 'generic', 'url': MASK},
    ])
    assert [e.get('url') for e in result] == ['URL-OPS', 'URL-PAGER'], (
        f'{blank!r} was treated as an identity, so two unnamed entries '
        'collided and both secrets were dropped'
    )


# ── the migration ─────────────────────────────────────────────────────

def test_ids_are_assigned_to_webhooks_that_have_none():
    settings = {'notifications': {'channels': {'webhooks': [
        {'name': 'ops', 'type': 'generic'},
        {'name': 'pager', 'type': 'gotify'},
    ]}}}
    assert assign_stable_entry_ids(settings) is True
    ids = [w['id'] for w in settings['notifications']['channels']['webhooks']]
    assert all(isinstance(i, str) and len(i) >= 8 for i in ids)
    assert len(set(ids)) == 2, 'two webhooks must not share an id'


def test_an_existing_id_is_never_replaced():
    """The id is the anchor. Reassigning it on a later load would detach every
    stored secret from the entry it belongs to — the defect, by another route."""
    settings = {'notifications': {'channels': {'webhooks': [
        {'id': 'keep-me', 'name': 'ops', 'type': 'generic'},
    ]}}}
    assert assign_stable_entry_ids(settings) is False
    assert settings['notifications']['channels']['webhooks'][0]['id'] == 'keep-me'


def test_the_migration_reports_whether_it_changed_anything():
    """CONTROL: the caller writes settings.json back on a True. Returning True
    when nothing changed would rewrite the file on every single load."""
    assert assign_stable_entry_ids({}) is False
    assert assign_stable_entry_ids({'notifications': None}) is False
    assert assign_stable_entry_ids(
        {'notifications': {'channels': {'webhooks': []}}}) is False
    assert assign_stable_entry_ids(
        {'notifications': {'channels': {'webhooks': ['not a dict']}}}) is False


def test_deploy_targets_are_deliberately_left_out():
    """They have the same shape and the same hazard, and are not listed.

    Neither route that writes them can reach the restore path:
    `/api/deploy/config` returns them unmasked and saves what it is given, and
    the generic settings POST refuses `deploy_hooks` outright. This test exists
    so that adding them is a decision someone makes on purpose, having read why
    they were left out, rather than a tidy-up."""
    from modules.core.settings import _STABLE_ID_LISTS
    assert ('deploy_hooks', 'targets') not in _STABLE_ID_LISTS

    settings = {'deploy_hooks': {'targets': [{'name': 'lb', 'type': 'ssh'}]}}
    assert assign_stable_entry_ids(settings) is False
    assert 'id' not in settings['deploy_hooks']['targets'][0]

    from modules.core.settings import SETTINGS_REJECT_KEYS
    assert 'deploy_hooks' in SETTINGS_REJECT_KEYS, (
        'the gate that makes leaving targets out safe has gone; either restore '
        'it or add ("deploy_hooks", "targets") to _STABLE_ID_LISTS'
    )
