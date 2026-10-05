"""API keys in states the application no longer creates but may still hold."""


def stored_as_admin_with_domains(container, name, domains):
    """A key stored with the admin role and `allowed_domains`.

    `create_api_key` refuses that combination, and so does `POST /api/keys`. A
    release before those refusals could write it, and it is still on disk on
    an instance that did. Made here the only way left: an operator key whose
    stored role is then set, as the old code set it.
    """
    ok, key = container.managers['auth'].create_api_key(
        name, role='operator', allowed_domains=list(domains))
    assert ok, key

    def as_it_was_written(settings):
        settings['api_keys'][key['id']]['role'] = 'admin'

    container.managers['settings'].update(as_it_was_written, 'test: a key from before the rule')
    return key


def the_downgrade_lifted():
    """A context in which such a key is honoured as the admin it is stored as.

    `AuthManager.effective_key_role` makes it act as an operator, so no
    restricted key reaches a route that takes the admin role, and the refusals
    those routes have of their own cannot be seen from outside. They are kept
    as a second line. This lifts the first one, so a test can show the second
    holds by itself.
    """
    from unittest import mock

    from modules.core.auth import AuthManager
    return mock.patch.object(
        AuthManager, 'effective_key_role',
        classmethod(lambda cls, role, allowed_domains: cls._normalize_role(role)))
