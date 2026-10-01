"""A stand-in for the `infisical-python` SDK that has the SDK's real shape.

Used by the tests that must not need the SDK installed. tests/test_infisical_backend_matches_its_sdk.py
checks every name here against the real one in the job that has it.
"""

# The SDK's surface as it is, not as the backend once assumed it was: the module is
# `infisical_client`, a call takes ONE options object, the methods are camelCase, and a
# result names its secret `secret_key`. The option fields below are the real ones;
# tests/test_infisical_backend_matches_its_sdk.py checks them against the installed SDK
# (the job that has it), so a rename cannot leave this fake agreeing with the backend and
# disagreeing with the library, which is how the backend ran in no release at all.
OPTION_FIELDS = {
    'GetSecretOptions': ('environment', 'project_id', 'secret_name', 'expand_secret_references',
                         'include_imports', 'path', 'type'),
    'CreateSecretOptions': ('environment', 'project_id', 'secret_name', 'secret_value', 'path',
                            'secret_comment', 'skip_multiline_encoding', 'type'),
    'UpdateSecretOptions': ('environment', 'project_id', 'secret_name', 'secret_value', 'path',
                            'skip_multiline_encoding', 'type'),
    'DeleteSecretOptions': ('environment', 'project_id', 'secret_name', 'path', 'type'),
    'ListSecretsOptions': ('environment', 'project_id', 'attach_to_process_env',
                           'expand_secret_references', 'include_imports', 'path', 'recursive'),
}


def make_sdk_stub():
    """A module standing in for `infisical_client`, with the real option fields."""
    import dataclasses
    import types
    module = types.ModuleType('infisical_client')
    for name, fields in OPTION_FIELDS.items():
        setattr(module, name, dataclasses.make_dataclass(
            name, [(f, object, dataclasses.field(default=None)) for f in fields]))
    return module


class SecretElement:
    """What a call returns: `secret_key` and `secret_value`, as the SDK's SecretElement."""
    def __init__(self, name, value):
        self.secret_key = name
        self.secret_value = value


class FakeInfisicalClient:
    """camelCase methods, one options object each, a bare Exception for a missing secret."""

    def __init__(self, sdk):
        self.store = {}  # secret_name -> secret_value
        self._sdk = sdk

    def _check(self, options, kind):
        assert isinstance(options, getattr(self._sdk, kind)), (
            f'{kind} expected, got {type(options).__name__}: the SDK takes one options object')

    def updateSecret(self, options):
        self._check(options, 'UpdateSecretOptions')
        if options.secret_name not in self.store:
            raise Exception(f"Secret with name '{options.secret_name}' not found.")
        self.store[options.secret_name] = options.secret_value
        return SecretElement(options.secret_name, options.secret_value)

    def createSecret(self, options):
        self._check(options, 'CreateSecretOptions')
        if options.secret_name in self.store:
            raise Exception(f"[Bad request]: Secret with name '{options.secret_name}' already exists.")
        self.store[options.secret_name] = options.secret_value
        return SecretElement(options.secret_name, options.secret_value)

    def getSecret(self, options):
        self._check(options, 'GetSecretOptions')
        if options.secret_name not in self.store:
            raise Exception(f"Secret with name '{options.secret_name}' not found.")
        return SecretElement(options.secret_name, self.store[options.secret_name])

    def listSecrets(self, options):
        self._check(options, 'ListSecretsOptions')
        return [SecretElement(n, v) for n, v in self.store.items()]

    def deleteSecret(self, options):
        self._check(options, 'DeleteSecretOptions')
        if options.secret_name not in self.store:
            raise Exception(f"Secret with name '{options.secret_name}' not found.")
        return SecretElement(options.secret_name, self.store.pop(options.secret_name))
