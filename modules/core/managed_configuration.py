"""Settings declared in a file instead of through the web interface (#1317).

A deployment that is configured from code (Helm values, a GitOps repository)
names the DNS provider accounts and the CA accounts it needs in a JSON file,
and points CertMate at it with ``CERTMATE_CONFIG_FILE``. What the file
declares is applied every time the settings are read and is never written to
``settings.json`` (see ``_put_back_managed`` in settings.py), so the file
stays the single source for those accounts: change the file, restart, and the
change is in effect.

The file is read once, when the settings manager is built. A file that cannot
be used stops the process, with one line that names the key at fault: an
instance that starts with half of its configuration is worse than one that
does not start. Without the variable nothing here runs.

    {
      "version": 1,
      "dns_providers": {
        "gandi": {"accounts": {"prod": {"name": "Prod", "api_token_file": "/run/secrets/gandi"}}}
      },
      "ca_providers": {
        "private_ca": {"accounts": {"stepca": {"name": "step-ca", "acme_url": "https://ca.internal/acme/acme/directory"}}}
      }
    }

Secrets are never written in the file. A field the settings API would mask
(a token, a password, a key) takes its value by reference, ``<field>_file`` or
``<field>_env``, the same references the accounts already accept
(modules/core/secret_refs.py). JSON, not YAML: a YAML parser turns ``no`` into
a boolean and ``010`` into a number, and a file that declares credentials
should say only what it says. Helm renders it with ``toPrettyJson``.

Not in this version: the storage backend, which changes how data is reached at
startup and comes after the accounts.
"""
from __future__ import annotations

import copy
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn

CONFIG_FILE_ENV = 'CERTMATE_CONFIG_FILE'
SUPPORTED_VERSION = 1
MAX_BYTES = 1024 * 1024

# Where the accounts of each kind live in the settings document.
ACCOUNT_KINDS = ('dns_providers', 'ca_providers')

_TOP_LEVEL = frozenset({'version', *ACCOUNT_KINDS})
_NOT_YET = {'storage_backend': 'the storage backend is not supported in a configuration file yet'}
_NAME = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')
_ACCOUNT_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
_REFERENCE_SUFFIXES = ('_file', '_env')
_KIND_LABEL = {'dns_providers': 'DNS', 'ca_providers': 'CA'}


class ManagedConfigurationError(RuntimeError):
    """The configuration file cannot be used. The message names the file and the key, never a value."""


@dataclass(frozen=True)
class ManagedConfiguration:
    """A validated configuration file: ``accounts[kind][provider][account_id]`` is the account's fields."""

    path: str
    accounts: dict

    @property
    def account_paths(self):
        """Every managed account as its path in the settings document."""
        return tuple(
            (kind, provider, 'accounts', account_id)
            for kind, providers in self.accounts.items()
            for provider, by_id in providers.items()
            for account_id in by_id
        )

    @property
    def restore_paths(self):
        """What a save puts back: the accounts, and the default-account pointer apply() may have moved."""
        pointers = tuple(('default_accounts', provider) for provider in self.accounts['dns_providers'])
        return self.account_paths + pointers

    def apply(self, settings: dict) -> dict:
        """Put the managed accounts into ``settings`` (in place), over any account with the same id.

        A provider saved in the flat, single-account shape is first moved into
        ``accounts.default``: CertMate reads only ``accounts`` once the key is
        there, so the saved account would otherwise stop being found. A DNS
        provider whose default account is not configured (the empty scaffold
        the first start writes) takes the first declared account that is.
        """
        from .dns_providers import DNSManager
        for kind in ACCOUNT_KINDS:
            for provider, by_id in self.accounts[kind].items():
                target = settings.setdefault(kind, {})
                if not isinstance(target, dict):
                    target = settings[kind] = {}
                entry = target.setdefault(provider, {})
                if not isinstance(entry, dict):
                    entry = target[provider] = {}
                accounts = as_accounts(entry)
                for account_id, fields in by_id.items():
                    accounts[account_id] = copy.deepcopy(fields)
                if kind != 'dns_providers':
                    continue
                pointers = settings.setdefault('default_accounts', {})
                current = pointers.get(provider)
                if current and DNSManager._account_has_credentials(provider, accounts.get(current)):
                    continue
                for account_id, fields in by_id.items():
                    if DNSManager._account_has_credentials(provider, fields):
                        pointers[provider] = account_id
                        break
        return settings

    def normalise_baseline(self, on_disk: dict) -> dict:
        """What the file holds, with the providers this configuration touches in the ``accounts`` shape.

        apply() moves a flat account into ``accounts.default`` in memory; the
        document a save restores from has to be read the same way, or the
        saved account would be restored to nothing and lost.
        """
        baseline = copy.deepcopy(on_disk)
        for kind in ACCOUNT_KINDS:
            section = baseline.get(kind)
            if not isinstance(section, dict):
                continue
            for provider in self.accounts[kind]:
                if isinstance(section.get(provider), dict):
                    as_accounts(section[provider])
        return baseline


def as_accounts(entry: dict) -> dict:
    """Give a provider entry the ``accounts`` shape, in place, and return its accounts.

    The flat keys of the single-account shape move into the ``default`` account
    (the same move the settings page makes), so they are not left beside
    ``accounts`` as a copy nothing reads.
    """
    if not isinstance(entry.get('accounts'), dict):
        legacy = {key: value for key, value in entry.items() if key != 'accounts'}
        entry.clear()
        entry['accounts'] = {'default': legacy} if legacy else {}
    return entry['accounts']


def configured_path() -> str | None:
    """The file ``CERTMATE_CONFIG_FILE`` names, or None when the variable is unset or empty."""
    return os.getenv(CONFIG_FILE_ENV) or None


def load(path: str, *, is_secret_field: Callable[[str, str], bool],
         known_providers: dict[str, set[str]]) -> ManagedConfiguration:
    """Read and validate ``path``. Raises ManagedConfigurationError; never returns a partial result.

    ``is_secret_field(provider, name)`` is the settings module's own answer to "is this a secret", so a
    field the API masks is a field this refuses inline; ``known_providers[kind]`` are the names CertMate
    can issue with, so a declaration that could never be used is refused at the start.
    """
    def refuse(reason: str) -> NoReturn:
        raise ManagedConfigurationError(f'{CONFIG_FILE_ENV}={path}: {reason}. Refusing to start.')

    try:
        with open(path, 'rb') as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as error:
        refuse(f'cannot be read ({error.strerror or type(error).__name__})')
    if len(raw) > MAX_BYTES:
        refuse(f'is larger than {MAX_BYTES} bytes')
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        refuse(f'is not valid JSON ({error})')
    if not isinstance(document, dict):
        refuse('must hold one JSON object')

    for key in document:
        if key in _NOT_YET:
            refuse(f'"{key}": {_NOT_YET[key]}')
        if key not in _TOP_LEVEL:
            refuse(f'unknown key "{key}" (known: {", ".join(sorted(_TOP_LEVEL))})')
    if document.get('version') != SUPPORTED_VERSION:
        refuse(f'"version" must be {SUPPORTED_VERSION}')

    accounts: dict = {}
    for kind in ACCOUNT_KINDS:
        providers = document.get(kind, {})
        if not isinstance(providers, dict):
            refuse(f'"{kind}" must be an object')
        accounts[kind] = {}
        for provider, spec in providers.items():
            where = f'{kind}.{provider}'
            if not _NAME.match(provider):
                refuse(f'"{where}": the provider name must be lower-case letters, digits, "_" or "-"')
            if provider not in known_providers[kind]:
                refuse(f'"{where}": "{provider}" is not a supported {_KIND_LABEL[kind]} provider')
            if not isinstance(spec, dict) or set(spec) != {'accounts'} or not isinstance(spec['accounts'], dict):
                refuse(f'"{where}" must be an object with one key, "accounts"')
            accounts[kind][provider] = {}
            for account_id, fields in spec['accounts'].items():
                at = f'{where}.accounts.{account_id}'
                if not _ACCOUNT_ID.match(account_id):
                    refuse(f'"{where}.accounts": the account id "{account_id}" is not valid '
                           '(letters, digits, "_", "." or "-", at most 64)')
                if not isinstance(fields, dict) or not fields:
                    refuse(f'"{at}" must be a non-empty object')
                _check_fields(fields, at, provider, is_secret_field, refuse)
                accounts[kind][provider][account_id] = fields
    return ManagedConfiguration(path=path, accounts=accounts)


def _check_fields(fields: dict, at: str, provider: str, is_secret_field: Callable[[str, str], bool],
                  refuse: Callable[[str], NoReturn]) -> None:
    """Refuse a secret written inline and a reference that points at nothing."""
    for name, value in fields.items():
        here = f'{at}.{name}'
        if name.endswith(_REFERENCE_SUFFIXES):
            if not isinstance(value, str) or not value.strip():
                refuse(f'"{here}" is a reference and must name a file or a variable')
            continue
        if isinstance(value, dict):
            _check_fields(value, here, provider, is_secret_field, refuse)
            continue
        if is_secret_field(provider, name) and value not in (None, '', False):
            refuse(f'"{here}" is a secret written in the file; use "{name}_file" or "{name}_env" instead')
