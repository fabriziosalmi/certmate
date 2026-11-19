"""Let a credential name where it lives instead of holding its value.

Every DNS provider API token and the OIDC client secret rest in
`settings.json` as cleartext JSON. The file is written 0600, which is the
right permission and is not the point: that file is what gets backed up,
copied between hosts, mounted into a container and handed to whoever is
debugging a renewal. A deployment that already keeps its secrets in a Docker
or Kubernetes secret had no way to keep them out of it.

`API_BEARER_TOKEN_FILE` already solved this shape for one secret. This is the
same idea generalised to the settings file: any field may be supplied
indirectly, by naming a file or an environment variable beside it.

    "cloudflare": {"accounts": {"prod": {"api_token_file": "/run/secrets/cf"}}}
    "cloudflare": {"accounts": {"prod": {"api_token_env": "CF_API_TOKEN"}}}

This does not encrypt anything and does not claim to. What it does is move the
highest-value secrets out of the file that travels, using a mechanism the
project already documents.

Three decisions worth stating, because each is a failure mode if reversed:

**A reference beats a literal.** A deployment moving to secrets sets
`api_token_file` and leaves the old `api_token` behind. Having the stale
literal win would keep issuing with the credential they thought they had
replaced, and nothing would say so. Order is `_file`, then `_env`, then the
literal.

**Trailing whitespace is stripped.** `docker secret` and `kubectl create
secret --from-file` both produce files ending in a newline. A token with a
trailing `\\n` reaches the DNS API as a wrong token, and what comes back is an
authentication error that names nothing useful.

**An unresolvable reference is never silently empty.** A missing file or an
unset variable raises rather than resolving to `''`, because an empty
credential produces a certbot failure that reads like a provider outage.
"""
from __future__ import annotations

import os
import stat

# Only these two suffixes are references. Checked against the credential
# registry by a test, so a provider field that one day genuinely ends in
# `_file` is a failing test rather than a field silently read as a pointer.
FILE_SUFFIX = '_file'
ENV_SUFFIX = '_env'

# The most a referenced file may hold. A credential is an API token, a key
# pair, a PEM private key or a cloud service-account JSON document: a few
# kilobytes at the most. 64 KiB leaves an order of magnitude of room above
# that, and stops a reference to a log, an image or a device from being read
# into memory, or read forever, by a settings save or an issuance.
MAX_SECRET_FILE_BYTES = 64 * 1024

# What is wrong with a reference, as SecretReferenceError.problem says it.
PROBLEMS = ('missing', 'not_a_file', 'too_large', 'not_text', 'empty', 'unreadable', 'unset')


class SecretReferenceError(Exception):
    """A field named a file or a variable that did not yield a value.

    Carries the field and the reference — never the value, and never a value
    read partially — because this is logged and the log is not the place for a
    credential.
    """

    def __init__(self, field: str, reference: str, reason: str, problem: str = 'unreadable'):
        self.field = field
        self.reference = reference
        self.reason = reason
        # One of PROBLEMS: what a caller can say about it without parsing
        # the reason.
        self.problem = problem
        super().__init__(f'{field}: {reference} {reason}')


def _read_file(field: str, path: str) -> str:
    """*field* is threaded through so the error names it. It was not, once,
    and the log line read `field ''` — which is the one thing the operator
    needed, since the whole point of that message is to say which credential
    the missing mount belongs to.

    Only a regular file, of at most MAX_SECRET_FILE_BYTES, holding UTF-8
    text. Opened without blocking and checked on the descriptor, so a FIFO
    or a device named here is refused rather than read forever, and a file
    swapped between a check and the read cannot slip past it. Every failure
    is a SecretReferenceError with its problem: a reference that is not
    text used to raise UnicodeDecodeError, which no caller expected (review
    of UX audit P19: a settings save answered 500 after writing).
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    except FileNotFoundError:
        raise SecretReferenceError(field, path, 'could not be read: it does not exist', 'missing') from None
    except OSError as exc:
        # strerror, not the exception: str(OSError) includes the filename,
        # which is already in the message, and nothing else useful.
        raise SecretReferenceError(field, path, f'could not be read ({exc.strerror})', 'unreadable') from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SecretReferenceError(field, path, 'is not a regular file', 'not_a_file')
        chunks, size = [], 0
        while size <= MAX_SECRET_FILE_BYTES:
            chunk = os.read(descriptor, MAX_SECRET_FILE_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise SecretReferenceError(field, path, f'could not be read ({exc.strerror})', 'unreadable') from None
    finally:
        os.close(descriptor)
    if size > MAX_SECRET_FILE_BYTES:
        raise SecretReferenceError(field, path, f'is larger than {MAX_SECRET_FILE_BYTES // 1024} KiB',
                                   'too_large')
    try:
        return b''.join(chunks).decode('utf-8')
    except UnicodeDecodeError:
        raise SecretReferenceError(field, path, 'is not UTF-8 text', 'not_text') from None


def resolve_field(config: dict, field: str) -> str | None:
    """The value for *field*, following a reference if one is present.

    Returns None when the field is absent altogether, which is different from
    a reference that could not be resolved — that raises.
    """
    file_key = field + FILE_SUFFIX
    env_key = field + ENV_SUFFIX

    reference = config.get(file_key)
    if isinstance(reference, str) and reference.strip():
        value = _read_file(field, reference.strip()).strip()
        if not value:
            raise SecretReferenceError(field, reference.strip(), 'is empty', 'empty')
        return value

    reference = config.get(env_key)
    if isinstance(reference, str) and reference.strip():
        value = (os.environ.get(reference.strip()) or '').strip()
        if not value:
            raise SecretReferenceError(
                field, reference.strip(), 'is unset or empty in the environment', 'unset')
        return value

    literal = config.get(field)
    return literal if literal is not None else None


def referenced_fields(config: dict) -> set[str]:
    """The fields this config supplies by reference rather than by value."""
    if not isinstance(config, dict):
        return set()
    fields = set()
    for key, value in config.items():
        if not isinstance(value, str) or not value.strip():
            continue
        for suffix in (FILE_SUFFIX, ENV_SUFFIX):
            if key.endswith(suffix) and len(key) > len(suffix):
                fields.add(key[:-len(suffix)])
    return fields


def has_value(config: dict, field: str) -> bool:
    """True when *field* is supplied, by value or by reference.

    Deliberately does NOT resolve. This answers "is this account configured",
    which is asked to render a settings page — reading every secret off disk to
    decide whether to draw a green tick would put credentials in memory for a
    page view, and would make the page fail when a secret is merely not mounted
    on the host that happens to be rendering it.
    """
    if not isinstance(config, dict):
        return False
    literal = config.get(field)
    # `str(...).strip()`, matching what validate_dns_provider_account did
    # before this replaced it: a whitespace-only token is not a token, and
    # letting one count as configured would move the failure to certbot.
    if isinstance(literal, str):
        if literal.strip():
            return True
    elif literal:
        return True
    return field in referenced_fields(config)


def resolve(config: dict) -> dict:
    """A copy of *config* with every referenced field resolved to its value.

    The reference keys are left in place: strategies read the fields they know
    by name, so an extra `api_token_file` key is inert, and removing it would
    make the returned dict no longer round-trip against what was stored.

    Raises SecretReferenceError if any reference cannot be resolved. Resolving
    the rest and leaving one field empty would produce a failure at the DNS
    provider that names the credential rather than the mount.
    """
    if not isinstance(config, dict):
        return config
    resolved = dict(config)
    for field in sorted(referenced_fields(config)):
        resolved[field] = resolve_field(config, field)
    return resolved
