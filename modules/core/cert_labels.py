"""Notes and tags on a server certificate (#1043).

Two optional fields an operator attaches to a certificate after it exists: a
free-text note, and a list of short tags. They record what CertMate cannot know
on its own (where a certificate was installed by hand, which ticket it was
issued for, who owns it) so that knowledge stops drifting into a spreadsheet.

They are stored in the certificate's ``metadata.json`` next to the
``deployment_*`` fields. Keys that a reissue does not rebuild belong to the
certificate and survive renewal and Edit & Reissue (#421), so nothing here
needs its own persistence.

The rules are in one place because two callers depend on them agreeing. The
write path refuses what does not fit; the deploy-hook path reads the same field
back and hands it to a shell as ``CERTMATE_TAGS``. A tag is held to a small
charset precisely so that second use is safe by construction: a value that can
only contain letters, digits and ``. _ : / -`` cannot carry a quote, a space or
a ``$``, wherever a hook author ends up pasting it.
"""

import re

MAX_NOTES_LENGTH = 2000
MAX_TAGS = 20
MAX_TAG_LENGTH = 32

# Starts with a letter or digit, so a tag can never read as a command-line
# option (`-rf`) or an absolute path (`/etc`) when a hook uses it unquoted.
_TAG_RE = re.compile(r'[a-z0-9][a-z0-9._:/-]*')


def normalize_tags(value):
    """Return ``value`` as a clean list of tags, or raise ``ValueError``.

    Tags compare case-insensitively, so they are stored lower-cased and a
    duplicate that differs only by case is dropped. Order is kept: it is the
    order the operator typed, and reordering would make an unchanged list look
    changed to whoever reads the audit log.
    """
    if not isinstance(value, list):
        raise ValueError('tags must be a list of strings')
    tags = []
    for raw in value:
        if not isinstance(raw, str):
            raise ValueError('tags must be a list of strings')
        tag = raw.strip().lower()
        if not tag or len(tag) > MAX_TAG_LENGTH or not _TAG_RE.fullmatch(tag):
            raise ValueError(
                f'invalid tag {raw[:40]!r}: use 1-{MAX_TAG_LENGTH} letters, digits, '
                f"'.', '_', '-', ':' or '/', starting with a letter or digit")
        if tag not in tags:
            tags.append(tag)
    if len(tags) > MAX_TAGS:
        raise ValueError(f'at most {MAX_TAGS} tags per certificate')
    return tags


def normalize_notes(value):
    """Return ``value`` as a clean note, or raise ``ValueError``.

    An empty or whitespace-only note is returned as ``''`` and the caller
    treats that as "no note". Control characters other than a newline or a tab
    are refused: a note is shown in a table and a detail panel, and a stray
    escape or NUL has no business in either.
    """
    if not isinstance(value, str):
        raise ValueError('notes must be a string')
    if len(value) > MAX_NOTES_LENGTH:
        raise ValueError(f'notes must be at most {MAX_NOTES_LENGTH} characters')
    if any(ord(c) < 32 and c not in '\n\t' or ord(c) == 127 for c in value):
        raise ValueError('notes must not contain control characters')
    return value.strip()


def tags_from_metadata(metadata):
    """The tags stored in ``metadata``, as a list that is safe to use.

    Read-side counterpart of :func:`normalize_tags`. ``metadata.json`` is a file
    an operator can edit by hand and a backup can bring back from an older
    version, so what is stored is not trusted to have passed the write path. A
    malformed or out-of-charset entry is skipped rather than raised: this feeds
    a deploy hook, and a bad tag must not stop a certificate being deployed.
    """
    stored = (metadata or {}).get('tags')
    if not isinstance(stored, list):
        return []
    tags = []
    for raw in stored:
        if isinstance(raw, str):
            tag = raw.strip().lower()
            if tag and len(tag) <= MAX_TAG_LENGTH and _TAG_RE.fullmatch(tag) and tag not in tags:
                tags.append(tag)
    return tags[:MAX_TAGS]
