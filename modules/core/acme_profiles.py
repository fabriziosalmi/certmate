"""ACME certificate profiles (#395): which kind of certificate the CA issues.

A CA that speaks profiles lists them in its directory, under `meta.profiles`. Let's Encrypt
offers, in production and on staging (measured on 2026-10-03): `classic` (90 days, the default),
`tlsserver` (45 days, no Common Name) and `shortlived` (160 hours, the only one that takes IP
addresses). A certificate asks for one in its order, and certbot sends it with
`--required-profile` (the order fails when the CA does not offer it) or `--preferred-profile`
(the CA's default is used instead).

CertMate uses both, on purpose:

* **at issuance, required.** The operator is there and chose the profile; a certificate of
  another kind, issued without a word, is not what was asked for.
* **at renewal, preferred.** A CA can withdraw a profile (Let's Encrypt retired `tlsclient` on
  2026-07-08). A renewal that fails on it leaves the certificate to expire, which is worse than
  a renewal under the CA's default. So the renewal configuration certbot writes is softened from
  required to preferred after the issuance, and the renewal says when the profile is no longer
  offered (`profile_offered`), so the fallback is told rather than silent.

The renewal decision itself, how long before expiry a 45-day or a 160-hour certificate renews,
is modules/core/renewal_policy.py (#393).
"""
import os
import re
from pathlib import Path

# The profile names CAs publish are short identifiers. Anything else is refused before it can
# reach a certbot argument list or a configuration file.
PROFILE_NAME = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')


def validate_profile(value):
    """(ok, normalized or error). None and '' mean "no profile": the CA's default."""
    if value is None or value == '':
        return True, None
    if not isinstance(value, str):
        return False, 'acme_profile must be a string'
    name = value.strip().lower()
    if not PROFILE_NAME.match(name):
        return False, ('acme_profile must be a profile name the CA publishes, such as '
                       'classic, tlsserver or shortlived')
    return True, name


def profiles_offered(directory):
    """The profile names a CA's directory document lists, or None when it lists none."""
    if not isinstance(directory, dict):
        return None
    meta = directory.get('meta')
    profiles = meta.get('profiles') if isinstance(meta, dict) else None
    if not isinstance(profiles, dict) or not profiles:
        return None
    return sorted(str(name) for name in profiles)


def profile_offered(directory, profile):
    """True, False, or None when the directory could not be read (nothing is known)."""
    if directory is None:
        return None
    offered = profiles_offered(directory)
    return bool(offered) and profile in offered


# Horizontal whitespace only: `\s` would match the newline and take the line break (and a blank
# line after it) with the match.
_REQUIRED_LINE = re.compile(r'^([ \t]*)required_profile([ \t]*=[ \t]*)(\S+)[ \t]*$', re.M)


def soften_renewal_conf(conf_path):
    """Turn `required_profile = X` into `preferred_profile = X` in a certbot renewal
    configuration. Returns the profile it softened, or None when there was nothing to do.

    certbot restores `required_profile` from this file on every `certbot renew`, and a
    required profile wins over a preferred one (certbot/_internal/client.py), so passing
    `--preferred-profile` on the renewal's command line is not enough: the line itself goes.
    """
    path = Path(conf_path)
    try:
        text = path.read_text(encoding='utf-8')
    except OSError:
        return None
    match = _REQUIRED_LINE.search(text)
    if not match:
        return None
    # The required line becomes the only profile line: an older preferred_profile line, if a
    # previous issuance left one, would otherwise sit beside it and certbot would read either.
    without = ''.join(line for line in text.splitlines(keepends=True)
                      if not re.match(r'^[ \t]*preferred_profile[ \t]*=', line))
    softened = _REQUIRED_LINE.sub(r'\1preferred_profile\2\3', without, count=1)
    # Written whole or not at all: a renewal configuration cut in half breaks the lineage.
    temporary = path.with_name(path.name + '.profile-tmp')
    temporary.write_text(softened, encoding='utf-8')
    os.replace(temporary, path)
    return match.group(3)
