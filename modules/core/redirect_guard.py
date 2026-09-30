"""A `requests` session that does not follow a redirect off the address it was given.

`requests` follows redirects by default, and what it carries across a host
change is narrower than it looks: it drops `Authorization`, and nothing else. A
request that holds a private key in its body, or a credential in any other
header (`X-Vault-Token`), arrives intact at whichever host the answer names.
A 307 or 308 keeps the method and the body, so the key goes too.

This session refuses instead. A redirect to the SAME origin (scheme, host and
port) is followed, because a trailing-slash or path redirect is ordinary. A
redirect to anything else is refused before any request is made there, and so is
a step from https down to http on the same host. The refusal names the host the
answer pointed at and nothing else: the path and query of a Location can carry
credentials of their own.

Not a subclass of `requests.RequestException` on purpose. That is an `OSError`,
and the storage backends retry `OSError` as a transient fault, which would send
the same body to the configured address two more times for an answer that will
not change.
"""

from urllib.parse import urljoin, urlparse

import requests

_DEFAULT_PORTS = {'http': 80, 'https': 443}


class RedirectRefused(Exception):
    """The address answered with a redirect that was not followed."""


def _origin(url):
    parsed = urlparse(url)
    port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme)
    return parsed.scheme, (parsed.hostname or '').lower(), port


class GuardedSession(requests.Session):
    """Follows a redirect only within one origin, and never from https to http."""

    def __init__(self, hint=''):
        super().__init__()
        self._hint = hint

    def get_redirect_target(self, resp):
        target = super().get_redirect_target(resp)
        if target is None:
            return None
        destination = urljoin(resp.url, target)
        if urlparse(resp.url).scheme == 'https' and urlparse(destination).scheme != 'https':
            raise RedirectRefused(self._message(
                f'a redirect from https to {urlparse(destination).scheme or "a non-https address"} '
                f'is refused'))
        if _origin(resp.url) != _origin(destination):
            host = urlparse(destination).hostname or 'another address'
            raise RedirectRefused(self._message(
                f'a redirect to {host} is refused: it is not the address that was configured'))
        return target

    def _message(self, what):
        return f'{what}. The request carries credentials and key material, so it is not repeated elsewhere.' \
               + (f' {self._hint}' if self._hint else '')
