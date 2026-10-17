"""Which DNS providers this instance can issue with.

The first-run wizard offered every supported provider alike, including the
ones whose certbot plugin is not in the image: issuance with one of those
fails at its preflight, after the operator has typed the credentials in.
This asks certbot once which plugins it has, and answers for every provider
with the same rule the preflight applies (certificates.py): a provider whose
strategy uses the manual hook, and acme-dns, need no plugin; any other needs
its plugin installed. A DNS alias also needs none, but that is a per-domain
choice the wizard does not know about yet.

It runs the command the preflight runs (`certbot plugins`, from PATH, see
dns_strategies.check_certbot_plugin_installed) and reads its output the same
way, through the application's shell executor like the other certbot calls.

`certbot plugins` takes about half a second in the image, so the answer is
kept for five minutes. A plugin only arrives with a new image, and a new
image is a restart, so the cache cannot hide a change.
"""
import subprocess
import threading
import time

from .dns_providers import DNSManager
from .dns_strategies import DNSStrategyFactory
from .utils import utc_now

CACHE_SECONDS = 300
_NEEDS_NO_PLUGIN = {'acme-dns'}

_lock = threading.Lock()
_cached = {'at': 0.0, 'value': None}


def installed_plugins(shell):
    """The plugin names `certbot plugins` lists, or None when certbot could not be asked."""
    if shell is None:
        return None
    try:
        result = shell.run(['certbot', 'plugins'], timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    stdout = getattr(result, 'stdout', None)
    if getattr(result, 'returncode', 1) != 0 or not isinstance(stdout, str):
        return None
    return {line.strip()[2:].strip() for line in stdout.splitlines()
            if line.strip().startswith('* ')}


def availability(plugins):
    """Every supported provider, with its plugin and whether it can issue here.

    `available` is None for a provider that needs a plugin when *plugins* is
    None: certbot could not be asked, and "unknown" is not "missing".
    """
    providers = []
    for name in DNSManager.SUPPORTED_PROVIDERS:
        plugin = DNSStrategyFactory.get_strategy(name).plugin_name
        if plugin == 'manual' or name in _NEEDS_NO_PLUGIN:
            providers.append({'provider': name, 'plugin': None, 'available': True})
        else:
            providers.append({'provider': name, 'plugin': plugin,
                              'available': None if plugins is None else plugin in plugins})
    return providers


def current(shell, now=time.monotonic):
    """The answer the API gives, from a cache of CACHE_SECONDS."""
    with _lock:
        if _cached['value'] is None or now() - _cached['at'] >= CACHE_SECONDS:
            plugins = installed_plugins(shell)
            _cached['value'] = {
                'certbot_answered': plugins is not None,
                'checked_at': utc_now().isoformat(),
                'providers': availability(plugins),
            }
            _cached['at'] = now()
        return _cached['value']


def forget():
    """Drop the cached answer (for tests)."""
    with _lock:
        _cached['value'] = None
        _cached['at'] = 0.0
