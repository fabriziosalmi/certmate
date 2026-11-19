"""Whether a CA or DNS account's credentials were checked, and what the check found.

A saved account used to be drawn as fine because it was saved: a DNS token
that Cloudflare refuses read "Configured", and a private CA that did not answer
was saved with a green "CA account saved" (UX audit P39). Saving proves the
form was filled in, nothing more.

A check is one read-only call, and it says no more than that call proved:

  cloudflare  GET https://api.cloudflare.com/client/v4/zones?per_page=1. It
              passes when the token reads at least one zone, which works for
              user and account-owned tokens alike. Permission to change DNS
              records is not tested: that would take a write.
  route53     ListHostedZones with MaxItems 1, with the same limit.
  a CA        GET of the ACME directory issuance uses, following redirects
              over https as the ACME client does. The outcome is `reachable`,
              never `passed`: without registering an account nothing tells a
              good EAB key from a bad one.

Every other DNS provider is "not checkable": no call, never a pass.

The credentials are the ones issuance uses: references (`api_token_file`,
`eab_hmac_env`) are read by the resolvers issuance calls
(DNSManager.resolve_account_config, CAManager.get_eab_credentials), and a CA
account without an email uses the instance's, as issuance does.

The result is kept per account in `account_checks.json` beside settings.json,
written only by a check the server ran, so no settings write can put a "passed"
there. It is keyed by an HMAC, with the instance secret, of the credentials as
resolved when the check ran: a changed token, file or variable no longer
matches, and the account reads "never" again. An identity CertMate does not
hold (Route53 in iam_role mode) cannot be keyed; its pass says so.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import tempfile
import threading
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from .secret_refs import SecretReferenceError
from .utils import _DNS_PROVIDER_CREDENTIALS

logger = logging.getLogger(__name__)

PASSED = 'passed'
FAILED = 'failed'
REACHABLE = 'reachable'
NOT_CHECKABLE = 'not_checkable'
NEVER = 'never'

CHECKABLE_DNS_PROVIDERS = frozenset({'cloudflare', 'route53'})
CLOUDFLARE_ZONES_URL = 'https://api.cloudflare.com/client/v4/zones'
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
MAX_REDIRECTS = 5
REASON_LIMIT = 200
_TESTED_LATER = 'permission to change DNS records is tested when a certificate is requested'
# Labels. Renaming an account does not change what was checked.
_LABELS = frozenset({'name', 'description'})
_EAB_FIELDS = ('eab_kid', 'eab_key_id', 'eab_hmac', 'eab_hmac_key')
_REDIRECTS = frozenset({301, 302, 303, 307, 308})

_stores: dict[str, AccountCheckStore] = {}
_stores_lock = threading.Lock()
# Only when no instance secret is at hand (a manager graph built without auth):
# a record keyed with it does not outlive the process, which is never a false pass.
_PROCESS_KEY = secrets.token_bytes(32)


def _now() -> str:
    return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def bounded_reason(text, secrets_=()) -> str:
    """*text* on one line, at most REASON_LIMIT characters, with no secret in it.

    The reason comes from the provider (its own message) and is stored and
    shown, so a provider that echoed a credential back must not get it onto
    the page: every credential value checked is replaced before anything else.
    """
    line = str(text)
    for secret in secrets_:
        if isinstance(secret, str) and len(secret) >= 4:
            line = line.replace(secret, '********')
    line = ' '.join(line.split())
    line = ''.join(ch for ch in line if ch.isprintable())
    if len(line) > REASON_LIMIT:
        line = line[:REASON_LIMIT - 3] + '...'
    return line


def _result(outcome, reason, secrets_=()) -> dict:
    return {'outcome': outcome, 'at': _now(),
            'reason': bounded_reason(reason, secrets_) if reason else None}


def _timeout_reason(exc, host) -> str:
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return f'{host} did not answer within {CONNECT_TIMEOUT} seconds'
    return f'{host} did not finish its answer within {READ_TIMEOUT} seconds'


# ------------------------------------------------------------------ store

class AccountCheckStore:
    """The last check of each account, in one JSON file written 0600."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> tuple[dict, bool]:
        """`(data, corrupt)`."""
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return {}, False
        except (OSError, ValueError):
            return {}, True
        return (data, False) if isinstance(data, dict) else ({}, True)

    def _write(self, data) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.account_checks.', dir=str(self.path.parent))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(data, handle, indent=1, sort_keys=True)
            os.chmod(name, 0o600)
            os.replace(name, self.path)
        except OSError:
            Path(name).unlink(missing_ok=True)
            raise

    def _change(self, change) -> None:
        """Read, *change*, write, under the lock. A file that cannot be read is
        kept aside first, so the write does not replace every other result."""
        with self._lock:
            data, corrupt = self._read()
            if corrupt:
                aside = self.path.with_name(
                    f"{self.path.name}.corrupt-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}")
                try:
                    os.replace(self.path, aside)
                    logger.error("The account check results could not be read; the file was "
                                 "kept as %s and a new one started", aside.name)
                except OSError as exc:
                    logger.error("The account check results could not be read nor kept aside (%s); "
                                 "nothing was written", type(exc).__name__)
                    return
            change(data)
            try:
                self._write(data)
            except OSError as exc:
                logger.error("The account check results could not be saved (%s)", type(exc).__name__)

    def record(self, kind, provider, account_id, key, result) -> None:
        """Keep *result*, a check the server ran on the credentials *key* names."""
        entry = {'outcome': result['outcome'], 'at': result['at'],
                 'reason': result.get('reason'), 'fingerprint': key}
        self._change(lambda data: data.setdefault(kind, {}).setdefault(provider, {}).__setitem__(
            account_id, entry))

    def forget(self, kind, provider, account_id) -> None:
        if not self.path.exists():
            return

        def drop(data):
            accounts = (data.get(kind) or {}).get(provider)
            if isinstance(accounts, dict):
                accounts.pop(account_id, None)
        self._change(drop)

    def last(self, kind, provider, account_id, key) -> dict:
        """The account's last check, as `{outcome, at, reason}`.

        `never` when nothing was recorded for these credentials (*key* None:
        they cannot be resolved now), `not_checkable` for a DNS provider no
        check exists for.
        """
        data, corrupt = self._read()
        if corrupt:
            logger.warning("The account check results could not be read; every account reads "
                           "never checked until the next check")
        entry = ((data.get(kind) or {}).get(provider) or {}).get(account_id)
        if key and isinstance(entry, dict) and hmac.compare_digest(str(entry.get('fingerprint')), key):
            return {'outcome': entry.get('outcome'), 'at': entry.get('at'), 'reason': entry.get('reason')}
        if kind == 'dns' and provider not in CHECKABLE_DNS_PROVIDERS:
            return {'outcome': NOT_CHECKABLE, 'at': None, 'reason': None}
        return {'outcome': NEVER, 'at': None, 'reason': None}


def store_for(settings_manager) -> AccountCheckStore:
    """The store beside *settings_manager*'s settings.json, one per file."""
    path = str(Path(settings_manager.settings_file).parent / 'account_checks.json')
    with _stores_lock:
        if path not in _stores:
            _stores[path] = AccountCheckStore(path)
        return _stores[path]


def forget_account(settings_manager, kind, provider, account_id) -> None:
    """Drop a deleted account's record. A manager whose settings file is not a
    path (a test double) has no store."""
    if isinstance(getattr(settings_manager, 'settings_file', None), (str, os.PathLike)):
        store_for(settings_manager).forget(kind, provider, account_id)


# -------------------------------------------------------------- the key

def _ca_manager(managers):
    from .ca_manager import CAManager
    return managers.get('ca') or CAManager(managers['settings'])


def _instance_email(managers) -> str:
    return str((managers['settings'].load_settings() or {}).get('email') or '')


def _resolved(managers, kind, provider, config) -> dict:
    """The credentials as issuance would use them. Raises if they cannot be read."""
    if kind == 'dns':
        return managers['dns'].resolve_account_config(provider, config)
    eab = _ca_manager(managers).get_eab_credentials(provider, config)
    return {**config, '_eab': list(eab),
            '_email': config.get('email') or _instance_email(managers)}


def credentials_key(managers, kind, provider, config):
    """An HMAC, with the instance secret, of the resolved credentials; None
    when they cannot be resolved (a missing file, an unset variable)."""
    try:
        resolved = _resolved(managers, kind, provider, config)
    except (SecretReferenceError, ValueError):
        return None
    text = json.dumps({key: value for key, value in resolved.items() if key not in _LABELS},
                      sort_keys=True, default=str)
    auth = managers.get('auth')
    if auth is not None and hasattr(auth, 'hash_api_token'):
        return auth.hash_api_token(text)
    return 'hmac-sha256:' + hmac.new(_PROCESS_KEY, text.encode('utf-8'), 'sha256').hexdigest()


# --------------------------------------------------------------------- DNS

def _cloudflare_errors(body) -> str:
    errors = body.get('errors') if isinstance(body, dict) else None
    said = []
    for error in errors if isinstance(errors, list) else []:
        if not isinstance(error, dict):
            continue
        text = str(error.get('message') or '')
        chain = [str(link.get('message')) for link in error.get('error_chain') or []
                 if isinstance(link, dict) and link.get('message')]
        if chain:
            text += ': ' + '; '.join(chain)
        if error.get('code') is not None:
            text += f" (code {error.get('code')})"
        said.append(text)
    return '; '.join(said)


def _check_cloudflare(token):
    host = 'api.cloudflare.com'
    try:
        response = requests.get(CLOUDFLARE_ZONES_URL, params={'per_page': 1},
                                headers={'Authorization': f'Bearer {token}'},
                                timeout=TIMEOUT, allow_redirects=False)
    except requests.Timeout as exc:
        return FAILED, _timeout_reason(exc, host)
    except requests.ConnectionError as exc:
        return FAILED, f'Could not connect to {host} ({type(exc).__name__})'
    except (requests.RequestException, UnicodeError) as exc:
        # The class only: an InvalidHeader's text quotes the header, token and all.
        return FAILED, f'The request to Cloudflare was not sent ({type(exc).__name__})'
    try:
        body = response.json()
    except ValueError:
        body = {}
    zones = body.get('result') if isinstance(body, dict) else None
    if response.status_code == 200 and body.get('success') is True and isinstance(zones, list):
        if zones:
            return PASSED, f'the token can read zones; {_TESTED_LATER}'
        return FAILED, 'Cloudflare accepted the token, but it reaches no zone'
    said = _cloudflare_errors(body)
    return FAILED, f'Cloudflare answered HTTP {response.status_code}' + (f': {said}' if said else '')


def _check_route53(config):
    from .storage_backends import _aws_storage_auth, _aws_storage_client
    try:
        mode, key, secret, role_arn = _aws_storage_auth(config, 'Route53 DNS')
    except ValueError as exc:
        return FAILED, str(exc)
    try:
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return FAILED, 'boto3 is not installed here; Route53 issuance needs it too'
    timeouts = Config(connect_timeout=CONNECT_TIMEOUT, read_timeout=READ_TIMEOUT,
                      retries={'max_attempts': 1})
    try:
        client = _aws_storage_client('route53', config.get('region') or 'us-east-1', mode,
                                     key, secret, role_arn, client_config=timeouts)
        client.list_hosted_zones(MaxItems='1')
    except ClientError as exc:
        error = (exc.response or {}).get('Error') or {}
        return FAILED, f"AWS answered {error.get('Code') or 'an error'}: {error.get('Message') or ''}"
    except BotoCoreError as exc:
        return FAILED, f'{type(exc).__name__}: {exc}'
    if mode == 'iam_role':
        # Not part of the record's key: CertMate does not hold that identity.
        return PASSED, (f"this host's AWS identity can list hosted zones; {_TESTED_LATER}. "
                        "A change to that identity is not seen until the next check")
    return PASSED, f'the keys can list hosted zones; {_TESTED_LATER}'


def _secret_values(provider, config) -> list:
    fields = set(_DNS_PROVIDER_CREDENTIALS.get(provider) or ()) | set(_EAB_FIELDS)
    return [value for key, value in (config or {}).items()
            if key in fields and isinstance(value, str)]


def check_dns_account(dns_manager, provider, config) -> dict:
    """Check the DNS account *config* of *provider*, saved or about to be."""
    if provider not in CHECKABLE_DNS_PROVIDERS:
        return _result(NOT_CHECKABLE, f'CertMate cannot check {provider} credentials yet')
    ok, message = dns_manager.test_provider(provider, config)
    if not ok:
        return _result(FAILED, message)
    try:
        resolved = dns_manager.resolve_account_config(provider, config)
    except SecretReferenceError as exc:
        return _result(FAILED, f'{exc.field} names {exc.reference}, which {exc.reason}')
    if provider == 'cloudflare':
        outcome, reason = _check_cloudflare(resolved.get('api_token'))
    else:
        outcome, reason = _check_route53(resolved)
    return _result(outcome, reason, _secret_values(provider, resolved))


# ---------------------------------------------------------------------- CA

def _get_once(url, verify):
    """One GET, no redirect followed: `(response, None)` or `(None, reason)`."""
    host = urlparse(url).hostname or url
    try:
        return requests.get(url, timeout=TIMEOUT, verify=verify, allow_redirects=False), None
    except requests.Timeout as exc:
        return None, _timeout_reason(exc, host)
    except requests.exceptions.SSLError:
        return None, f'The TLS certificate of {host} could not be verified (SSLError)'
    except requests.ConnectionError as exc:
        return None, f'Could not connect to {host} ({type(exc).__name__})'
    except requests.RequestException as exc:
        return None, f'The request to {host} was not sent ({type(exc).__name__})'


def _fetch_directory(url, verify):
    """GET the directory, following redirects over https only, as the ACME
    client follows them, at most MAX_REDIRECTS times."""
    for hop in range(MAX_REDIRECTS + 1):
        host = urlparse(url).hostname or url
        response, refused = _get_once(url, verify)
        if refused:
            return FAILED, refused
        location = (getattr(response, 'headers', None) or {}).get('Location')
        if response.status_code not in _REDIRECTS or not location:
            break
        if hop == MAX_REDIRECTS:
            return FAILED, f'{host} redirected more than {MAX_REDIRECTS} times'
        url = urljoin(url, location)
        if urlparse(url).scheme.lower() != 'https':
            return FAILED, f'{host} redirected to a URL that is not https, which is not followed'
    if response.status_code != 200:
        return FAILED, f'{host} answered HTTP {response.status_code}'
    try:
        directory = response.json()
    except ValueError:
        directory = None
    if not isinstance(directory, dict) or 'newAccount' not in directory:
        return FAILED, f'{host} answered, but not with an ACME directory'
    return REACHABLE, None


def check_ca_account(ca_manager, provider, config, instance_email='') -> dict:
    """Check the CA account *config* of *provider*, saved or about to be.

    `reachable` at best: the directory answered and the account has what
    issuance reads. The CA checks the account and its EAB key only when it
    registers, which a read-only check cannot do."""
    if not str(config.get('email') or instance_email or '').strip():
        return _result(FAILED, 'Neither the account nor the instance has an email address, which the CA needs')
    valid, message = ca_manager.validate_ca_configuration(provider, config)
    if not valid:
        return _result(FAILED, message)
    try:
        eab = ca_manager.get_eab_credentials(provider, config)
        url = ca_manager.get_acme_server_url(provider, account_config=config)
    except ValueError as exc:
        return _result(FAILED, str(exc))
    secrets_ = [value for value in eab if value]
    bundle = None
    if provider == 'private_ca' and config.get('ca_cert'):
        bundle = ca_manager.create_ca_trust_bundle(provider, config)
        if not bundle:
            return _result(FAILED, 'The CA certificate is not a PEM certificate bundle')
    try:
        outcome, reason = _fetch_directory(url, bundle or True)
    finally:
        if bundle:
            Path(bundle).unlink(missing_ok=True)
    if outcome == REACHABLE:
        reason = ('The CA checks the account and its EAB key only when it registers' if secrets_
                  else 'The CA checks the account only when it registers')
    return _result(outcome, reason, secrets_)


def _ca_accounts(settings) -> dict:
    """`{provider: {account_id: config}}`, the CA accounts the settings page lists.

    `accounts`, or a legacy flat entry, which is the account `default`. And
    Let's Encrypt as the default CA with no entry: the page lists it as
    "Default account", issuance uses certbot's defaults with the instance
    email, and the account route saves it with that email (_as_accounts).
    """
    listed: dict = {}
    for provider, entry in (settings.get('ca_providers') or {}).items():
        if not isinstance(entry, dict) or not entry:
            continue
        accounts = entry['accounts'] if isinstance(entry.get('accounts'), dict) else {'default': entry}
        listed[provider] = {key: value for key, value in accounts.items() if isinstance(value, dict)}
    if (settings.get('default_ca') or 'letsencrypt') == 'letsencrypt' and 'letsencrypt' not in listed:
        listed['letsencrypt'] = {'default': {'email': settings.get('email') or ''}}
    return listed


def stored_ca_account(settings, provider, account_id):
    """The CA account *account_id* of *provider* as saved, or None."""
    return _ca_accounts(settings).get(provider, {}).get(account_id)


# -------------------------------------------------------------- HTTP glue

_RESOURCE_TYPES = {'dns': 'dns_provider', 'ca': 'ca_provider'}


def run_check(managers, kind, provider, config) -> dict:
    if kind == 'dns':
        return check_dns_account(managers['dns'], provider, config)
    return check_ca_account(_ca_manager(managers), provider, config, _instance_email(managers))


def _stored(kind, managers, provider, account_id):
    if kind == 'dns':
        return managers['dns'].stored_account(provider, account_id)
    return stored_ca_account(managers['settings'].load_settings() or {}, provider, account_id)


def _wants(flag) -> bool:
    from flask import request
    return str(request.args.get(flag, '')).strip().lower() in ('1', 'true', 'yes')


def _audit(managers, kind, provider, account_id, result) -> None:
    from flask import request
    audit = managers.get('audit')
    if not audit:
        return
    user = getattr(request, 'current_user', None) or {}
    audit.log_operation(
        operation='check_account', resource_type=_RESOURCE_TYPES[kind],
        resource_id=f'{provider}:{account_id}',
        status='success' if result['outcome'] in (PASSED, REACHABLE) else 'failure',
        details={'outcome': result['outcome']}, user=user.get('username'),
        ip_address=request.remote_addr)


def keep(managers, kind, provider, account_id, config, result) -> None:
    """Keep *result*, a check of the saved account *config*; audit and log it."""
    store_for(managers['settings']).record(
        kind, provider, account_id, credentials_key(managers, kind, provider, config), result)
    _audit(managers, kind, provider, account_id, result)
    # Never the reason: it is the provider's text.
    logger.info("Credential check of %s account %r of provider %r ended %s",
                kind, account_id, provider, result['outcome'])


def run_and_keep(managers, kind, provider, account_id, config) -> dict:
    """Check the saved account *config* and keep the result."""
    result = run_check(managers, kind, provider, config)
    keep(managers, kind, provider, account_id, config, result)
    return result


def answer_with_last_checks(managers, accounts) -> list:
    """The DNS account list, each entry with its `last_check`."""
    store = store_for(managers['settings'])
    for account in accounts if isinstance(accounts, list) else []:
        if isinstance(account, dict) and account.get('provider') and account.get('account_id'):
            provider, account_id = account['provider'], account['account_id']
            config = managers['dns'].stored_account(provider, account_id) or {}
            account['last_check'] = store.last(
                'dns', provider, account_id, credentials_key(managers, 'dns', provider, config))
    return accounts


def ca_last_checks(managers) -> list:
    """Every saved CA account with its `last_check`."""
    store = store_for(managers['settings'])
    listed = []
    for provider, accounts in sorted(_ca_accounts(managers['settings'].load_settings() or {}).items()):
        for account_id, config in accounts.items():
            key = credentials_key(managers, 'ca', provider, config)
            listed.append({'provider': provider, 'account_id': account_id,
                           'last_check': store.last('ca', provider, account_id, key)})
    return listed


def check_before_save(managers, kind, provider, config):
    """For a save asked with `?check=1`: `(result, refusal)`, or `(None, None)`
    when the request asks for no check.

    The refusal is the 422 ACCOUNT_CHECK_FAILED answer for a failed check,
    unless `save_anyway=1` is asked too. A check that could not run (no
    answer, a refused connection) is a failed check. Call it after every
    refusal of the save's own, so nothing goes out for a save that would be
    refused anyway."""
    from flask import jsonify, make_response
    if not _wants('check'):
        return None, None
    result = run_check(managers, kind, provider, config)
    if result['outcome'] == FAILED and not _wants('save_anyway'):
        return result, make_response(jsonify({
            'error': f"The check failed: {result['reason']}",
            'code': 'ACCOUNT_CHECK_FAILED', 'last_check': result}), 422)
    return result, None


def keep_after_save(managers, kind, provider, account_id, result) -> None:
    """Keep *result* for the account as saved, read back."""
    if result is None:
        return
    saved = _stored(kind, managers, provider, account_id)
    if saved is not None:
        keep(managers, kind, provider, account_id, saved, result)


def checks_before_save(kind, managers_of, target_of):
    """Decorator for the DNS account saves: `?check=1` checks first.

    See check_before_save. Without `check`, a save is what it was, and a
    stored result applies only while the credentials are unchanged (see
    credentials_key). *target_of(request, kwargs, managers)* gives
    `(provider, account_id, config)`, the account the view is about to save,
    or None to leave the request to the view (which answers its own 400). A
    decorator, like refuses_a_taken_account, so the budgeted route closures
    gain no branch.
    """
    def decorator(view):
        @wraps(view)
        def guarded(*args, **kwargs):
            from flask import make_response, request
            if request.method not in ('POST', 'PUT') or not _wants('check'):
                return view(*args, **kwargs)
            managers = managers_of()
            target = target_of(request, kwargs, managers)
            if target is None:
                return view(*args, **kwargs)
            provider, account_id, config = target
            result, refusal = check_before_save(managers, kind, provider, config)
            if refusal is not None:
                return refusal
            response = make_response(view(*args, **kwargs))
            if response.status_code < 300:
                keep_after_save(managers, kind, provider, account_id, result)
                body = response.get_json(silent=True)
                if isinstance(body, dict):
                    body['last_check'] = result
                    response.set_data(json.dumps(body))
            return response
        return guarded
    return decorator


def dns_create_target(request, kwargs, managers):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    account_id = data.get('name') or data.get('account_id')
    provider = kwargs.get('provider') or data.get('provider')
    config = data.get('config')
    if not account_id or not provider or not isinstance(config, dict):
        return None
    return provider, account_id, config


def dns_update_target(request, kwargs, managers):
    data = request.get_json(silent=True) or {}
    provider, account_id = kwargs.get('provider'), kwargs.get('account_id')
    if not isinstance(data, dict) or not provider or not account_id:
        return None
    existing = managers['dns'].stored_account(provider, account_id) or {}
    # The merge the update route makes: the masked placeholder keeps a secret.
    merged = dict(existing)
    merged.update({key: value for key, value in data.items()
                   if key != 'set_as_default' and value != '********'})
    return provider, account_id, merged
