"""Whether a CA or DNS account's credentials were checked, and what the check found.

A saved account used to be drawn as fine because it was saved: a DNS token
that Cloudflare refuses read "Configured", and a private CA that did not answer
was saved with a green "CA account saved" (UX audit P39). Saving proves the
form was filled in, nothing more.

A check here is one read-only call that only correct credentials pass:

  cloudflare  GET https://api.cloudflare.com/client/v4/user/tokens/verify
  route53     ListHostedZones with MaxItems 1
  a CA        GET of the ACME directory issuance uses (the CA's own, or the
              account's acme_url for a private CA, Sectigo or DigiCert)

Every other DNS provider is "not checkable": no call is made and nothing
passes. A CA check cannot test an EAB key without registering an account, so a
CA pass means the directory answered and the account has what issuance reads,
and says so in its reason.

The credentials are the ones issuance uses: references (`api_token_file`,
`eab_hmac_env`) are read by the resolvers issuance calls
(DNSManager.resolve_account_config, CAManager.get_eab_credentials), never by a
second copy.

The result is kept per account in `account_checks.json` beside settings.json,
written only by a check the server ran. It is not in settings.json, so no
settings write (the settings endpoints, an account save, a restore) can put a
"passed" there. It carries a fingerprint of the account as checked: once the
account changes, the stored result no longer describes it and the account reads
"never checked" again.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import requests

from .secret_refs import SecretReferenceError
from .utils import _DNS_PROVIDER_CREDENTIALS

logger = logging.getLogger(__name__)

PASSED = 'passed'
FAILED = 'failed'
NOT_CHECKABLE = 'not_checkable'
NEVER = 'never'

CHECKABLE_DNS_PROVIDERS = frozenset({'cloudflare', 'route53'})
CLOUDFLARE_VERIFY_URL = 'https://api.cloudflare.com/client/v4/user/tokens/verify'
# (connect, read) in seconds: a host that does not answer costs five.
TIMEOUT = (5, 10)
REASON_LIMIT = 200
# Labels. Renaming an account does not change what was checked.
_LABELS = frozenset({'name', 'description'})
_EAB_FIELDS = ('eab_kid', 'eab_key_id', 'eab_hmac', 'eab_hmac_key')

_stores: dict[str, AccountCheckStore] = {}
_stores_lock = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def bounded_reason(text, secrets=()) -> str:
    """*text* on one line, at most REASON_LIMIT characters, with no secret in it.

    The reason comes from the provider (its own message) and is stored and
    shown, so a provider that echoed a credential back must not get it onto
    the page: every credential value checked is replaced before anything else.
    """
    line = str(text)
    for secret in secrets:
        if isinstance(secret, str) and len(secret) >= 4:
            line = line.replace(secret, '********')
    line = ' '.join(line.split())
    line = ''.join(ch for ch in line if ch.isprintable())
    if len(line) > REASON_LIMIT:
        line = line[:REASON_LIMIT - 3] + '...'
    return line


def _result(outcome, reason, secrets=()) -> dict:
    return {'outcome': outcome, 'at': _now(),
            'reason': bounded_reason(reason, secrets) if reason else None}


def fingerprint(config) -> str:
    """What the stored result is about: the account as saved, labels aside."""
    shaped = {key: value for key, value in (config or {}).items() if key not in _LABELS}
    return hashlib.sha256(
        json.dumps(shaped, sort_keys=True, default=str).encode('utf-8')).hexdigest()


class AccountCheckStore:
    """The last check of each account, in one JSON file written 0600."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            logger.warning("The account check results could not be read (%s); "
                           "every account reads never checked", type(exc).__name__)
            return {}
        return data if isinstance(data, dict) else {}

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

    def record(self, kind, provider, account_id, config, result) -> None:
        """Keep *result*, a check the server ran on *config*."""
        entry = {'outcome': result['outcome'], 'at': result['at'],
                 'reason': result.get('reason'), 'fingerprint': fingerprint(config)}
        with self._lock:
            data = self._read()
            data.setdefault(kind, {}).setdefault(provider, {})[account_id] = entry
            try:
                self._write(data)
            except OSError as exc:
                logger.error("The result of an account check could not be saved (%s)",
                             type(exc).__name__)

    def last(self, kind, provider, account_id, config) -> dict:
        """The account's last check, as `{outcome, at, reason}`.

        `never` when nothing was recorded for the account as it is now, and
        `not_checkable` for a DNS provider no check exists for.
        """
        entry = (((self._read().get(kind) or {}).get(provider) or {}).get(account_id))
        if isinstance(entry, dict) and entry.get('fingerprint') == fingerprint(config):
            return {'outcome': entry.get('outcome'), 'at': entry.get('at'),
                    'reason': entry.get('reason')}
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
    try:
        response = requests.get(CLOUDFLARE_VERIFY_URL, headers={'Authorization': f'Bearer {token}'},
                                timeout=TIMEOUT, allow_redirects=False)
    except requests.Timeout:
        return FAILED, f'api.cloudflare.com did not answer within {TIMEOUT[1]} seconds'
    except requests.ConnectionError as exc:
        return FAILED, f'Could not connect to api.cloudflare.com ({type(exc).__name__})'
    except (requests.RequestException, UnicodeError) as exc:
        # The class only: an InvalidHeader's text quotes the header, token and all.
        return FAILED, f'The request to Cloudflare was not sent ({type(exc).__name__})'
    try:
        body = response.json()
    except ValueError:
        body = {}
    result = body.get('result') if isinstance(body, dict) else None
    status = result.get('status') if isinstance(result, dict) else None
    if response.status_code == 200 and body.get('success') is True and status == 'active':
        return PASSED, 'Cloudflare says the token is active'
    if response.status_code == 200 and status:
        return FAILED, f'Cloudflare says the token is {status}'
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
    timeouts = Config(connect_timeout=TIMEOUT[0], read_timeout=TIMEOUT[1],
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
    return PASSED, 'Route53 listed the hosted zones'


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

def _fetch_directory(url, verify):
    host = urlparse(url).hostname or url
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=verify, allow_redirects=False)
    except requests.Timeout:
        return FAILED, f'{host} did not answer within {TIMEOUT[1]} seconds'
    except requests.exceptions.SSLError:
        return FAILED, f'The TLS certificate of {host} could not be verified (SSLError)'
    except requests.ConnectionError as exc:
        return FAILED, f'Could not connect to {host} ({type(exc).__name__})'
    except requests.RequestException as exc:
        return FAILED, f'The request to {host} was not sent ({type(exc).__name__})'
    if response.status_code != 200:
        return FAILED, f'{host} answered HTTP {response.status_code}'
    try:
        directory = response.json()
    except ValueError:
        directory = None
    if not isinstance(directory, dict) or 'newAccount' not in directory:
        return FAILED, f'{host} answered, but not with an ACME directory'
    return PASSED, f'The ACME directory at {host} answered'


def check_ca_account(ca_manager, provider, config) -> dict:
    """Check the CA account *config* of *provider*, saved or about to be."""
    if not str(config.get('email') or '').strip():
        return _result(FAILED, 'The account has no email address, which the CA needs to register it')
    valid, message = ca_manager.validate_ca_configuration(provider, config)
    if not valid:
        return _result(FAILED, message)
    try:
        eab = ca_manager.get_eab_credentials(provider, config)
        url = ca_manager.get_acme_server_url(provider, account_config=config)
    except ValueError as exc:
        return _result(FAILED, str(exc))
    secrets = [value for value in eab if value]
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
    if outcome == PASSED and secrets:
        reason += '. The CA checks the EAB key only when an account registers'
    return _result(outcome, reason, secrets)


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

_RUNS = {'dns': lambda managers, provider, config: check_dns_account(managers['dns'], provider, config),
         'ca': lambda managers, provider, config: check_ca_account(_ca_manager(managers), provider, config)}
_RESOURCE_TYPES = {'dns': 'dns_provider', 'ca': 'ca_provider'}


def _ca_manager(managers):
    from .ca_manager import CAManager
    return managers.get('ca') or CAManager(managers['settings'])


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
        status='success' if result['outcome'] == PASSED else 'failure',
        details={'outcome': result['outcome']}, user=user.get('username'),
        ip_address=request.remote_addr)


def run_and_keep(managers, kind, provider, account_id, config) -> dict:
    """Check the saved account *config*, keep the result, audit and log it."""
    result = _RUNS[kind](managers, provider, config)
    store_for(managers['settings']).record(kind, provider, account_id, config, result)
    _audit(managers, kind, provider, account_id, result)
    logger.info("Credential check of %s account %r of provider %r ended %s",
                kind, account_id, provider, result['outcome'])
    return result


def answer_with_last_checks(managers, accounts) -> list:
    """The DNS account list, each entry with its `last_check`."""
    store = store_for(managers['settings'])
    for account in accounts if isinstance(accounts, list) else []:
        if isinstance(account, dict) and account.get('provider') and account.get('account_id'):
            config = managers['dns'].stored_account(account['provider'], account['account_id']) or {}
            account['last_check'] = store.last('dns', account['provider'], account['account_id'], config)
    return accounts


def ca_last_checks(managers) -> list:
    """Every saved CA account with its `last_check`."""
    store = store_for(managers['settings'])
    listed = []
    for provider, accounts in sorted(_ca_accounts(managers['settings'].load_settings() or {}).items()):
        for account_id, config in accounts.items():
            listed.append({'provider': provider, 'account_id': account_id,
                           'last_check': store.last('ca', provider, account_id, config)})
    return listed


def checks_before_save(kind, managers_of, target_of):
    """Decorator: a save asked with `?check=1` runs the check first.

    A failed check answers 422 ACCOUNT_CHECK_FAILED, with the result in
    `last_check`, and saves nothing, unless `save_anyway=1` is asked too: then
    the account is saved and the failed result kept. A check that could not
    run (no answer, refused connection) is a failed check. A provider with no
    check saves without asking and keeps "not checkable". The kept result is
    the account as saved, read back after the save; the answer carries it.

    Without `check`, a save is what it was, and a stored result stays only
    while the account is unchanged (see `fingerprint`).

    *target_of(request, kwargs, managers)* gives `(provider, account_id,
    config)`, the account the view is about to save, or None to leave the
    request to the view (which answers its own 400). A decorator, like
    refuses_a_taken_account, so the budgeted route closures gain no branch.
    """
    def decorator(view):
        @wraps(view)
        def guarded(*args, **kwargs):
            from flask import jsonify, make_response, request
            if request.method not in ('POST', 'PUT') or not _wants('check'):
                return view(*args, **kwargs)
            managers = managers_of()
            target = target_of(request, kwargs, managers)
            if target is None:
                return view(*args, **kwargs)
            provider, account_id, config = target
            result = _RUNS[kind](managers, provider, config)
            if result['outcome'] == FAILED and not _wants('save_anyway'):
                return make_response(jsonify({
                    'error': f"The check failed: {result['reason']}",
                    'code': 'ACCOUNT_CHECK_FAILED', 'last_check': result}), 422)
            response = make_response(view(*args, **kwargs))
            saved = _stored(kind, managers, provider, account_id) if response.status_code < 300 else None
            body = response.get_json(silent=True) if saved is not None else None
            if saved is not None:
                store_for(managers['settings']).record(kind, provider, account_id, saved, result)
                _audit(managers, kind, provider, account_id, result)
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


def ca_save_target(request, kwargs, managers):
    from .settings import _strip_masked_values
    from .utils import validate_email
    raw = request.get_json(silent=True)
    provider, account_id = kwargs.get('provider'), kwargs.get('account_id')
    if not isinstance(raw, dict) or not provider or not account_id:
        return None
    ca_manager = _ca_manager(managers)
    existing = stored_ca_account(managers['settings'].load_settings() or {}, provider, account_id) or {}
    config = {**existing, **_strip_masked_values(raw)}
    # What the save route refuses with a 400 is left to it: a check would only
    # repeat the refusal as a failed check the operator could save anyway.
    if (provider not in ca_manager.ca_providers or not config.get('email')
            or not validate_email(config['email'])[0]
            or not ca_manager.validate_ca_configuration(provider, config)[0]):
        return None
    return provider, account_id, config
