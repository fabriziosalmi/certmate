#!/usr/bin/env python3
"""Certbot manual DNS hook for Azure DNS.

Azure DNS-01 used to go through ``certbot-dns-azure``. That plugin has no
release for certbot 4 or later (the latest requires ``certbot<4.0``), and it
calls the Azure SDK in a way the SDK has already outgrown once (#1072). Azure is
a provider, not a plugin: CertMate depends on ``azure-identity`` and
``azure-mgmt-dns`` directly, and certbot's ``--manual`` hooks are how acme-dns
and the Custom Script provider already answer a challenge without a plugin. So
the TXT record is written here, with the SDK, and the plugin is gone (#103).

Run by certbot as ``--manual-auth-hook`` / ``--manual-cleanup-hook``::

    azure_dns_hook.py --config <file> --action auth|cleanup

``<file>`` is the 0600 JSON CertMate writes for the operation and removes when it
ends: the service principal, the subscription and resource group, and the hosted
zones to choose from. certbot passes the challenge in the environment
(``CERTBOT_DOMAIN``, ``CERTBOT_VALIDATION``); how long to wait for the record to
be visible comes from ``CERTMATE_DNS_PROPAGATION_SECONDS``, the same variable the
Custom Script provider's hooks read.

What the plugin did, kept:

* the zone is the longest configured one the challenge name falls under, so a
  wildcard under a parent zone lands in the parent;
* one name can carry several values (a wildcard and its apex are validated on
  the same ``_acme-challenge`` name), so a value is added to the record, never
  written over it, and cleanup removes only its own value;
* writes carry the record's ETag, and a conflicting write (412) is retried;
* cleanup never fails the issuance: a record left behind is a warning.
"""

import argparse
import json
import os
import random
import sys
import time

CHALLENGE_LABEL = '_acme-challenge'
TXT_TTL_SECONDS = 60
MAX_CONFLICT_RETRIES = 10
MAX_WAIT_SECONDS = 3600


class AzureDNSHookError(RuntimeError):
    pass


def _require(config, *keys):
    missing = [key for key in keys if not str(config.get(key) or '').strip()]
    if missing:
        raise AzureDNSHookError(
            f"Missing Azure DNS credential fields: {', '.join(missing)}")


def _normalize(name):
    return (name or '').strip().lower().removeprefix('*.').rstrip('.')


def zone_for(domain, zones):
    """The longest configured zone that *domain* is, or sits under.

    Matched on label boundaries: ``notexample.org`` is not under ``example.org``.
    """
    name = _normalize(domain)
    candidates = sorted(
        (_normalize(zone) for zone in zones or [] if _normalize(zone)),
        key=len, reverse=True)
    for zone in candidates:
        if name == zone or name.endswith('.' + zone):
            return zone
    raise AzureDNSHookError(
        f"No Azure DNS zone is configured for {name or '(no domain)'}; "
        f"configured zones: {', '.join(candidates) or 'none'}")


def record_name(domain, zone):
    """``(zone-relative record name, zone)`` for the DNS-01 challenge of *domain*."""
    zone = _normalize(zone)
    fqdn = f'{CHALLENGE_LABEL}.{_normalize(domain)}'
    if fqdn == zone:
        return '@'
    return fqdn[:-(len(zone) + 1)]


def _client(config):
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.dns import DnsManagementClient
    except ImportError as exc:
        raise AzureDNSHookError(
            'Azure DNS needs azure-identity and azure-mgmt-dns '
            '(requirements-azure.txt); they are not installed here.') from exc
    credential = ClientSecretCredential(
        tenant_id=config['tenant_id'], client_id=config['client_id'],
        client_secret=config['client_secret'])
    return DnsManagementClient(credential, config['subscription_id'])


def _is_status(error, status):
    return getattr(error, 'status_code', None) == status


def _read_record(client, resource_group, zone, name):
    """``(values, etag)``: each TXT string as a list of chunks, and the record's ETag.

    A record that does not exist is ``([], None)``. The ``-`` placeholder the
    plugin used to keep a record that was named explicitly is not a value.
    """
    from azure.core.exceptions import HttpResponseError
    try:
        existing = client.record_sets.get(
            resource_group_name=resource_group, zone_name=zone,
            relative_record_set_name=name, record_type='TXT')
    except HttpResponseError as exc:
        if _is_status(exc, 404):
            return [], None
        raise
    values = [list(record.value or []) for record in (existing.txt_records or [])]
    return [chunks for chunks in values if ''.join(chunks) != '-'], existing.etag


def _write_record(client, resource_group, zone, name, values, etag):
    from azure.mgmt.dns.models import RecordSet, TxtRecord
    client.record_sets.create_or_update(
        resource_group_name=resource_group, zone_name=zone,
        relative_record_set_name=name, record_type='TXT',
        parameters=RecordSet(
            ttl=TXT_TTL_SECONDS, txt_records=[TxtRecord(value=chunks) for chunks in values]),
        # A new record must not overwrite one created a moment ago by another
        # challenge; an existing one must not overwrite a newer version.
        if_match=etag, if_none_match=None if etag else '*')


def _delete_record(client, resource_group, zone, name, etag):
    from azure.core.exceptions import HttpResponseError
    try:
        client.record_sets.delete(
            resource_group_name=resource_group, zone_name=zone,
            relative_record_set_name=name, record_type='TXT', if_match=etag)
    except HttpResponseError as exc:
        if not _is_status(exc, 404):
            raise


def _retry_on_conflict(operation):
    """Run *operation*, again when another writer got to the record first (412)."""
    from azure.core.exceptions import HttpResponseError
    for attempt in range(MAX_CONFLICT_RETRIES + 1):
        try:
            return operation()
        except HttpResponseError as exc:
            if not _is_status(exc, 412) or attempt == MAX_CONFLICT_RETRIES:
                raise
            # Jitter so two challenges racing for the same name do not collide
            # again in lockstep. Not a security use of `random`.
            time.sleep(random.uniform(0.2, 1.5))  # nosec B311


def add_txt(client, resource_group, zone, name, validation):
    def attempt():
        values, etag = _read_record(client, resource_group, zone, name)
        if any(''.join(chunks) == validation for chunks in values):
            return
        _write_record(client, resource_group, zone, name, values + [[validation]], etag)
    _retry_on_conflict(attempt)


def remove_txt(client, resource_group, zone, name, validation):
    def attempt():
        values, etag = _read_record(client, resource_group, zone, name)
        if etag is None:
            return
        remaining = [chunks for chunks in values if ''.join(chunks) != validation]
        if len(remaining) == len(values):
            return
        if remaining:
            _write_record(client, resource_group, zone, name, remaining, etag)
        else:
            _delete_record(client, resource_group, zone, name, etag)
    _retry_on_conflict(attempt)


def _wait_seconds():
    try:
        seconds = int(os.environ.get('CERTMATE_DNS_PROPAGATION_SECONDS') or 0)
    except ValueError:
        return 0
    return max(0, min(MAX_WAIT_SECONDS, seconds))


def run(config, action, environ=None):
    environ = os.environ if environ is None else environ
    domain = environ.get('CERTBOT_DOMAIN')
    validation = environ.get('CERTBOT_VALIDATION')
    if not domain or not validation:
        if action == 'cleanup':
            return
        raise AzureDNSHookError('CERTBOT_DOMAIN and CERTBOT_VALIDATION must be set')
    _require(config, 'tenant_id', 'client_id', 'client_secret',
             'subscription_id', 'resource_group')
    zone = zone_for(domain, config.get('zones'))
    name = record_name(domain, zone)
    client = _client(config)
    if action == 'auth':
        add_txt(client, config['resource_group'], zone, name, validation)
        time.sleep(_wait_seconds())
    else:
        remove_txt(client, config['resource_group'], zone, name, validation)


def _expected_errors():
    """What a challenge can fail with: ours, the config file, or the Azure SDK."""
    errors = [AzureDNSHookError, OSError, ValueError]
    try:
        from azure.core.exceptions import AzureError
        errors.append(AzureError)
    except ImportError:
        pass  # run() reports it, with the install hint
    return tuple(errors)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--action', choices=['auth', 'cleanup'], required=True)
    args = parser.parse_args(argv)

    try:
        with open(args.config, encoding='utf-8') as f:
            config = json.load(f)
        if not isinstance(config, dict):
            raise AzureDNSHookError('the hook config is not a JSON object')
        run(config, args.action)
    except _expected_errors() as exc:
        if args.action == 'cleanup':
            # Same rule as the alias hook: a failed cleanup must not fail the
            # issuance that already succeeded or failed on its own.
            print(f'Azure DNS cleanup failed: {exc}', file=sys.stderr)
            return 0
        print(f'Azure DNS challenge failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
