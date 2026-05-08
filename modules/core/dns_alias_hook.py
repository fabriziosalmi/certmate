#!/usr/bin/env python3
"""Certbot manual DNS hook for DNS alias validation.

The hook writes the DNS-01 TXT value to ``_acme-challenge.<domain_alias>``.
CertMate keeps using the requested certificate domain for the ACME order; the
user-owned CNAME from the real challenge name to this alias target is still
required.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class DNSAliasError(RuntimeError):
    pass


LEXICON_PROVIDER_MAP = {
    'cloudflare': 'cloudflare',
    'route53': 'route53',
    'azure': 'azure',
    'google': 'googleclouddns',
    'powerdns': 'powerdns',
    'digitalocean': 'digitalocean',
    'linode': 'linode',
    'gandi': 'gandi',
    'ovh': 'ovh',
    'namecheap': 'namecheap',
    'arvancloud': 'arvancloud',
    'infomaniak': 'infomaniak',
    'duckdns': 'duckdns',
}


def _provider_config(config):
    return config.get('config') or config


def _require(config, *keys):
    missing = [key for key in keys if not str(config.get(key) or '').strip()]
    if missing:
        raise DNSAliasError(f"Missing DNS alias credential fields: {', '.join(missing)}")


def _json_request(method, url, headers, data=None):
    body = None
    if data is not None:
        body = json.dumps(data).encode('utf-8')
        headers = {**headers, 'Content-Type': 'application/json'}

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode('utf-8')
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='replace')
        raise DNSAliasError(f'DNS provider API request failed: {exc.code} {detail}') from exc
    except urllib.error.URLError as exc:
        raise DNSAliasError(f'DNS provider API request failed: {exc.reason}') from exc


def _zone_guesses(domain):
    labels = domain.strip('.').split('.')
    for index in range(len(labels) - 1):
        yield '.'.join(labels[index:])


def _record_name(alias_domain):
    return f"_acme-challenge.{alias_domain.strip('.')}"


def _public_ip():
    try:
        with urllib.request.urlopen('https://api.ipify.org', timeout=10) as response:
            return response.read().decode('utf-8').strip()
    except Exception as exc:
        raise DNSAliasError(
            "Namecheap alias mode requires client_ip/auth_client_ip, and CertMate "
            "could not auto-detect the public IP for the API request."
        ) from exc


def _google_service_account_value(provider_config):
    service_account = provider_config.get('service_account_key')
    _require({'service_account_key': service_account}, 'service_account_key')
    encoded = base64.b64encode(service_account.encode('utf-8')).decode('ascii')
    return f'base64::{encoded}'


def _lexicon_config(provider, alias_domain, provider_config):
    base = {
        'provider_name': LEXICON_PROVIDER_MAP[provider],
        'domain': alias_domain,
    }

    if provider == 'cloudflare':
        token = provider_config.get('api_token') or provider_config.get('token')
        _require({'api_token': token}, 'api_token')
        base['auth_token'] = token
    elif provider == 'route53':
        _require(provider_config, 'access_key_id', 'secret_access_key')
        base['auth_access_key'] = provider_config['access_key_id']
        base['auth_access_secret'] = provider_config['secret_access_key']
    elif provider == 'azure':
        _require(provider_config, 'subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret')
        base.update({
            'auth_subscription_id': provider_config['subscription_id'],
            'resource_group': provider_config['resource_group'],
            'auth_tenant_id': provider_config['tenant_id'],
            'auth_client_id': provider_config['client_id'],
            'auth_client_secret': provider_config['client_secret'],
        })
    elif provider == 'google':
        _require(provider_config, 'project_id', 'service_account_key')
        base['project_id'] = provider_config['project_id']
        base['auth_service_account_info'] = _google_service_account_value(provider_config)
    elif provider == 'powerdns':
        _require(provider_config, 'api_url', 'api_key')
        base['pdns_server'] = provider_config['api_url']
        base['auth_token'] = provider_config['api_key']
        if provider_config.get('server_id'):
            base['pdns_server_id'] = provider_config['server_id']
    elif provider in {'digitalocean', 'arvancloud', 'infomaniak', 'duckdns'}:
        token = provider_config.get('api_token') or provider_config.get('api_key') or provider_config.get('token')
        _require({'api_token': token}, 'api_token')
        base['auth_token'] = token
    elif provider == 'linode':
        token = provider_config.get('api_key') or provider_config.get('api_token')
        _require({'api_key': token}, 'api_key')
        base['auth_token'] = token
    elif provider == 'gandi':
        _require(provider_config, 'api_token')
        base['auth_token'] = provider_config['api_token']
        base['api_protocol'] = 'rest'
    elif provider == 'ovh':
        _require(provider_config, 'endpoint', 'application_key', 'application_secret', 'consumer_key')
        base.update({
            'auth_entrypoint': provider_config['endpoint'],
            'auth_application_key': provider_config['application_key'],
            'auth_application_secret': provider_config['application_secret'],
            'auth_consumer_key': provider_config['consumer_key'],
        })
    elif provider == 'namecheap':
        _require(provider_config, 'username', 'api_key')
        base['auth_username'] = provider_config['username']
        base['auth_token'] = provider_config['api_key']
        base['auth_client_ip'] = (
            provider_config.get('client_ip')
            or provider_config.get('auth_client_ip')
            or _public_ip()
        )
        if provider_config.get('sandbox') is not None:
            base['auth_sandbox'] = bool(provider_config.get('sandbox'))
    else:
        raise DNSAliasError(f"Unsupported Lexicon alias provider: {provider}")

    return base


def _lexicon_change(config, validation, action):
    provider = config['provider']
    provider_config = _provider_config(config)
    alias_domain = config['domain_alias']
    record = _record_name(alias_domain)

    try:
        from lexicon.client import Client
    except Exception as exc:
        raise DNSAliasError("dns-lexicon is required for this DNS alias provider") from exc

    lexicon_config = _lexicon_config(provider, alias_domain, provider_config)
    with Client(lexicon_config) as operations:
        if action == 'create':
            operations.create_record('TXT', record, validation)
        else:
            operations.delete_record(rtype='TXT', name=record, content=validation)


def _edgegrid_auth(config):
    provider_config = _provider_config(config)
    _require(provider_config, 'client_token', 'client_secret', 'access_token', 'host')
    try:
        import requests
        from akamai.edgegrid import EdgeGridAuth
    except Exception as exc:
        raise DNSAliasError("edgegrid-python and requests are required for EdgeDNS alias mode") from exc

    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=provider_config['client_token'],
        client_secret=provider_config['client_secret'],
        access_token=provider_config['access_token'],
    )
    host = provider_config['host'].removeprefix('https://').rstrip('/')
    return session, f'https://{host}'


def _edgedns_zone(alias_domain, session, base_url):
    for zone_name in _zone_guesses(alias_domain):
        response = session.get(f'{base_url}/config-dns/v2/zones/{zone_name}')
        if response.status_code == 200:
            return zone_name
    guesses = list(_zone_guesses(alias_domain))
    raise DNSAliasError(f"Unable to determine EdgeDNS zone for alias '{alias_domain}' using zone names: {guesses}")


def _edgedns_change(config, validation, action):
    alias_domain = config['domain_alias']
    session, base_url = _edgegrid_auth(config)
    zone = _edgedns_zone(alias_domain, session, base_url)
    name = _record_name(alias_domain)
    recordsets_url = f'{base_url}/config-dns/v2/zones/{zone}/recordsets'

    if action == 'create':
        response = session.post(recordsets_url, json={
            'name': name,
            'type': 'TXT',
            'ttl': 60,
            'rdata': [validation],
        })
        if response.status_code == 409:
            response = session.put(f'{recordsets_url}/{name}/TXT', json={
                'name': name,
                'type': 'TXT',
                'ttl': 60,
                'rdata': [validation],
            })
    else:
        response = session.delete(f'{recordsets_url}/{name}/TXT')
        if response.status_code == 404:
            return

    if response.status_code >= 400:
        raise DNSAliasError(f'EdgeDNS API request failed: {response.status_code} {response.text}')


def _acme_dns_change(config, validation, action):
    if action == 'delete':
        return
    provider_config = _provider_config(config)
    _require(provider_config, 'api_url', 'username', 'password', 'subdomain')
    alias_domain = config['domain_alias'].rstrip('.')
    subdomain = provider_config['subdomain'].rstrip('.')
    if alias_domain != subdomain:
        raise DNSAliasError(
            f"ACME-DNS alias domain must match configured subdomain '{subdomain}'"
        )
    _json_request(
        'POST',
        f"{provider_config['api_url'].rstrip('/')}/update",
        {
            'X-Api-User': provider_config['username'],
            'X-Api-Key': provider_config['password'],
        },
        {
            'subdomain': subdomain,
            'txt': validation,
        },
    )


def _change_txt(config, action):
    validation = os.environ.get('CERTBOT_VALIDATION')
    if not validation:
        if action == 'delete':
            return
        raise DNSAliasError('CERTBOT_VALIDATION is not set')

    provider = config['provider']
    if provider in LEXICON_PROVIDER_MAP:
        _lexicon_change(config, validation, action)
    elif provider == 'edgedns':
        _edgedns_change(config, validation, action)
    elif provider == 'acme-dns':
        _acme_dns_change(config, validation, action)
    else:
        raise DNSAliasError(f"Unsupported DNS alias provider: {provider}")

    if action == 'create':
        propagation_seconds = int(config.get('propagation_seconds') or 0)
        if propagation_seconds > 0:
            time.sleep(propagation_seconds)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--action', choices=['auth', 'cleanup'], required=True)
    args = parser.parse_args()

    with open(args.config, encoding='utf-8') as f:
        config = json.load(f)

    try:
        if args.action == 'auth':
            _change_txt(config, 'create')
        else:
            try:
                _change_txt(config, 'delete')
            except Exception as exc:
                print(f'DNS alias cleanup failed: {exc}', file=sys.stderr)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
